using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using DNSecurityAPI;

namespace DNSniffer.Bots
{
    /// <summary>
    /// Simulates the neccessary actions to make the game run smoothly with the proxy.
    /// </summary>
    class ClientSimulatorBot : IBot
    {
        bool charScreen = false;
        bool WeCool = false;
        public void ProcessPacket(Packet packet, Context context, Context remote_context, Context local_context)
        {
            if (context == remote_context && packet.Opcode1 == 0x02 && packet.Opcode2 == 0x01)
                SimulateTownTeleports(packet, context, remote_context, local_context);
            else if (context == remote_context && packet.Opcode1 == 0x02 && packet.Opcode2 == 0x03)
                SimulateOutOfTownTeleports(packet, context, remote_context, local_context);
            else if (packet.Opcode1 == 0x02 && packet.Opcode2 == 0x08)
                SimulateCharScreen(packet, context, remote_context, local_context);
            else if (packet.Opcode == 0x0217 && !WeCool) //Check if the encryption/decryption is OKAY.
            {
                if(packet.ReadUInt8() != 0xE8)
                    Console.WriteLine("It's advised to close and contact the developer or you're going to get B A N N E D.");
                WeCool = true;
            }
        }

        private void SimulateTownTeleports(Packet packet, Context context, Context remote_context, Context local_context)
        {
            DNSecurityAPI.Packet fakePacket = new DNSecurityAPI.Packet(0x02, 0x01);
            fakePacket.WriteUInt8Array(packet.ReadUInt8Array(0x04)); //World server ID probably?
            fakePacket.WriteUInt8Array(Encoding.ASCII.GetBytes("127.0.0.1")); //remote IP to connect to
            string remIP = Encoding.ASCII.GetString(packet.ReadUInt8Array(14));
            fakePacket.WriteUInt8Array(new byte[23]); //IP padding
            packet.ReadUInt8Array(18);
            ushort remPort = packet.ReadUInt16();
            int _localPort = FreeTcpPort();
            fakePacket.WriteUInt16(_localPort); //remote port
            fakePacket.WriteUInt8Array(packet.ReadUInt8Array(14)); //Rest of the packet.
            Utility.Hexdump(fakePacket, true);
            Console.WriteLine($"Should connect to {remIP}:{remPort}");
            new Thread(() => Program.Proxy(remIP, remPort, _localPort)).Start();
            Thread.Sleep(1000);
            context.RelaySecurity.Send(fakePacket);
        }

        private void SimulateOutOfTownTeleports(Packet packet, Context context, Context remote_context, Context local_context)
        {
            Packet fakePacket = new Packet(0x02, 0x03);
            fakePacket.WriteUInt8Array(packet.ReadUInt8Array(5)); //Empty bytes
            fakePacket.WriteUInt8Array(new byte[4] { 127, 0, 0, 1 }); //IP to connect to
            var ipbytes = packet.ReadUInt8Array(4);
            string remIP = ipbytes[0] + "." + ipbytes[1] + "." + ipbytes[2] + "." + ipbytes[3];
            ushort remUDPPort = packet.ReadUInt16();
            ushort remTCPPort = packet.ReadUInt16();
            int _localPort = FreeTcpPort();
            fakePacket.WriteUInt16(_localPort + 1); //UDP Port
            fakePacket.WriteUInt16(_localPort);  //TCP Port
            fakePacket.WriteUInt8Array(packet.ReadUInt8Array(16)); //Rest of bytes
            Utility.Hexdump(fakePacket, true);
            Console.WriteLine($"Should connect to {remIP}:{remTCPPort}");
            new Thread(() => Program.Proxy(remIP, remTCPPort, _localPort)).Start();
            new Thread(() => Program.UltraFastUDPProxy(remIP, remUDPPort, _localPort + 1)).Start();
            Thread.Sleep(2000);
            context.RelaySecurity.Send(fakePacket);
        }

        private void SimulateCharScreen(Packet packet, Context context, Context remote_context, Context local_context)
        {
            if (context == remote_context && packet.Opcode1 == 0x02 && packet.Opcode2 == 0x08)
            {
                if (packet.ReadUInt32() == 0 && charScreen)
                {
                    charScreen = false;
                    new Thread(() => Program.Proxy("211.43.158.245", 14300, Program.TCPPort)).Start();
                    Thread.Sleep(1000);
                }
            }
            else if (context == local_context && packet.Opcode1 == 0x02 && packet.Opcode2 == 0x08)
            {
                if (packet.GetBytes().Length == 0)
                    charScreen = true;
            }
        }

        private int FreeTcpPort()
        {
            TcpListener l = new TcpListener(IPAddress.Loopback, 0);
            l.Start();
            int port = ((IPEndPoint)l.LocalEndpoint).Port;
            l.Stop();
            return port;
        }
    }
}
