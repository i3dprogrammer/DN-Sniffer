using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using DNSecurityAPI;
using DNSecurityAPI.Interfaces;

namespace DNSniffer
{
    class Program
    { //F:\Dragon Nest MuSh0 Version\Dragon Nest\
        const string DragonNestPath = @"DragonNest.exe";
        static ushort TCPPort = 50000;

        class Context
        {
            public ISecurity Security;
            public Socket Socket;
            public ISecurity RelaySecurity;
            public TransferBuffer Buffer;

            public Context(ISecurity security)
            {
                Security = security;
                Socket = null;
                RelaySecurity = null;
                Buffer = new TransferBuffer(0x40000);
            }
        }

        static byte[] test = new byte[] { 0xaa, 0x00, 0x77, 0x86, 0x00, 0x2a, 0x6b, 0x8d, 0x00, 0xd8, 0x32, 0xc3, 0x13, 0x1c, 0x91, 0x2d, 0x9d, 0x33, 0xf9, 0xcc, 0x23, 0x70, 0xe1, 0x33, 0x8c, 0x13, 0x72, 0x91, 0x41, 0x9d, 0x4a, 0xf9, 0xec, 0x23, 0x03, 0xdd, 0x50, 0xc3, 0x72, 0x1c, 0xfc, 0x2d, 0xf0, 0x33, 0x9c, 0xcc, 0x51, 0x70, 0xae, 0x33, 0xe3, 0x13, 0x75, 0x91, 0x43, 0x9d, 0x13, 0xf9, 0xab, 0x23, 0x11, 0xdd, 0x5e, 0xc3, 0x76, 0x1c, 0xb1, 0x2d, 0xfc, 0x33, 0x95, 0xcc, 0x4f, 0x70, 0xf1, 0x33, 0xe3, 0x13, 0x7b, 0x91, 0x42, 0x9d, 0x13, 0xf9, 0xa8, 0x23, 0x19, 0xdd, 0x40, 0xc3, 0x70, 0x1c, 0xfe, 0x2d, 0xef, 0x33, 0x9d, 0xcc, 0x03, 0x70, 0xb8, 0x33, 0xb6, 0x13, 0x3c, 0x91, 0x4c, 0x9d, 0x5d, 0xf9, 0xa8, 0x23, 0x50, 0xdd, 0x51, 0xc3, 0x66, 0x1c, 0xe8, 0x2d, 0xbd, 0x33, 0x9f, 0xcc, 0x51, 0x70, 0xb2, 0x33, 0xae, 0x13, 0x3c, 0x91, 0x5d, 0x9d, 0x56, 0xf9, 0xa3, 0x23, 0x00, 0xdd, 0x5f, 0xc3, 0x76, 0x1c };
        static byte[] base64 = new byte[] { 0x2F, 0x53, 0x2B, 0x5A, 0x5A, 0x50, 0x54, 0x54, 0x44, 0x53, 0x35, 0x4C, 0x45, 0x72, 0x4D, 0x56, 0x50, 0x38, 0x33, 0x41, 0x32, 0x36, 0x67, 0x79, 0x68, 0x53, 0x58, 0x63, 0x76, 0x34, 0x66, 0x71, 0x44, 0x74, 0x2F, 0x70, 0x6B, 0x54, 0x72, 0x6C, 0x79, 0x63, 0x42, 0x58, 0x76, 0x34, 0x66, 0x71, 0x44, 0x74, 0x2F, 0x70, 0x6B, 0x54, 0x72, 0x6C, 0x79, 0x63, 0x42, 0x58, 0x76, 0x34, 0x66, 0x71, 0x44, 0x74, 0x2F, 0x70, 0x6B, 0x54, 0x72, 0x6C, 0x79, 0x63, 0x42, 0x58, 0x76, 0x34, 0x66, 0x71 };

        static bool enter;
        static int counter = 0;
        static uint roulleteCount = 0;
        static uint spinCounter = 0;
        static uint charHP = 0;
        static uint monsterHP = 0;
        static bool playBoardGame = true;
        public static Packet FormLoginPacket(string username, string password, string ip, string mac)
        {
            if (username.Length >= 32)
                throw new Exception("Username too large.");
            if (password.Length > 20)
                throw new Exception("Password too large.");

            Packet p = new Packet(0x01, 0x28);
            p.WriteFixedAscii(username, 32);
            p.WriteFixedAscii(password, 21);
            p.WriteUInt8(0x00);
            p.WriteUInt16(0x19);
            p.WriteUInt8Array(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x01, 0x7C, 0x00 });
            p.WriteFixedAscii(ip, 22);
            p.WriteUInt16(0x19);
            p.WriteUInt32(0x00);
            p.WriteUInt8Array(new byte[] { 0x8B, 0x7C, 0x49, 0x00, 0x00 });
            p.WriteFixedAscii(mac, 20);
            return p;
        }

        static Context RemoteTCPContext;
        static void Main(string[] args)
        {
            DNSecurityAPI.Keys.Initialize(LocalKeys.XTEAKey, LocalKeys.UDPCryptoKey, LocalKeys.UDPDecryptKey, LocalKeys.UDPEncryptKey, LocalKeys.CustomeBase64Table);
            DNLoader manager = new DNLoader(DragonNestPath,
                $"/ip:127.0.0.1;127.0.0.1 /port:{TCPPort};{TCPPort} /Lver:2 /use_packing /language:ENG");

            manager.LaunchProcess();
            Console.WriteLine(manager.PatchIPCheck());
            //Thread.Sleep(1000);
            //manager.GetXTEAKey();
            //manager.GetUDPKey();

            new Thread(() => Proxy("211.43.158.240", 14300, TCPPort)).Start();

            while (true)
            {
                var command = Console.ReadLine();
                switch(command)
                {
                    case "play":
                        playBoardGame = !playBoardGame;
                        Console.WriteLine("Play board game is now set to: " + playBoardGame);
                        break;
                }
                Thread.Sleep(1);
            }
        }

        private static void Proxy(string remoteIP, int remotePort, int localPort)
        {
            List<Context> contexts = new List<Context>();
            Context local_context = new Context(new TCPSecurity());
            Context remote_context = new Context(new TCPSecurity());

            local_context.RelaySecurity = remote_context.Security;
            remote_context.RelaySecurity = local_context.Security;

            contexts.Add(local_context);
            contexts.Add(remote_context);
            enter = true;
            Console.WriteLine($"Bot went to ladder {counter}");

            RemoteTCPContext = remote_context;

            using (var listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
            {
                Console.WriteLine($"Waiting for connection on 127.0.0.1:{localPort}");
                listener.Bind(new IPEndPoint(IPAddress.Any, localPort));
                listener.Listen(1);
                local_context.Socket = listener.Accept();
                Console.WriteLine("Connection Accepted");
            }
            var charScreen = false;
            using (local_context.Socket)
            {
                using (remote_context.Socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
                {
                    remote_context.Socket.Connect(remoteIP, remotePort);

                    while (true)
                    {
                        #region TransferIncoming
                        //Receive packets from local and remote contexts.
                        if (!TCPTransferIngoing(contexts))
                            break;

                        foreach (var context in contexts)
                        {
                            foreach (var packet in context.Security.TransferIncoming())
                            {
                                //Utility.Hexdump(packet, context == remote_context);
                                if (context == remote_context && packet.Opcode1 == 0x02 && packet.Opcode2 == 0x01)
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
                                    new Thread(() => Proxy(remIP, remPort, _localPort)).Start();
                                    Thread.Sleep(1000);
                                    context.RelaySecurity.Send(fakePacket);
                                }
                                else if (context == remote_context && packet.Opcode1 == 0x02 && packet.Opcode2 == 0x03)
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
                                    Console.WriteLine($"Should connect to {remoteIP}:{remTCPPort}");
                                    new Thread(() => Proxy(remIP, remTCPPort, _localPort)).Start();
                                    new Thread(() => UltraFastUDPProxy(remIP, remUDPPort, _localPort + 1)).Start();
                                    Thread.Sleep(1000);
                                    context.RelaySecurity.Send(fakePacket);
                                } else if(context == remote_context && packet.Opcode1 == 0x02 && packet.Opcode2 == 0x08)
                                {
                                    if (packet.ReadUInt32() == 0 && charScreen)
                                    {
                                        new Thread(() => Proxy("211.43.158.245", 14300, TCPPort)).Start();
                                        Thread.Sleep(1000);
                                    }
                                    context.RelaySecurity.Send(packet);
                                } else if(context == local_context && packet.Opcode1 == 0x02 && packet.Opcode2 == 0x08)
                                {
                                    if (packet.GetBytes().Length == 0)
                                        charScreen = true;
                                    context.RelaySecurity.Send(packet);
                                }
                                else if (context == remote_context && packet.Opcode == 0x070A)
                                {
                                    packet.ReadUInt8Array(0x14);
                                    roulleteCount = packet.ReadUInt16();
                                    context.RelaySecurity.Send(packet);
                                }
                                else if (context == remote_context && packet.Opcode == 0x2D00)
                                {
                                    packet.ReadUInt64();
                                    charHP = packet.ReadUInt32();
                                    packet.ReadUInt64();
                                    monsterHP = packet.ReadUInt32();
                                    Console.WriteLine($"Character HP: {charHP} - Boss HP: {monsterHP}");
                                    context.RelaySecurity.Send(packet);

                                    if (charHP == 0)
                                        context.Security.Send(new Packet(0x2B, 0x03, new byte[] { 0x00 }));
                                }
                                else if (context == remote_context && packet.Opcode == 0x2D01 && playBoardGame)
                                {
                                    packet.ReadUInt64();
                                    charHP = packet.ReadUInt32();
                                    packet.ReadUInt64();
                                    monsterHP = packet.ReadUInt32();
                                    packet.ReadUInt32();
                                    spinCounter = packet.ReadUInt32();
                                    if (spinCounter < 300 && roulleteCount > 0 && charHP > 0)
                                        remote_context.Security.Send(new Packet(0x2B, 0x02, new byte[] { 0x00 }));
                                    else if(charHP == 0)
                                        context.Security.Send(new Packet(0x2B, 0x03, new byte[] { 0x00 }));

                                    context.RelaySecurity.Send(packet);
                                    Console.WriteLine($"Spin Count {spinCounter} / 300, Roulletes left {roulleteCount}");
                                    Console.WriteLine($"Character HP: {charHP} - Boss HP: {monsterHP}");
                                    Thread.Sleep(200);
                                }
                                else if(context == remote_context && packet.Opcode == 0x2D02 && playBoardGame)
                                {
                                    charHP = packet.ReadUInt32();
                                    if (spinCounter < 300 && roulleteCount > 0)
                                        remote_context.Security.Send(new Packet(0x2B, 0x02, new byte[] { 0x00 }));
                                    context.RelaySecurity.Send(packet);
                                }
                                else
                                {
                                    context.RelaySecurity.Send(packet);
                                }

                                //if(context == local_context && (packet.Opcode == 0x0401 || packet.Opcode == 0x0402 || packet.Opcode == 0x0403))
                                //{
                                //    Utility.Hexdump(packet, false);
                                //}

                                if (packet.Opcode1 == 0x13 && packet.Opcode2 == 0x23 && enter)
                                {
                                    enter = false;
                                    Console.WriteLine("GO LADDER GO!");
                                    Packet p = new Packet(0x13, 0x0E);
                                    p.WriteUInt8(0x00);
                                    remote_context.Security.Send(p);
                                }
                            }
                        }

                        #endregion

                        TCPTransferOutgoing(contexts);
                        Thread.Sleep(1);
                    }
                }
            }
        }

        private static void UDPProxy(string remoteIP, int remotePort, int localPort)
        {
            List<Context> contexts = new List<Context>();
            Context local_context = new Context(new UDPSecurity());
            Context remote_context = new Context(new UDPSecurity());

            local_context.RelaySecurity = remote_context.Security;
            remote_context.RelaySecurity = local_context.Security;

            EndPoint local_recv_endpoint = new IPEndPoint(IPAddress.Any, localPort);
            EndPoint remote_recv_endpoint = new IPEndPoint(IPAddress.Parse(remoteIP), remotePort);

            contexts.Add(local_context);
            contexts.Add(remote_context);
            using (local_context.Socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp))
            {
                local_context.Socket.Bind(local_recv_endpoint);
                using (remote_context.Socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp))
                {
                    while (true)
                    {
                        #region TransferIncoming
                        //Receive packets from local and remote contexts.
                        foreach (var context in contexts)
                        {
                            if (context.Socket.Poll(0, SelectMode.SelectRead))
                            {
                                try
                                {
                                    int count = 0;
                                    if (context == remote_context)
                                        count = context.Socket.Receive(context.Buffer.Buffer);
                                    else
                                        count = context.Socket.ReceiveFrom(context.Buffer.Buffer, ref local_recv_endpoint);
                                    if (count == 0)
                                    {
                                        local_context.Socket.Dispose();
                                        remote_context.Socket.Dispose();
                                        Console.WriteLine("UDP connection SUCKS ass.");
                                        return;
                                    }

                                    context.Security.Recv(context.Buffer.Buffer, 0, count);
                                }
                                catch (Exception)
                                {
                                    Console.WriteLine("UDP SUCKS");
                                    local_context.Socket.Dispose();
                                    remote_context.Socket.Dispose();
                                    return;
                                }
                            }
                        }

                        foreach (var context in contexts)
                        {
                            foreach (var packet in context.Security.TransferIncoming())
                            {
                                Console.WriteLine("[UDP]");
                                Utility.Hexdump(packet, context == remote_context);
                                context.RelaySecurity.Send(packet);
                            }
                        }
                        #endregion

                        #region TransferOutgoing
                        foreach (var context in contexts)
                        {
                            if (context.Socket.Poll(0, SelectMode.SelectWrite))
                            {
                                foreach (var kvp in context.Security.TransferOutgoing())
                                {
                                    TransferBuffer buffer = kvp.Key;
                                    int count = 0;
                                    if (context == remote_context)
                                        count = context.Socket.SendTo(buffer.Buffer, buffer.Offset, buffer.Size, SocketFlags.None, remote_recv_endpoint);
                                    else
                                        count = context.Socket.SendTo(buffer.Buffer, buffer.Offset, buffer.Size, SocketFlags.None, local_recv_endpoint);

                                    Thread.Sleep(1);
                                }
                            }
                        }
                        #endregion
                        Thread.Sleep(1);
                    }
                }
            }
        }

        private static void UltraFastUDPProxy(string remoteIP, int remotePort, int localPort)
        {
            counter++;
            byte[] buffer = new byte[0x2000];
            EndPoint local_recv_endpoint = new IPEndPoint(IPAddress.Any, localPort);
            EndPoint remote_recv_endpoint = new IPEndPoint(IPAddress.Parse(remoteIP), remotePort);
            var l_socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            var r_socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            var sec = new UDPSecurity();

            using (l_socket)
            {
                l_socket.Bind(local_recv_endpoint);
                using (r_socket)
                {
                    while (true)
                    {
                        try
                        {
                            if (l_socket.Poll(0, SelectMode.SelectRead))
                            {
                                int count = l_socket.ReceiveFrom(buffer, ref local_recv_endpoint);
                                var bytes = buffer.Take(count).ToArray();
                                r_socket.SendTo(bytes, 0, count, SocketFlags.None, remote_recv_endpoint);
                            }

                            if (r_socket.Poll(0, SelectMode.SelectRead))
                            {
                                int count = r_socket.Receive(buffer);
                                var bytes = buffer.Take(count).ToArray();
                                l_socket.SendTo(bytes, 0, count, SocketFlags.None, local_recv_endpoint);
                            }
                        }
                        catch (Exception)
                        {
                            r_socket.Dispose();
                            l_socket.Dispose();
                            return;
                        }
                        Thread.Sleep(1);
                    }
                }
            }
        }

        private static bool TCPTransferIngoing(List<Context> contexts)
        {
            foreach (var context in contexts)
            {
                if (context.Socket.Poll(0, SelectMode.SelectRead))
                {
                    try
                    {
                        int count = context.Socket.Receive(context.Buffer.Buffer);
                        if (count == 0)
                        {
                            contexts[0].Socket.Dispose();
                            contexts[1].Socket.Dispose();
                            return false;
                        }
                        context.Security.Recv(context.Buffer.Buffer, 0, count);
                    }
                    catch (Exception)
                    {
                        contexts[0].Socket.Dispose();
                        contexts[1].Socket.Dispose();
                        return false;
                    }
                }
            }

            return true;
        }
        private static void TCPTransferOutgoing(List<Context> contexts)
        {
            foreach (var context in contexts)
            {
                if (context.Socket.Poll(0, SelectMode.SelectWrite))
                {
                    foreach (var kvp in context.Security.TransferOutgoing())
                    {
                        TransferBuffer buffer = kvp.Key;
                        do
                        {
                            int count = context.Socket.Send(buffer.Buffer, buffer.Offset, buffer.Size, SocketFlags.None);
                            buffer.Offset += count;
                            Thread.Sleep(1);
                        } while (buffer.Offset != buffer.Size);
                    }
                }
            }
        }
        static int FreeTcpPort()
        {
            TcpListener l = new TcpListener(IPAddress.Loopback, 0);
            l.Start();
            int port = ((IPEndPoint)l.LocalEndpoint).Port;
            l.Stop();
            return port;
        }
        static void SendTCPPacket(Packet p)
        {
            RemoteTCPContext.Security.Send(p);
        }

        /* 
         
[C -> S] [2B-02] [1 bytes]
000000: 00                                                  .

[S -> C] [07-0A] [51 bytes]
000000: 00 08 C9 12 00 30 B8 60 37 5C 02 79 37 00 9B B4     ..É..0,`7\.y7..'
000010: 47 16 00 00 64 01 00 00 00 00 00 00 01 00 00 01     G...d...........
000020: 00 00 00 00 00 00 00 00 00 00 00 00 A0 19 28 00     ............ .(.
000030: 00 00 00                                            ...

[S -> C] [2D-01] [36 bytes]
000000: 0C 00 00 00 14 00 00 00 5B 03 00 00 03 00 00 00     ........[.......
000010: 09 00 00 00 EA 01 00 00 02 00 00 00 02 00 00 00     ....ê...........
000020: 00 00 00 00                                         ....

[S -> C] [02-16] [4 bytes]
000000: B8 B3 2B 80                                         ,3+.

[C -> S] [02-11] [4 bytes]
000000: B8 B3 2B 80                                         ,3+.

[C -> S] [2B-02] [1 bytes]
000000: 00                                                  .

[S -> C] [07-0A] [51 bytes]
000000: 00 08 C9 12 00 30 B8 60 37 5C 02 79 37 00 9B B4     ..É..0,`7\.y7..'
000010: 47 16 00 00 62 01 00 00 00 00 00 00 01 00 00 01     G...b...........
000020: 00 00 00 00 00 00 00 00 00 00 00 00 A0 19 28 00     ............ .(.
000030: 00 00 00                                            ...

[S -> C] [2D-01] [36 bytes]
000000: 02 00 00 00 02 00 00 00 02 02 00 00 0C 00 00 00     ................
000010: 01 00 00 00 C2 01 00 00 02 00 00 00 03 00 00 00     ....A...........
000020: 00 00 00 00                                         ....


[S -> C] [2D-00] [32 bytes]
000000: 1B 00 00 00 00 00 00 00 00 00 00 00 09 00 00 00     ................
000010: 02 00 00 00 0E 01 00 00 01 00 00 00 06 00 00 00     ................

[C -> S] [20-02] [2 bytes]
000000: 10 00                                               ..

[C -> S] [2B-03] [1 bytes]
000000: 00                                                  .

[S -> C] [2D-02] [4 bytes]
000000: E8 03 00 00                                         è...
        
[S -> C] [2D-00] [32 bytes]
000000: 36 00 00 00 00 00 00 00 00 00 00 00 0D 00 00 00     6...............
000010: 03 00 00 00 18 01 00 00 0E 00 00 00 0A 00 00 00     ................

[S -> C] [2D-00] [32 bytes]
000000: 36 00 00 00 00 00 00 00 E8 03 00 00 0D 00 00 00     6.......è.......
000010: 03 00 00 00 18 01 00 00 0E 00 00 00 0A 00 00 00     ................


         */
    }
}