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
        public static ushort TCPPort = 50000;

        static Context RemoteTCPContext;
        static BotsManager botsManager = new BotsManager();

        static bool dumpTCP = false, dumpUDP = false, saveUDP = false;
        static Socket remote_sock;
        static EndPoint remote_endpoint;
        static Client.DNLoader loader;
        static bool init = false;
        static void Main(string[] args)
        {
            Console.WriteLine(string.Concat(Enumerable.Repeat("#", 20)));
            Bots.BoxOpenerBot boxOpener = new Bots.BoxOpenerBot(ref RemoteTCPContext);

            botsManager
                .RegisterBot(new Bots.BoardGameBot())
                .RegisterBot(new Bots.ClientSimulatorBot())
                .RegisterBot(new Bots.LadderBot())
                .RegisterBot(boxOpener);

            Console.WriteLine(string.Concat(Enumerable.Repeat("#", 20)));

            loader = new Client.DNLoader(DragonNestPath,
                $"/ip:127.0.0.1;127.0.0.1 /port:{TCPPort};{TCPPort} /Lver:2 /use_packing /language:ENG");

            loader.LaunchProcess();
            Console.WriteLine("Patch status: " + loader.PatchIPCheck());

            Console.WriteLine($"Should connect to 211.43.158.240:14300");
            new Thread(() => Proxy("211.43.158.240", 14300, TCPPort)).Start();

            while (true)
            {
                var command = Console.ReadLine();
                switch (command)
                {
                    case "l1":
                        dumpTCP = !dumpTCP;
                        Console.WriteLine("Dump TCP is set to: " + dumpTCP);
                        break;
                    case "l2":
                        dumpUDP = !dumpUDP;
                        Console.WriteLine("Dump UDP is set to: " + dumpUDP);
                        break;
                    case "l3":
                        saveUDP = !saveUDP;
                        Console.WriteLine("UdpPacket.txt logging is now set to: " + saveUDP);
                        break;
                    case "forcesell":
                        boxOpener.SellJades(RemoteTCPContext);
                        break;
                    case "open":
                        boxOpener.OpenJadeBox(RemoteTCPContext);
                        break;
                    case "invinfo":
                        boxOpener.ShowInfo();
                        break;
                    case "sell":
                        boxOpener.StartSellinJades(RemoteTCPContext);
                        break;
                }
            }
        }

        public static void Proxy(string remoteIP, int remotePort, int localPort)
        {
            List<Context> contexts = new List<Context>();
            Context local_context = new Context(new TCPSecurity());
            Context remote_context = new Context(new TCPSecurity());

            local_context.RelaySecurity = remote_context.Security;
            remote_context.RelaySecurity = local_context.Security;

            contexts.Add(local_context);
            contexts.Add(remote_context);
            RemoteTCPContext = remote_context;

            using (var listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
            {
                Console.WriteLine($"But waiting for connection on 127.0.0.1:{localPort}");
                listener.Bind(new IPEndPoint(IPAddress.Any, localPort));
                listener.Listen(1);
                local_context.Socket = listener.Accept();
                Console.WriteLine("Connection Accepted");
            }

            if(!init)
                InitializeKeys();

            using (local_context.Socket)
            {
                using (remote_context.Socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
                {
                    remote_context.Socket.Connect(remoteIP, remotePort);
                    Console.WriteLine($"Connected to {remoteIP}:{remotePort}.");
                    while (true)
                    {
                        #region TransferIncoming
                        //Receive packets from local and remote contexts.
                        if (!ProxyTransferIncoming(contexts))
                            break;

                        foreach (var context in contexts)
                        {
                            foreach (var packet in context.Security.TransferIncoming())
                            {
                                if (dumpTCP && context == remote_context)
                                    Utility.Hexdump(packet, context == remote_context);

                                botsManager.ProcessPacket(packet, context, remote_context, local_context);

                                if (context == remote_context && (packet.Opcode == 0x0201 || packet.Opcode == 0x0203))
                                    continue;

                                context.RelaySecurity.Send(packet);
                            }
                        }

                        #endregion

                        TCPTransferOutgoing(contexts);
                        Thread.Sleep(1);
                    }
                }
            }
        }

        public static void UDPProxy(string remoteIP, int remotePort, int localPort)
        {
            List<Context> contexts = new List<Context>();
            Context local_context = new Context(new TempUDPSecurity());
            Context remote_context = new Context(new TempUDPSecurity());

            local_context.RelaySecurity = remote_context.Security;
            remote_context.RelaySecurity = local_context.Security;

            EndPoint local_recv_endpoint = new IPEndPoint(IPAddress.Loopback, localPort);
            EndPoint remote_recv_endpoint = new IPEndPoint(IPAddress.Parse(remoteIP), remotePort);

            contexts.Add(local_context);
            contexts.Add(remote_context);

            Console.WriteLine("Initializing UDP Proxy.");

            using (local_context.Socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp))
            {
                local_context.Socket.Bind(local_recv_endpoint);
                using (remote_context.Socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp))
                {
                    remote_context.Socket.Connect(remote_recv_endpoint);
                    while (true)
                    {
                        #region TransferIncoming
                        //Receive packets from local and remote contexts.
                        ProxyTransferIncoming(contexts);

                        foreach (var context in contexts)
                        {
                            foreach (var packet in context.Security.TransferIncoming())
                            {
                                if (dumpUDP)
                                    Utility.Hexdump(packet, context == remote_context, true);

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

        public static void UltraFastUDPProxy(string remoteIP, int remotePort, int localPort)
        {
            byte[] buffer = new byte[0x2000];
            EndPoint local_recv_endpoint = new IPEndPoint(IPAddress.Loopback, localPort);
            EndPoint remote_recv_endpoint = new IPEndPoint(IPAddress.Parse(remoteIP), remotePort);
            var l_socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            var r_socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            var sec = new UDPSecurity();
            int[] l_crc = new int[8] { 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00 };
            int[] r_crc = new int[8] { 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00 };
            remote_sock = r_socket;
            remote_endpoint = remote_recv_endpoint;
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

                                if (bytes.Length >= 10)
                                {
                                    var checker = BitConverter.ToInt16(bytes, 0);
                                    if (checker == l_crc[checker & 7])
                                    {
                                        Console.WriteLine("[C -> S] GOOD.");
                                        l_crc[checker & 7] += 8;
                                    }
                                    else
                                    {
                                        Console.WriteLine("[C -> S] NOT GOOD!");
                                    }
                                }

                                if (saveUDP)
                                {
                                    Log("[C -> S] [{0} bytes]", bytes.Length);
                                    Log(Utility.HexdumpBytes(bytes));
                                    Log("\n");
                                }
                            }

                            if (r_socket.Poll(0, SelectMode.SelectRead))
                            {
                                int count = r_socket.Receive(buffer);
                                var bytes = buffer.Take(count).ToArray();
                                l_socket.SendTo(bytes, 0, count, SocketFlags.None, local_recv_endpoint);

                                if (bytes.Length >= 10)
                                {
                                    var checker = BitConverter.ToInt16(bytes, 0);
                                    if (checker == r_crc[checker & 7])
                                    {
                                        Console.WriteLine("[S -> C] GOOD.");
                                        r_crc[checker & 7] += 8;
                                    }
                                    else
                                    {
                                        Console.WriteLine("[S -> C] NOT GOOD!");
                                    }
                                }

                                if (saveUDP)
                                {
                                    Log("[S -> C] [{0} bytes]", bytes.Length);
                                    Log(Utility.HexdumpBytes(bytes));
                                    Log("\n");
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            r_socket.Dispose();
                            l_socket.Dispose();
                            Console.WriteLine(ex.Message + "\n" + ex.StackTrace);
                            return;
                        }
                        Thread.Sleep(1);
                    }
                }
            }
        }

        private static void Log(string text, params object[] format)
        {
            var bytes = Encoding.ASCII.GetBytes("\n\n" + string.Format(text, format) + "\n");
            Log(bytes);
        }

        private static void Log(byte[] bytes)
        {
            using (var writer = File.Open("UdpPackets.txt", FileMode.OpenOrCreate, FileAccess.Write))
            {
                writer.Seek(0x00, SeekOrigin.End);
                writer.Write(bytes, 0, bytes.Length);
            }
        }
        private static bool ProxyTransferIncoming(List<Context> contexts)
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
                        if (dumpTCP && context == contexts[1])
                            Utility.Hexdump(kvp.Value, context != contexts[1]);

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

        static void SendTCPPacket(Packet p)
        {
            RemoteTCPContext.Security.Send(p);
        }

        private static void InitializeKeys()
        {
            LocalKeys.XTEAKey = loader.GetXTEAKey();
            LocalKeys.UDPCryptoKey = loader.GetUDPKey();
            DNSecurityAPI.Keys.Initialize(LocalKeys.XTEAKey, LocalKeys.UDPCryptoKey, LocalKeys.UDPDecryptKey, LocalKeys.UDPEncryptKey, LocalKeys.CustomeBase64Table);
            init = true;
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