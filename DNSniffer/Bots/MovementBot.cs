using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using DNSecurityAPI;

namespace DNSniffer.Bots
{
    class MovementBot : IBot
    {
        //TODO try to follow X, Y script.

        public void ProcessPacket(Packet packet, Context context, Context remote_context, Context local_context)
        {
            if (context == local_context && packet.Opcode == 0x0401)
            {
                packet.ReadUInt32(); // Char ID
                packet.ReadUInt32(); // CPU Tick Count
                var dir = packet.ReadUInt16(); // Direction

                if (dir != 0x4E)
                {

                    byte x1 = packet.ReadUInt8();
                    byte x2 = packet.ReadUInt8();
                    byte x3 = packet.ReadUInt8();

                    byte y1 = packet.ReadUInt8();
                    byte y2 = packet.ReadUInt8();
                    byte y3 = packet.ReadUInt8();

                    byte z1 = packet.ReadUInt8();
                    byte z2 = packet.ReadUInt8();
                    byte z3 = packet.ReadUInt8();

                    Console.WriteLine($"Moving to X: {CalculatePosition(x1, x2, x3)}, Y: {CalculatePosition(y1, y2, y3)}, Z: {CalculatePosition(z1, z2, z3)}");
                }
            }
        }

        private static float CalculatePosition(byte f2, byte f3, byte f1)
        {
            return BitConverter.ToSingle(BitConverter.GetBytes((f3 << 5) + (f1 << 13) + ((((f2 & 0xC0) << 3) + (f2 & 0x3F)) << 21)), 0);
        }
    }
}
