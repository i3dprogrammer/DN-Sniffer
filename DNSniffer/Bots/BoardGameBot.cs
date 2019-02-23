using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using DNSecurityAPI;

namespace DNSniffer.Bots
{
    class BoardGameBot : IBot
    {
        private int _roulleteCount;
        private uint _spinCounter = 0;
        private uint _charHP = 0;
        private uint _monsterHP = 0;

        public void ProcessPacket(Packet packet, Context context, Context remote_context, Context local_context)
        {
            if (context == remote_context && packet.Opcode == 0x070A) //Inventory slot got updated.
            {
                packet.ReadUInt8Array(0x14);
                _roulleteCount = packet.ReadUInt16();
            }
            else if (context == remote_context && packet.Opcode == 0x2D00) //Roullete game opened.
            {
                packet.ReadUInt64();
                _charHP = packet.ReadUInt32();
                packet.ReadUInt64();
                _monsterHP = packet.ReadUInt32();
                Console.WriteLine($"Character HP: {_charHP} - Boss HP: {_monsterHP}");

                if (_charHP == 0)
                    context.Security.Send(new Packet(0x2B, 0x03, new byte[] { 0x00 }));
            }
            else if (context == remote_context && packet.Opcode == 0x2D01) //Roullete spinned.
            {
                packet.ReadUInt64();
                _charHP = packet.ReadUInt32();
                packet.ReadUInt64();
                _monsterHP = packet.ReadUInt32();
                packet.ReadUInt32();
                _spinCounter = packet.ReadUInt32();

                if (_spinCounter < 300 && _roulleteCount > 0 && _charHP > 0)
                    remote_context.Security.Send(new Packet(0x2B, 0x02, new byte[] { 0x00 })); //Spin the roullete!
                else if (_charHP == 0)
                    remote_context.Security.Send(new Packet(0x2B, 0x03, new byte[] { 0x00 })); //Revive.
                Console.WriteLine($"Spin Count {_spinCounter} / 300, Roulletes left {_roulleteCount}");
                Console.WriteLine($"Character HP: {_charHP} - Boss HP: {_monsterHP}");
                //Thread.Sleep(200); //Delay so we don't get caught.
            }
            else if (context == remote_context && packet.Opcode == 0x2D02) //We revived.
            {
                _charHP = packet.ReadUInt32();
                if (_spinCounter < 300 && _roulleteCount > 0) //If we still have tickets & we didnt cap the spins yet
                    remote_context.Security.Send(new Packet(0x2B, 0x02, new byte[] { 0x00 })); //roll boi!
            }
        }
    }
}
