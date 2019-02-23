using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using DNSecurityAPI;

namespace DNSniffer.Bots
{
    class LadderBot : IBot
    {
        private bool _enterLadder = true;
        private int _counter = 0;

        public void ProcessPacket(Packet packet, Context context, Context remote_context, Context local_context)
        {
            if (context == remote_context && packet.Opcode1 == 0x13 && packet.Opcode2 == 0x23 && _enterLadder) //If the game requested the ladder participants list.
            {
                Console.WriteLine($"Bot went to ladder {_counter++} times, requesting match!");
                _enterLadder = false;
                Packet p = new Packet(0x13, 0x0E);
                p.WriteUInt8(0x00);
                remote_context.Security.Send(p);
            }
            else if (context == remote_context && packet.Opcode1 == 0x02 && packet.Opcode2 == 0x03) //If we got teleported out of city!
            {
                _enterLadder = true;
            }
        }
    }
}
