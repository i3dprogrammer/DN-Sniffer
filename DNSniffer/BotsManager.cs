using DNSecurityAPI;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DNSniffer
{
    class BotsManager
    {
        List<IBot> Bots = new List<IBot>();

        public BotsManager RegisterBot(IBot bot)
        {
            Console.WriteLine(bot.GetType().Name + " is initialized.");
            Bots.Add(bot);
            return this;
        }

        public void ProcessPacket(Packet packet, Context context, Context remote_context, Context local_context)
        {
            Bots.ForEach(x =>
            {
                packet.SeekRead(0x00, System.IO.SeekOrigin.Begin);
                x.ProcessPacket(packet, context, remote_context, local_context);
            });
        }
    }
}
