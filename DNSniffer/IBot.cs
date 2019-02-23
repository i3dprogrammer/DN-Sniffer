using DNSecurityAPI;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DNSniffer
{
    public interface IBot
    {
        /// <summary>
        /// Processes the passed packet to complete the bot's job.
        /// </summary>
        /// <param name="packet">The packet to process.</param>
        /// <param name="context">The context that received the packet.</param>
        /// <param name="remote_context">The remote context connected to the server.</param>
        /// <param name="local_context">The local context connected to the game client.</param>
        ///// <returns>Returns a bool indicating whether or not to relay the passed packet to the other context.</returns>
        void ProcessPacket(Packet packet, Context context, Context remote_context, Context local_context);
    }
}
