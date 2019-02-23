using DNSecurityAPI;
using DNSecurityAPI.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace DNSniffer
{
    public class Context
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
}
