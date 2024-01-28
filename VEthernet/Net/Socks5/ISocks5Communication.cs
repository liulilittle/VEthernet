namespace VEthernet.Net.Socks5
{
    using System;
    using System.Net;

    public interface ISocks5Communication : IDisposable
    {
        string UserName
        {
            get;
            set;
        }

        string Password
        {
            get;
            set;
        }

        IPEndPoint LocalEndPoint
        {
            get;
        }

        ISocks5NetworkTunnelFactory Factory
        {
            get;
        }

        void Listen(string address);
    }
}
