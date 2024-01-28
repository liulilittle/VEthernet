namespace VEthernet.Net.Socks5
{
    using System.Net.Sockets;

    public class Socks5NetworkTunnelFactory : ISocks5NetworkTunnelFactory
    {
        public virtual ISocks5NetworkTunnel CreateTunnel(ISocks5Communication communication, Socket session, Socket local, NetworkAddress remoteEP)
        {
            if (local == null)
            {
                return new Tcp.Socks5NetworkTunnel(session, remoteEP);
            }
            else
            {
                return new Udp.Socks5NetworkTunnel(local, session, null);
            }
        }
    }
}