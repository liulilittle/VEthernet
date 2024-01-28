namespace VEthernet.Net.Socks5
{
    using System.Net.Sockets;

    public interface ISocks5NetworkTunnelFactory
    {
        ISocks5NetworkTunnel CreateTunnel(ISocks5Communication communication, Socket session, Socket local, NetworkAddress remoteEP);
    }
}
