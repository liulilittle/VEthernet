namespace VEthernet.Net.Socks5
{
    using System;

    public interface ISocks5NetworkTunnel : IDisposable
    {
        event EventHandler Disconnected;

        void Open();
    }
}
