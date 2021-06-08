namespace tun2socks
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Net;
    using System.Net.NetworkInformation;
    using System.Security;
    using System.Text;
    using System.Threading;
    using VEthernet.Net;
    using VEthernet.Net.Icmp;
    using VEthernet.Net.IP;
    using VEthernet.Net.Routing;
    using VEthernet.Net.Tools;
    using VEthernet.Net.Tun;
    using VEthernet.Net.Udp;
    using VEthernet.Utilits;

    public class Socks5Ethernet : TapTap2Socket
    {
        private RouteInformation[] _cachesRoutes = null;
        private readonly object _syncobj = new object();
        private int _disposed = 0;
        private IEnumerable<IPAddressRange> _bypassIplistRoutes = null;

        [SecurityCritical]
        [SecuritySafeCritical]
        public Socks5Ethernet(IPEndPoint proxyServer, string bypassIplist, NetworkStatistics networkStatistics) : base(0, networkStatistics)
        {
            this.Server = proxyServer ?? throw new ArgumentNullException(nameof(proxyServer));
            NetworkInterface exitNetworkInterface = Layer3Netif.GetPreferredNetworkInterfaceAddress(true, out IPAddress exitGatewayAddress);
            if (exitNetworkInterface == null)
            {
                throw new InvalidOperationException("The preferred outbound ethernet device interface could not be found");
            }
            else
            {
                this.Datagram = this.CreateDatagram();
            }
            this.ExitNetworkInterface = exitNetworkInterface;
            this.ExitGatewayAddress = exitGatewayAddress;
            this.ExitInterfaceAddress = Layer3Netif.GetNetworkInterfaceAddress(exitNetworkInterface, out IPAddress exitInterfaceMask);
            this.ExitInterfaceMask = exitInterfaceMask;
            if (IPFrame.Equals(IPAddress.Any, this.ExitInterfaceAddress) || IPFrame.Equals(IPAddress.Any, this.ExitInterfaceMask))
            {
                throw new InvalidOperationException("The IPv4 address of the preferred outbound ethernet device interface could not be found");
            }
            this._bypassIplistRoutes = this.BypassIplistFromFileName(bypassIplist);
            this.ExitInterfaceIfIndex = Layer3Netif.GetAdapterIndex(exitNetworkInterface);
        }

        public bool IsDisposed => Interlocked.CompareExchange(ref this._disposed, 0, 0) != 0;

        public Datagram Datagram { get; }

        public IPEndPoint Server { get; }

        public IPAddress ExitGatewayAddress { get; private set; }

        public IPAddress ExitInterfaceAddress { get; private set; }

        public IPAddress ExitInterfaceMask { get; private set; }

        public NetworkInterface ExitNetworkInterface { get; private set; }

        public int ExitInterfaceIfIndex { get; private set; }

        public virtual IPAddress[] ApplyDNSServerAddresses { get; private set; } = new IPAddress[]
        {
            IPAddress.Parse("1.1.1.1"),
            IPAddress.Parse("8.8.8.8")
        };

        public virtual IPAddress[] RestoreDNSServerAddresses { get; private set; } = new IPAddress[]
        {
            IPAddress.Parse("223.5.5.5"),
            IPAddress.Parse("223.6.6.6")
        };

        protected virtual void AddAllRouter()
        {
            RouteInformation[] routes = null;
            lock (this._syncobj)
            {
                routes = Router.FindAllAnyAddress(out Router.Error error).Where(i =>
                    i.IfIndex != this.Tap.Index && !IPFrame.Equals(i.NextHop, this.Tap.GatewayAddress)).ToArray();
                this._cachesRoutes = routes;
            }
            IPAddress cirdMiddleMask = IPAddress.Parse("128.0.0.0"); // 0.0.0.0/1
            if (routes != null)
            {
                Router.Delete(this._cachesRoutes);
            }
            Router.Create(this.Server.Address, this.ExitGatewayAddress, 1);
            Router.AddFast(this._bypassIplistRoutes, this.ExitGatewayAddress);

            Router.Create(IPAddress.Any, IPAddress.Any, this.Tap.GatewayAddress, this.Tap.Index, 1);
            Router.Create(IPAddress.Any, cirdMiddleMask, this.Tap.GatewayAddress, this.Tap.Index, 1);
            Router.Create(cirdMiddleMask, cirdMiddleMask, this.Tap.GatewayAddress, this.Tap.Index, 1);
        }

        protected virtual void DeleteAllRouter()
        {
            RouteInformation[] cachesRoutes = null;
            lock (this._syncobj)
            {
                cachesRoutes = this._cachesRoutes;
                this._cachesRoutes = null;
            }
            IPAddress cirdMiddleMask = IPAddress.Parse("128.0.0.0"); // 0.0.0.0/1
            {
                Router.Delete(IPAddress.Any, this.Tap.GatewayAddress);
                Router.Delete(IPAddress.Any, this.Tap.GatewayAddress);
                Router.Delete(cirdMiddleMask, this.Tap.GatewayAddress);
            }
            RouteInformation[] routes = Router.FindAllAnyAddress(out Router.Error error);
            if (routes != null)
            {
                if (cachesRoutes != null)
                {
                    routes = routes.Where(i =>
                        cachesRoutes.FirstOrDefault(p => IPFrame.Equals(p.NextHop, i.NextHop)) != null).ToArray();
                }
                Router.Delete(routes);
            }
            Router.Delete(this.Server.Address, this.ExitGatewayAddress);
            Router.DeleteFast(Interlocked.Exchange(ref this._bypassIplistRoutes, null), this.ExitGatewayAddress);
            {
                bool addDefaultGW = false;
                if (cachesRoutes != null)
                {
                    addDefaultGW = cachesRoutes.
                        FirstOrDefault(i => IPFrame.Equals(i.Mask, IPAddress.Any)) != null;
                    Router.Create(cachesRoutes); // 恢复路由
                }
                if (!addDefaultGW)
                {
                    Router.Create(IPAddress.Any, IPAddress.Any, this.ExitGatewayAddress, 1); // 恢复路由
                }
            }
        }

        protected virtual void SwitchNamespaceServers(IPAddress[] addresses)
        {
            Dnss.SetAddresses(this.Tap.Index, addresses);
            Dnss.SetAddresses(this.ExitInterfaceIfIndex, addresses);
            Dnss.Flush();
        }

        public override void Listen()
        {
            base.Listen();
            this.AddAllRouter();
            this.SwitchNamespaceServers(this.ApplyDNSServerAddresses);
        }

        public override void Dispose()
        {
            if (Interlocked.CompareExchange(ref this._disposed, 1, 0) == 0)
            {
                using (this.Datagram)
                {
                    base.Dispose();
                }
                if (this.Tap != null)
                {
                    this.DeleteAllRouter();
                    this.SwitchNamespaceServers(this.RestoreDNSServerAddresses);
                }
            }
        }

        protected virtual Datagram CreateDatagram() => new Datagram(this);

        protected override TapTcpClient BeginAcceptClient(IPEndPoint localEP, IPEndPoint remoteEP)
        {
            return new Connection(this, localEP, remoteEP);
        }

        protected override bool ProcessUdpInput(IPFrame packet, UdpFrame frame)
        {
            if (!base.ProcessUdpInput(packet, frame))
            {
                return false;
            }
            return this.Datagram.Input(frame);
        }

        protected override bool ProcessIcmpInput(IPFrame packet, IcmpFrame frame)
        {
            return base.ProcessIcmpInput(packet, frame);
        }

        private IEnumerable<IPAddressRange> BypassIplistFromFileName(string fullName)
        {
            if (string.IsNullOrEmpty(fullName))
            {
                return null;
            }
            fullName = Path.GetFullPath(fullName);
            if (!File.Exists(fullName))
            {
                return null;
            }
            string content = File.ReadAllText(fullName, Encoding.UTF8);
            if (string.IsNullOrEmpty(content))
            {
                return null;
            }
            return Dnss.ToAddressRangeResources(content);
        }
    }
}
