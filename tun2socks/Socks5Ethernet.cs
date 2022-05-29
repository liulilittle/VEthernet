namespace tun2socks
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.IO;
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
        private readonly IDictionary<IPAddress, RouteInformation> _cachesRoutes = new Dictionary<IPAddress, RouteInformation>();
        private readonly object _syncobj = new object();
        private readonly Stopwatch _sw = new Stopwatch();
        private int _disposed = 0;
        private IEnumerable<IPAddressRange> _bypassIplistRoutes = null;

        [SecurityCritical]
        [SecuritySafeCritical]
        public Socks5Ethernet(IPEndPoint proxyServer, IPAddress[] dnsAddresses, bool productMode, string user, string password, string bypassIplist, NetworkStatistics networkStatistics) : base(subnetstack: true, 0, networkStatistics)
        {
            this.Server = proxyServer ?? throw new ArgumentNullException(nameof(proxyServer));
            NetworkInterface exitNetworkInterface = Layer3Netif.GetPreferredNetworkInterfaceAddress(true, out IPAddress exitGatewayAddress);
            if (exitNetworkInterface == null)
            {
                throw new InvalidOperationException("The preferred outbound ethernet device interface could not be found");
            }
            if (dnsAddresses != null && dnsAddresses.Length > 0)
            {
                this.ApplyDNSServerAddresses = dnsAddresses;
            }
            this.ProductMode = productMode;
            this.ValidateChecksum = false;
            if (!string.IsNullOrEmpty(user) && !string.IsNullOrEmpty(password))
            {
                this.User = user;
                this.Password = password;
            }
            this.Datagram = this.CreateDatagram();
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

        public bool ProductMode { get; }

        public IPEndPoint Server { get; }

        public string User { get; set; }

        public string Password { get; set; }

        public object SynchronizedObject
        {
            get
            {
                return this._syncobj;
            }
        }

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

        protected virtual int AutomaticGatewayTimeout => 5000;

        [SecurityCritical]
        [SecuritySafeCritical]
        private bool DeleteAllAnyAddress()
        {
            lock (this._syncobj)
            {
                if (this.IsDisposed)
                {
                    return false;
                }
                var routes = Router.FindAllAnyAddress(out Router.Error error);
                if (routes != null)
                {
                    foreach (RouteInformation route in routes)
                    {
                        if (route == null)
                        {
                            continue;
                        }
                        if (!IPFrame.Equals(route.NextHop, this.Tap.GatewayAddress))
                        {
                            if (this._cachesRoutes.ContainsKey(route.NextHop))
                            {
                                continue;
                            }
                            this._cachesRoutes.Add(route.NextHop, route);
                        }
                    }
                }
                Router.Delete(this._cachesRoutes.Values);
                return true;
            }
        }

        [SecurityCritical]
        [SecuritySafeCritical]
        private void AddAllAnyAddress()
        {
            lock (this._syncobj)
            {
                IDictionary<IPAddress, RouteInformation> routes = this._cachesRoutes;
                if (routes.Count > 0)
                {
                    Router.Delete(Router.FindAllAnyAddress(out Router.Error _));
                    Router.Create(routes.Values);
                }
                routes.Clear();
            }
        }

        [SecurityCritical]
        [SecuritySafeCritical]
        protected override void OnTick(EventArgs e)
        {
            // Prevent external IP routing table modify default gw, Cause ip traffic to go not tun2socks outbound.
            Stopwatch sw = this._sw;
            if (sw.IsRunning)
            {
                lock (this._syncobj)
                {
                    if (sw.ElapsedMilliseconds >= this.AutomaticGatewayTimeout)
                    {
                        sw.Restart();
                        this.DeleteAllAnyAddress();
                    }
                }
            }
            base.OnTick(e);
        }

        protected virtual void AddAllRouter()
        {
            lock (this._syncobj)
            {
                this.DeleteAllAnyAddress();
                IPAddress cirdMiddleMask = IPAddress.Parse("128.0.0.0"); // 0.0.0.0/1
                Router.Create(IPAddress.Any, IPAddress.Any, this.Tap.GatewayAddress, this.Tap.Index, 1);
                Router.Create(IPAddress.Any, cirdMiddleMask, this.Tap.GatewayAddress, this.Tap.Index, 1);
                Router.Create(cirdMiddleMask, cirdMiddleMask, this.Tap.GatewayAddress, this.Tap.Index, 1);

                Router.Create(this.Server.Address, this.ExitGatewayAddress, 1);
                Router.AddFast(this._bypassIplistRoutes, this.ExitGatewayAddress);
            }
        }

        protected virtual void DeleteAllRouter()
        {
            lock (this._syncobj)
            {
                IPAddress cirdMiddleMask = IPAddress.Parse("128.0.0.0"); // 0.0.0.0/1
                Router.Delete(IPAddress.Any, this.Tap.GatewayAddress);
                Router.Delete(IPAddress.Any, this.Tap.GatewayAddress);
                Router.Delete(cirdMiddleMask, this.Tap.GatewayAddress);

                Router.Delete(this.Server.Address, this.ExitGatewayAddress);
                Router.DeleteFast(Interlocked.Exchange(ref this._bypassIplistRoutes, null), this.ExitGatewayAddress);
                this.AddAllAnyAddress();
            }
        }

        protected virtual void SwitchNamespaceServers(IPAddress[] addresses)
        {
            lock (this._syncobj)
            {
                Dnss.SetAddresses(this.Tap.Index, addresses);
                Dnss.SetAddresses(this.ExitInterfaceIfIndex, addresses);
                Dnss.Flush();
            }
        }

        [SecurityCritical]
        [SecuritySafeCritical]
        public override void Listen()
        {
            Exception exception = null;
            try
            {
                lock (this._syncobj)
                {
                    if (this.IsDisposed)
                    {
                        exception = new ObjectDisposedException("tun2socks");
                        return;
                    }
                    try
                    {
                        base.Listen();
                        this.AddAllRouter();
                        this.SwitchNamespaceServers(this.ApplyDNSServerAddresses);
                        this._sw.Restart();
                    }
                    catch (Exception e)
                    {
                        exception = e;
                    }
                }
            }
            finally
            {
                if (exception != null)
                {
                    throw exception;
                }
            }
        }

        [SecurityCritical]
        [SecuritySafeCritical]
        public override void Dispose()
        {
            if (Interlocked.CompareExchange(ref this._disposed, 1, 0) == 0)
            {
                lock (this._syncobj)
                {
                    this._sw.Reset();
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
                GC.SuppressFinalize(this);
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
            if (!base.ProcessIcmpInput(packet, frame))
            {
                return false;
            }
            if (frame.Type != IcmpType.ICMP_ECHO)
            {
                return false;
            }
            IcmpFrame e = new IcmpFrame(frame.Destination, frame.Source, frame.Payload)
            {
                Type = IcmpType.ICMP_ER,
                Code = frame.Code,
                Ttl = IPFrame.DefaultTtl,
                Sequence = frame.Sequence,
                Identification = frame.Identification,
            };
            this.Output(IcmpLayer.ToIPFrame(e));
            return true;
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
