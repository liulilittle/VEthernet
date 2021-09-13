namespace tun2socks
{
    using System;
    using System.Collections.Concurrent;
    using System.Collections.Generic;
    using System.Net;
    using VEthernet.Net.Udp;
    using VEthernet.Threading;
    using Interlocked = System.Threading.Interlocked;

    public class Datagram : IDisposable
    {
        private IDictionary<IPEndPoint, Port> _portTable = new ConcurrentDictionary<IPEndPoint, Port>();
        private Timer _tickAlwaysTimer = null;

        public Datagram(Socks5Ethernet ethernet)
        {
            this.Ethernet = ethernet ?? throw new ArgumentNullException(nameof(ethernet));
            this._tickAlwaysTimer = new Timer();
            this._tickAlwaysTimer.Interval = 1000;
            this._tickAlwaysTimer.Tick += (sender, e) => this.ProcessTickAlways();
            this._tickAlwaysTimer.Start();
        }

        public Socks5Ethernet Ethernet { get; }

        ~Datagram() => this.Dispose();

        public virtual void Dispose()
        {
            using (var t = Interlocked.Exchange(ref this._tickAlwaysTimer, null))
            {
                t?.Stop();
            }
            IDictionary<IPEndPoint, Port> pairs = Interlocked.Exchange(ref this._portTable, null);
            if (pairs != null)
            {
                foreach (var p in pairs.Values)
                {
                    p?.Dispose();
                }
            }
            GC.SuppressFinalize(this);
        }

        protected virtual bool ProcessTickAlways()
        {
            IDictionary<IPEndPoint, Port> pairs = this._portTable;
            if (pairs == null)
            {
                return false;
            }
            foreach (var kv in pairs)
            {
                Port port = kv.Value;
                if (port == null || port.IsPortAging)
                {
                    if (port != null)
                    {
                        port.Dispose();
                    }
                    pairs.Remove(kv.Key);
                }
            }
            return true;
        }

        protected internal virtual bool Input(UdpFrame packet)
        {
            if (packet == null)
            {
                return false;
            }
            IDictionary<IPEndPoint, Port> pairs = this._portTable;
            if (pairs == null)
            {
                return false;
            }
            Port localPort = null;
            lock (pairs)
            {
                if (!pairs.TryGetValue(packet.Source, out localPort) || localPort == null)
                {
                    localPort = this.CreatePort(packet.Source);
                    if (localPort == null)
                    {
                        return false;
                    }
                    else if (!localPort.Listen())
                    {
                        localPort.Dispose();
                        return false;
                    }
                    pairs[packet.Source] = localPort;
                }
            }
            if (localPort == null)
            {
                return false;
            }
            return localPort.Input(packet);
        }

        protected virtual Port CreatePort(IPEndPoint localEP) => new Port(this, localEP);
    }
}
