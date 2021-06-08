namespace tun2socks
{
    using System;
    using System.Collections.Generic;
    using System.Net;
    using VEthernet.Collections;
    using VEthernet.Net.Udp;
    using VEthernet.Threading;

    public class Datagram : IDisposable
    {
        private readonly object _syncobj = new object();
        private Timer _tickAlwaysTimer = null;
        private bool _disposed = false;
        private readonly IDictionary<IPEndPoint, Port> _portTable = new ConcurrentDictionary<IPEndPoint, Port>();

        public Datagram(Socks5Ethernet ethernet)
        {
            this.Ethernet = ethernet ?? throw new ArgumentNullException(nameof(ethernet));
            this._tickAlwaysTimer = new Timer();
            this._tickAlwaysTimer.Interval = 1000;
            this._tickAlwaysTimer.Tick += (sender, e) =>
            {
                bool disposed = false;
                lock (this._syncobj)
                {
                    disposed = this._disposed;
                }
                if (!disposed)
                {
                    this.ProcessTickAlways();
                }
            };
            this._tickAlwaysTimer.Start();
        }

        public Socks5Ethernet Ethernet { get; }

        ~Datagram() => this.Dispose();

        public virtual void Dispose()
        {
            IList<IDisposable> disposables = null;
            lock (this._syncobj)
            {
                using (var timer = this._tickAlwaysTimer)
                {
                    this._tickAlwaysTimer = null;
                }
                if (!this._disposed)
                {
                    disposables = new List<IDisposable>();
                    foreach (var kv in this._portTable)
                    {
                        var port = kv.Value;
                        if (port != null)
                        {
                            disposables.Add(port);
                        }
                    }
                    this._portTable.Clear();
                }
                this._disposed = true;
            }
            if (disposables != null)
            {
                foreach (var p in disposables)
                {
                    p.Dispose();
                }
            }
            GC.SuppressFinalize(this);
        }

        protected virtual bool ProcessTickAlways()
        {
            IDictionary<IPEndPoint, Port> portEnumrator = null;
            lock (this._syncobj)
            {
                if (this._disposed)
                {
                    return false;
                }
                portEnumrator = this._portTable;
            }
            if (portEnumrator == null)
            {
                return false;
            }
            foreach (var kv in portEnumrator)
            {
                Port port = kv.Value;
                if (port == null || port.IsPortAging)
                {
                    if (port != null)
                    {
                        port.Dispose();
                    }
                    this._portTable.Remove(kv.Key);
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
            Port localPort = null;
            lock (this._syncobj)
            {
                if (this._disposed)
                {
                    return false;
                }
                if (!this._portTable.TryGetValue(packet.Source, out localPort) || localPort == null)
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
                    this._portTable[packet.Source] = localPort;
                }
            }
            if (localPort == null)
            {
                return false;
            }
            return localPort.Input(packet);
        }

        protected virtual Port CreatePort(IPEndPoint localEP)
        {
            return new Port(this, localEP);
        }
    }
}
