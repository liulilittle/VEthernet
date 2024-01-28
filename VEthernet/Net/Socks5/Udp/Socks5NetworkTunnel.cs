namespace VEthernet.Net.Socks5.Udp
{
    using System;
    using System.Diagnostics;
    using System.Net;
    using System.Net.Sockets;
    using System.Threading;
    using VEthernet.Net.Auxiliary;
    using VEthernet.Net.IP;
    using VEthernet.Net.Socks5;
    using Timer = VEthernet.Threading.Timer;

    public unsafe class Socks5NetworkTunnel : ISocks5NetworkTunnel, IDisposable
    {
        private Socket _server;
        private Socket _session;
        private AsyncSocket _async_server;
        private AsyncSocket _async_local;
        private int _disposed = 0;
        private Timer _agingTimer = null;
        private readonly Stopwatch _agingsw = new Stopwatch();

        public event EventHandler Disconnected = default(EventHandler);

        public QoS Qos { get; private set; }

        protected virtual Socket Server => this._server;

        protected virtual Socket Local { get; private set; }

        protected virtual EndPoint LocalEP { get; private set; }

        protected virtual void OnDisconnected(EventArgs e) => this.Disconnected?.Invoke(this, e);

        public Socks5NetworkTunnel(Socket local, Socket session, QoS qos)
        {
            this.Local = local ?? throw new ArgumentNullException(nameof(local));
            this._session = session ?? throw new ArgumentNullException(nameof(session));
            this.Qos = qos;
            try
            {
                this._server = new NetworkSocket(AddressFamily.InterNetworkV6, SocketType.Dgram, ProtocolType.Udp);
                this._server.SetTypeOfService();
                this._server.IPv6Only(false);
                SocketExtension.SioUdpConnectReset(this._server);
                this._server.Bind(new IPEndPoint(IPAddress.IPv6Any, 0));
                this._async_local = AsyncContext.GetContext().CreateSocket(local);
                this._async_server = AsyncContext.GetContext().CreateSocket(this._server);
            }
            catch (Exception e)
            {
                this.Dispose();
                throw e;
            }
            this.ActiveTunnel();
        }

        ~Socks5NetworkTunnel() => this.Dispose();

        protected virtual int MaxInactivityTime => 72000;

        public virtual bool IsDisposed => 0 != Interlocked.CompareExchange(ref this._disposed, 0, 0);

        public virtual bool IsPortAging
        {
            get
            {
                if (this.IsDisposed)
                {
                    return true;
                }
                long maxInactivityTime = this.MaxInactivityTime;
                if (maxInactivityTime < 1000)
                {
                    maxInactivityTime = 1000;
                }
                long milliseconds = this._agingsw.ElapsedMilliseconds;
                return milliseconds >= maxInactivityTime;
            }
        }

        protected virtual void ActiveTunnel()
        {
            if (Interlocked.CompareExchange(ref this._disposed, 0, 0) == 0)
            {
                this._agingsw.Restart();
            }
        }

        public virtual void Dispose()
        {
            if (Interlocked.CompareExchange(ref this._disposed, 1, 0) == 0)
            {
                bool disconnected = false;
                SocketExtension.Closesocket(Interlocked.Exchange(ref this._server, null));
                SocketExtension.Closesocket(Interlocked.Exchange(ref this._session, null));
                SocketExtension.Closesocket(Interlocked.Exchange(ref this._server, null));
                Interlocked.Exchange(ref this._async_local, null)?.Close();
                Interlocked.Exchange(ref this._async_server, null)?.Close();
                Socket socket = this.Local;
                if (socket != null)
                {
                    SocketExtension.Closesocket(socket);
                    disconnected = true;
                    this.Local = null;
                }
                using (var t = Interlocked.Exchange(ref this._agingTimer, null))
                {
                    t?.Stop();
                }
                if (disconnected)
                {
                    this.OnDisconnected(EventArgs.Empty);
                }
                this.Disconnected = null;
            }
            GC.SuppressFinalize(this);
        }

        public virtual void Open()
        {
            if (Interlocked.CompareExchange(ref this._disposed, 0, 0) != 0)
            {
                throw new ObjectDisposedException(this.GetType().FullName);
            }
            Timer agingTimer = this._agingTimer;
            if (this._agingTimer == null)
            {
                agingTimer = new Timer();
                agingTimer.Interval = 1000;
                agingTimer.Tick += (sender, e) =>
                {
                    if (this.IsPortAging)
                    {
                        this.Dispose();
                    }
                };
                agingTimer.Start();
                this._agingTimer = agingTimer;
            }
            this.StartLocalReceive(null);
            this.StartServerReceive(null);
            this.StartSessionMonitor(null);
        }

        private void StartSessionMonitor(IAsyncResult ar)
        {
            if (this.IsDisposed)
            {
                this.Dispose();
                return;
            }
            Socket socket = this._session;
            if (socket == null)
            {
                this.Dispose();
                return;
            }
            if (ar == null)
            {
                byte[] buffer = new byte[1];
                if (!SocketExtension.BeginReceive(socket, buffer, 0, buffer.Length, this.StartSessionMonitor))
                {
                    this.Dispose();
                }
            }
            else
            {
                int len = SocketExtension.EndReceive(socket, ar);
                if (len < 1)
                {
                    this.Dispose();
                    return;
                }
                this.ActiveTunnel();
                this.StartSessionMonitor(null);
            }
        }

        private void StartServerReceive(IAsyncResult ar)
        {
            if (this.IsDisposed)
            {
                this.Dispose();
                return;
            }
            AsyncSocket socket = this._async_server;
            if (socket == null || SocketExtension.CleanedUp(socket.Socket))
            {
                this.Dispose();
                return;
            }
            QoS qos = this.Qos;
            if (qos == null)
            {
                byte[] buffer = socket.Context.Buffer;
                if (!socket.ReceiveFrom(buffer, 0, buffer.Length, (len, remoteEP) =>
                {
                    if (len < 0)
                    {
                        this.Dispose();
                        return;
                    }
                    if (len > 0)
                    {
                        this.ActiveTunnel();
                        this.SendToLocal(buffer, 0, len, IPFrame.Transform(remoteEP));
                    }
                    this.StartServerReceive(null);
                }))
                {
                    this.Dispose();
                    return;
                }
            }
            else
            {
                byte[] buffer = socket.Context.Buffer;
                bool ok = qos.ReceiveFrom(socket, buffer, 0, buffer.Length, (len, remoteEP) =>
                {
                    if (len < 0)
                    {
                        this.Dispose();
                        return;
                    }
                    if (len > 0)
                    {
                        this.ActiveTunnel();
                        this.SendToLocal(buffer, 0, len, (IPEndPoint)remoteEP);
                    }
                    this.StartServerReceive(null);
                });
                if (!ok)
                {
                    this.Dispose();
                    return;
                }
            }
        }

        protected virtual bool SendToLocal(byte[] buffer, int ofs, int len, IPEndPoint remoteEP) =>
            Socks5Extension.SendTo(this.Local, buffer, ofs, len, this.LocalEP, remoteEP);

        private void StartLocalReceive(IAsyncResult ar)
        {
            if (this.IsDisposed)
            {
                this.Dispose();
                return;
            }
            AsyncSocket socket = this._async_local;
            if (socket == null || SocketExtension.CleanedUp(socket.Socket))
            {
                this.Dispose();
                return;
            }
            byte[] buffer = socket.Context.Buffer;
            if (!socket.ReceiveFrom(buffer, 0, buffer.Length, (len, remoteEP) =>
            {
                if (len < 0)
                {
                    this.Dispose();
                    return;
                }
                this.LocalEP = IPFrame.Transform(remoteEP);
                if (len > 0)
                {
                    int offset = -1;
                    NetworkAddress address = Socks5Extension.ResolveEP(buffer, &offset, len);
                    if (address != null && offset >= 0)
                    {
                        this.SendToServer(buffer, offset, (len - offset), address);
                    }
                }
                this.StartLocalReceive(null);
            }))
            {
                this.Dispose();
                return;
            }
        }

        protected virtual bool SendToServer(byte[] buffer, int ofs, int len, NetworkAddress address)
        {
            IPEndPoint remoteEP = address.EndPoint;
            if (remoteEP == null)
            {
                return false;
            }
            return SocketExtension.SendTo(this._server, buffer, ofs, len, remoteEP);
        }
    }
}
