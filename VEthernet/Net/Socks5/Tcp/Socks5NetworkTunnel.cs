namespace VEthernet.Net.Socks5.Tcp
{
    using System;
    using System.Diagnostics;
    using System.Net;
    using System.Net.Sockets;
    using System.Threading;
    using VEthernet.Net.Auxiliary;
    using VEthernet.Net.Socks5;
    using Timer = VEthernet.Threading.Timer;

    public class Socks5NetworkTunnel : ISocks5NetworkTunnel, IDisposable
    {
        private byte[] _session_buffer; // 代理客户端缓冲区
        private byte[] _server_buffer; // 远程服务器缓冲区
        private Socket _session; // 代理客户端
        private Socket _server; // 远程服务器
        private int _disposed = 0;
        private NetworkAddress _remoteEP; // 远程网路端点
        private Timer _agingTimer = null;
        private readonly Stopwatch _agingsw = new Stopwatch();

        public Socks5NetworkTunnel(Socket session, NetworkAddress remoteEP)
        {
            this._session = session ?? throw new ArgumentNullException(nameof(session));
            this._remoteEP = remoteEP ?? throw new ArgumentNullException(nameof(remoteEP));
            try
            {
                this._server = new NetworkSocket(AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp);
                this._server.SetFastOpen();
                this._server.SetTypeOfService();
                this._server.IPv6Only(false);
            }
            catch (Exception e)
            {
                this.Dispose();
                throw e;
            }
        }

        ~Socks5NetworkTunnel() => this.Dispose();

        public event EventHandler Disconnected; // 隧道被关闭

        protected virtual Socket Session => this._session;

        protected virtual Socket Server => this._server;

        protected virtual byte[] SessionBuffer => this._server_buffer;

        protected virtual byte[] ServerBuffer => this._server_buffer;

        protected virtual void OnDisconnected(EventArgs e)
        {
            var events = this.Disconnected;
            if (events != null)
            {
                events(this, e);
            }
        }

        protected virtual NetworkAddress GetNetworkAddress() => this._remoteEP;

        protected virtual IPEndPoint DestinationHost
        {
            get
            {
                NetworkAddress address = this._remoteEP;
                if (address == null)
                {
                    return null;
                }
                return address.EndPoint;
            }
        }

        protected virtual int MSS
        {
            get
            {
                return SocketExtension.MSS;
            }
        }


        protected virtual int MaxInactivityTime => 300000;

        public virtual bool IsDisposed => Interlocked.CompareExchange(ref this._disposed, 0, 0) != 0;

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

        public virtual void Open()
        {
            if (Interlocked.CompareExchange(ref this._disposed, 0, 0) != 0)
            {
                return;
            }
            IPEndPoint host = this.DestinationHost;
            if (host == null)
            {
                this.Dispose();
                return;
            }
            try
            {
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
                this._server.BeginConnect(host, (ar) =>
                {
                    Socket socket = this._server;
                    if (ar == null || socket == null)
                    {
                        this.Dispose();
                        return;
                    }
                    try
                    {
                        socket.EndConnect(ar);
                    }
                    catch
                    {
                        this.Dispose();
                        return;
                    }
                    this.OnDestinationHostConnected(true);
                }, null);
            }
            catch
            {
                this.Dispose();
            }
        }

        public virtual void Dispose()
        {
            bool disconnected = false;
            SocketExtension.Closesocket(Interlocked.Exchange(ref this._server, null));
            SocketExtension.Closesocket(Interlocked.Exchange(ref this._session, null));
            using (var t = Interlocked.Exchange(ref this._agingTimer, null))
            {
                t?.Stop();
            }
            this._session_buffer = null;
            this._server_buffer = null;
            if (Interlocked.CompareExchange(ref this._disposed, 1, 0) == 0)
            {
                if (disconnected)
                {
                    this.OnDisconnected(EventArgs.Empty);
                }
            }
            this._remoteEP = null;
            this.Disconnected = null;
            GC.SuppressFinalize(this);
        }

        protected virtual void ActiveTunnel()
        {
            if (Interlocked.CompareExchange(ref this._disposed, 0, 0) == 0)
            {
                this._agingsw.Restart();
            }
        }

        protected virtual void OnDestinationHostConnected(bool pullReceiver) // 隧道连接成功
        {
            if (Interlocked.CompareExchange(ref this._disposed, 0, 0) != 0)
            {
                return;
            }
            this._server_buffer = new byte[this.MSS];
            this._session_buffer = new byte[this.MSS];
            if (pullReceiver)
            {
                this.ActiveTunnel();
                this.PullReceiver(true);
                this.PullReceiver(false);
            }
        }

        protected virtual void PullReceiver(bool local)
        {
            if (local)
            {
                this.ForwardToServer(null);
            }
            else
            {
                this.ForwardToSession(null);
            }
        }

        private void ForwardToSession(IAsyncResult ar)
        {
            Socket socket = this._server;
            if (socket == null)
            {
                return;
            }
            byte[] buffer = this._server_buffer;
            if (buffer == null)
            {
                return;
            }
            try
            {
                SocketError error = SocketError.SocketError;
                if (ar == null)
                {
                    if (!SocketExtension.BeginReceive(socket, buffer, 0, buffer.Length, this.ForwardToSession))
                    {
                        this.Dispose();
                    }
                }
                else
                {
                    int len = 0;
                    if (!SocketExtension.CleanedUp(socket))
                    {
                        len = socket.EndReceive(ar, out error);
                    }
                    if (len < 1 || error != SocketError.Success)
                    {
                        this.Dispose();
                    }
                    else
                    {
                        this.SendToLocal(buffer, 0, len, (ok) =>
                        {
                            if (ok)
                            {
                                this.ActiveTunnel();
                                this.PullReceiver(false);
                            }
                        });
                    }
                }
            }
            catch
            {
                this.Dispose();
            }
        }

        private void ForwardToServer(IAsyncResult ar)
        {
            Socket socket = this._session;
            if (socket == null)
            {
                return;
            }
            byte[] buffer = this._session_buffer;
            if (buffer == null)
            {
                return;
            }
            try
            {
                SocketError error = SocketError.SocketError;
                if (ar == null)
                {
                    if (!SocketExtension.BeginReceive(socket, buffer, 0, buffer.Length, this.ForwardToServer))
                    {
                        this.Dispose();
                    }
                }
                else
                {
                    int len = 0;
                    if (!SocketExtension.CleanedUp(socket))
                    {
                        len = socket.EndReceive(ar, out error);
                    }
                    if (len < 1 || error != SocketError.Success)
                    {
                        this.Dispose();
                    }
                    else
                    {
                        this.SendToServer(buffer, 0, len, (ok) =>
                        {
                            if (ok)
                            {
                                this.ActiveTunnel();
                                this.PullReceiver(true);
                            }
                        });
                    }
                }
            }
            catch
            {
                this.Dispose();
            }
        }

        public virtual bool SendToLocal(byte[] buffer, int offset, int length, Action<bool> success)
        {
            bool ok = SocketExtension.BeginSend(this._session, buffer, offset, length, (AsyncCallback)((ar) =>
            {
                SocketError error = SocketError.SocketError;
                try
                {
                    Socket socket = this._session;
                    if (socket != null)
                    {
                        socket.EndReceive(ar, out error);
                    }
                }
                catch { }
                bool noerror = error == SocketError.Success;
                if (!noerror)
                {
                    this.Dispose();
                }
                success?.Invoke(noerror);
            }));
            if (!ok)
            {
                this.Dispose();
                return false;
            }
            return true;
        }

        public virtual bool SendToServer(byte[] buffer, int offset, int length, Action<bool> success)
        {
            bool ok = SocketExtension.BeginSend(this._server, buffer, offset, length, (AsyncCallback)((ar) =>
            {
                SocketError error = SocketError.SocketError;
                try
                {
                    Socket socket = this._server;
                    if (socket != null)
                    {
                        socket.EndReceive(ar, out error);
                    }
                }
                catch { }
                bool noerror = error == SocketError.Success;
                if (!noerror)
                {
                    this.Dispose();
                }
                success?.Invoke(noerror);
            }));
            if (!ok)
            {
                this.Dispose();
                return false;
            }
            return true;
        }
    }
}
