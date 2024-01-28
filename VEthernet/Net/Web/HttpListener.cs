namespace VEthernet.Net.Web
{
    using System;
    using System.Collections.Concurrent;
    using System.Collections.Generic;
    using System.Net;
    using System.Net.Sockets;
    using System.Threading;
#if NETCOREAPP
    using System.Runtime.CompilerServices;
#endif
    using global::VEthernet.Net;
    using global::VEthernet.Net.Auxiliary;
    using Timer = global::VEthernet.Threading.Timer;

    public class HttpListener : IDisposable
    {
        private bool disposed = false;
        private Socket listener = null;
        private Timer tickTimer = null;
        private readonly IDictionary<HttpTunnel, HttpTunnel> tunnels
            = new ConcurrentDictionary<HttpTunnel, HttpTunnel>();

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public HttpListener(string host, int port)
        {
            if (port < IPEndPoint.MinPort || port >= IPEndPoint.MaxPort)
            {
                throw new ArgumentOutOfRangeException($"The ports you want to bind to the network card for listening must be between {IPEndPoint.MinPort + 1} and {IPEndPoint.MaxPort}");
            }
            if (string.IsNullOrEmpty(host) || (host = host.Trim()).Length < 1)
            {
                host = IPAddress.IPv6Any.ToString();
            }
            IPAddress address = IPAddress.IPv6Any;
            if (!string.IsNullOrEmpty(host))
            {
                if (!IPAddress.TryParse(host, out address))
                {
                    address = IPAddress.IPv6Any;
                }
            }
            this.Port = port;
            this.listener = new NetworkSocket(AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp);
            this.listener.SetFastOpen();
            this.listener.IPv6Only(false);
            this.listener.SetTypeOfService();
            SocketExtension.EnableReuseAddress(this.listener);
            try
            {
                this.listener.Bind(new IPEndPoint(address, port));
            }
            catch (SocketException)
            {
                this.listener.Bind(new IPEndPoint(address, 0));
            }
            IPEndPoint localEP = (IPEndPoint)this.listener.LocalEndPoint;
            this.Host = address.ToString();
            this.Port = localEP.Port;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        ~HttpListener() => this.Dispose();

        public bool IsDisposed
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
            get => this.disposed;
        }

        public virtual bool NoDelay
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif 
            get => false;
        }

        public int Port
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
            get;
        }

        public string Host
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
            get;
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            protected set;
        }

        public virtual int MaxInactivityTime
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
            get;
        } = 300000;

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public virtual bool Listen()
        {
            if (this.disposed)
            {
                return false;
            }
            try
            {
                this.listener.NoDelay = this.NoDelay;
                SocketExtension.Listen(this.listener, SocketExtension.Backlog);
            }
            catch
            {
                return false;
            }
            if (this.tickTimer == null)
            {
                this.tickTimer = new Timer(1000);
                this.tickTimer.Tick += (sender, e) => this.ProcessTickAlways();
                this.tickTimer.Start();
            }
            Thread t = new Thread(this.AcceptWorkThread);
            t.IsBackground = true;
            t.Priority = ThreadPriority.Lowest;
            t.Start();
            return true;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        protected virtual void ProcessTickAlways()
        {
            foreach (HttpTunnel tunnel in this.tunnels.Values)
            {
                if (tunnel.IsPortAging)
                {
                    using (tunnel)
                    {
                        this.tunnels.Remove(tunnel);
                    }
                }
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        protected virtual internal bool Unwatch(HttpTunnel tunnel)
        {
            if (tunnel == null)
            {
                return false;
            }
            return this.tunnels.Remove(tunnel);
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        private void AcceptWorkThread()
        {
            Socket server;
            while (!this.disposed && (server = this.listener) != null)
            {
                Socket socket;
                try
                {
                    socket = server.Accept();
                }
                catch
                {
                    bool b = this.disposed || this.listener == null;
                    if (b)
                    {
                        break;
                    }
                    else
                    {
                        Thread.Sleep(10);
                        continue;
                    }
                }
                try
                {
                    socket.NoDelay = this.NoDelay;
                    socket.SetTypeOfService();
                }
                catch
                {
                    SocketExtension.Closesocket(socket);
                    continue;
                }
                bool closesocket = true;
                HttpTunnel tunnel = null;
                if (socket != null)
                {
                    tunnel = this.CreateTunnel(socket);
                    if (tunnel != null)
                    {
                        if (tunnel.ConnectAsync())
                        {
                            closesocket = false;
                            this.tunnels.Add(tunnel, tunnel);
                        }
                    }
                }
                if (closesocket)
                {
                    if (tunnel != null)
                    {
                        try
                        {
                            tunnel.Dispose();
                        }
                        catch { }
                    }
                    SocketExtension.Closesocket(socket);
                }
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        protected virtual HttpTunnel CreateTunnel(Socket socket)
        {
            if (socket == null)
            {
                return null;
            }
            try
            {
                return new HttpTunnel(this, socket);
            }
            catch
            {
                return null;
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public virtual void Dispose()
        {
            SocketExtension.Closesocket(Interlocked.Exchange(ref this.listener, null));
            foreach (HttpTunnel tunnel in this.tunnels.Values)
            {
                tunnel.Dispose();
            }
            this.tunnels.Clear();
            using (var t = this.tickTimer)
            {
                if (t != null)
                {
                    t.Stop();
                    this.tickTimer = null;
                }
            }
            this.disposed = true;
            GC.SuppressFinalize(this);
        }
    }
}
