namespace VEthernet.Net.Socks5
{
    using System;
    using System.Collections.Concurrent;
    using System.Collections.Generic;
    using System.Net;
    using System.Net.Sockets;
    using System.Threading;
    using VEthernet.Net.Auxiliary;
    using VEthernet.Net.IP;
    using VEthernet.Utilits;

    public unsafe class Socks5Communication : ISocks5Communication, IDisposable
    {
        private readonly ConcurrentDictionary<Socks5NetworkClient, Socks5NetworkClient> _networkClients
            = new ConcurrentDictionary<Socks5NetworkClient, Socks5NetworkClient>();
        private Socket _listener = null;

        public string UserName
        {
            get;
            set;
        }

        public string Password
        {
            get;
            set;
        }

        public IPEndPoint LocalEndPoint
        {
            get;
            private set;
        }

        public int Port { get; private set; }

        public virtual bool NoDelay => false;

        public ISocks5NetworkTunnelFactory Factory { get; private set; }

        public Socks5Communication(ISocks5NetworkTunnelFactory facotry)
        {
            this.Factory = facotry ?? throw new ArgumentNullException(nameof(facotry));
        }

        ~Socks5Communication() => this.Dispose();

        public virtual void Listen(string address)
        {
            IPEndPoint localEP = null;
            if (this._listener != null)
            {
                throw new InvalidOperationException("The server is already started.");
            }
            else
            {
                Ipep.FromIpepAddress(address, out string host, out int port);
                if (port < IPEndPoint.MinPort || port >= IPEndPoint.MaxPort)
                {
                    port = 0;
                }
                localEP = IPFrame.Transform(Ipep.GetEndPoint(host, port));
                if (IPFrame.Any(localEP))
                {
                    localEP = new IPEndPoint(IPAddress.Any, localEP.Port);
                }
                else if (IPFrame.Loopback(localEP))
                {
                    localEP = new IPEndPoint(IPAddress.Loopback, localEP.Port);
                }
                else
                {
                    localEP = IPFrame.V6ToV4(localEP);
                }
            }
            if (localEP == null)
            {
                throw new InvalidOperationException("Socks5 server port does not allow listening on IPv6 local addresses.");
            }
            Exception exception = null;
            try
            {
                this._listener = new NetworkSocket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                this._listener.NoDelay = this.NoDelay;
                this._listener.SetFastOpen();
                this._listener.SetTypeOfService();
                SocketExtension.EnableReuseAddress(this._listener);
                {
                    try
                    {
                        this._listener.Bind(localEP);
                    }
                    catch
                    {
                        this._listener.Bind(new IPEndPoint(localEP.Address, 0));
                    }
                    this._listener.Listen(SocketExtension.Backlog);
                }
                this.LocalEndPoint = (IPEndPoint)_listener.LocalEndPoint;
                this.Port = this.LocalEndPoint.Port;
                new Thread(this.AcceptWorkThread)
                {
                    IsBackground = true,
                    Priority = ThreadPriority.Lowest
                }.Start();
            }
            catch (Exception e)
            {
                exception = e;
                this.Dispose();
            }
            if (exception != null)
            {
                throw exception;
            }
        }

        private void AcceptWorkThread()
        {
            Socket server;
            while ((server = this._listener) != null)
            {
                Socket socket;
                try
                {
                    socket = server.Accept();
                }
                catch
                {
                    if (this._listener == null)
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
                if (!this.RunClient(socket))
                {
                    SocketExtension.Closesocket(socket);
                }
            }
        }

        private bool RunClient(Socket session)
        {
            if (session == null)
            {
                return false;
            }
            Socks5NetworkClient client = null;
            try
            {
                client = this.CreateClient(session);
                {
                    client.Disposing += (sender, e) =>
                    {
                        Socks5NetworkClient networkClient = sender as Socks5NetworkClient;
                        if (networkClient != null)
                        {
                            this._networkClients.TryRemove(networkClient, out networkClient);
                        }
                    };
                    this._networkClients.TryAdd(client, client);
                }
                client.Run();
                return true;
            }
            catch
            {
                if (client != null)
                {
                    try
                    {
                        client.Dispose();
                    }
                    catch { }
                }
                return false;
            }
        }

        protected virtual Socks5NetworkClient CreateClient(Socket session) => new Socks5NetworkClient(this, session);

        public virtual IEnumerable<Socks5NetworkClient> GetAllNetworkClient() => this._networkClients.Values;

        public virtual void Dispose()
        {
            SocketExtension.Closesocket(Interlocked.Exchange(ref this._listener, null));
            this.Factory = null;
            foreach (Socks5NetworkClient networkClient in this.GetAllNetworkClient())
            {
                networkClient.Dispose();
            }
            this._networkClients.Clear();
            GC.SuppressFinalize(this);
        }
    }
}
