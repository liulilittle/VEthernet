namespace VEthernet.Net.WebSocket
{
    using System;
    using System.Diagnostics;
    using System.Net;
    using System.Net.Sockets;
    using System.Threading;
    using VEthernet.Net.Auxiliary;

    public class WebSocketServer
    {
        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private Socket server = default(Socket);

        public event OpenEventHandler OnOpen;
        public event MessageEventHandler OnMessage;
        public event ErrorEventHandler OnError;
        public event CloseEventHandler OnClose;

        public WebSocketServer(int port)
        {
            if (port < 1 || port > 0xFFFF)
            {
                throw new ArgumentException("port");
            }
            this.Port = port;
        }

        public virtual void Start()
        {
            lock (this)
            {
                if (server != null)
                {
                    throw new InvalidOperationException();
                }
                server = new NetworkSocket(AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp);
                server.SetTypeOfService();
                server.IPv6Only(false);
                server.SetFastOpen();
                server.EnableReuseAddress();
                server.Bind(new IPEndPoint(IPAddress.IPv6Any, Port));
                server.Listen(SocketExtension.Backlog);
                StartAccept(null);
            }
        }

        public virtual int Port { get; private set; }

        public virtual object Tag
        {
            get;
            set;
        }

        public virtual object UserToken
        {
            get;
            set;
        }

        public virtual int GetBindPort()
        {
            if (server == null)
            {
                return 0;
            }
            IPEndPoint ipep = (IPEndPoint)server.LocalEndPoint;
            return ipep.Port;
        }

        public virtual void Stop()
        {
            lock (this)
            {
                SocketExtension.Closesocket(Interlocked.Exchange(ref this.server, null));
            }
        }

        private void StartAccept(SocketAsyncEventArgs e)
        {
            bool willRaiseEvent = true;
            if (e == null)
            {
                e = new SocketAsyncEventArgs();
                e.Completed += ProcessAccept;
            }
            e.AcceptSocket = null;
            try
            {
                lock (this)
                {
                    if (!SocketExtension.CleanedUp(server))
                    {
                        willRaiseEvent = server.AcceptAsync(e);
                    }
                }
            }
            catch { /*-A-*/ }
            if (!willRaiseEvent)
            {
                ProcessAccept(server, e);
            }
        }

        private void ProcessAccept(object sender, SocketAsyncEventArgs e)
        {
            if (e.SocketError == SocketError.Success)
            {
                Socket socket = e.AcceptSocket;
                if (socket != null)
                {
                    WebSocket ws = null;
                    try
                    {
                        socket.SetTypeOfService();
                        {
                            ws = new WebSocket(socket);
                            ws.OnClose += WebSocket_OnClose;
                            ws.OnError += WebSocket_OnError;
                            ws.OnMessage += WebSocket_OnMessage;
                            ws.OnOpen += WebSocket_OnOpen;
                            ws.Open();
                        }
                    }
                    catch(Exception)
                    {
                        if (ws != null)
                        {
                            ws.Dispose();
                        }
                        SocketExtension.Closesocket(socket);
                    }
                }
            }
            StartAccept(e);
        }

        private void WebSocket_OnOpen(object sender, EventArgs e) => OnOpen?.Invoke((WebSocket)sender, e);

        private void WebSocket_OnMessage(object sender, MessageEventArgs e) => OnMessage?.Invoke((WebSocket)sender, e);

        private void WebSocket_OnError(object sender, ErrorEventArgs e) => OnError?.Invoke((WebSocket)sender, e);

        private void WebSocket_OnClose(object sender, CloseEventArgs e) => OnClose?.Invoke((WebSocket)sender, e);
    }
}
