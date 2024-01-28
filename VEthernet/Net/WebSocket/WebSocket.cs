namespace VEthernet.Net.WebSocket
{
    using System;
    using System.IO;
    using System.Net;
    using System.Net.Sockets;
    using System.Text;
    using System.Threading;
    using VEthernet.Core;
    using VEthernet.Net.Auxiliary;

    public class WebSocket : IDisposable
    {
        private readonly Uri _connectUri;
        private string _rawUri;
        private byte[] _buffer;
        private bool _cleanUp;
        private AsyncCallback _rcvAc;
        private WebSocketFrame _frame;
        private Socket _socket;
        private readonly bool _clientMode;
        private readonly IPEndPoint _serverEP;
        private readonly object _syncobj = new object();
        private static readonly Encoding _encoding = Encoding.UTF8;

        public event EventHandler<MessageEventArgs> OnMessage;
        public event EventHandler<EventArgs> OnOpen;
        public event EventHandler<ErrorEventArgs> OnError;
        public event EventHandler<CloseEventArgs> OnClose;

        public virtual bool Available
        {
            get
            {
                lock (this._syncobj)
                {
                    if (SocketExtension.CleanedUp(_socket))
                    {
                        return false;
                    }
                    return _socket.Connected;
                }
            }
        }

        public virtual EndPoint LocalEndPoint
        {
            get
            {
                return _socket.LocalEndPoint;
            }
        }

        public virtual int Ttl
        {
            get
            {
                return _socket.Ttl;
            }
        }

        public virtual IntPtr Handle
        {
            get
            {
                return _socket.Handle;
            }
        }

        public virtual EndPoint RemoteEndPoint
        {
            get
            {
                return _socket.RemoteEndPoint;
            }
        }

        public virtual string Path
        {
            get
            {
                if (this._clientMode)
                {
                    return this._connectUri.AbsolutePath;
                }
                else
                {
                    return this._rawUri;
                }
            }
        }

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

        public virtual void Open()
        {
            if (this.Available)
            {
                if (this._clientMode)
                {
                    throw new InvalidOperationException();
                }
            }
            lock (this._syncobj)
            {
                if (this._clientMode)
                {
                    this.DoConnectAsync(this._serverEP);
                }
                else
                {
                    SHCreateThread(this.Handshake);
                }
            }
        }

        private void DoConnectAsync(IPEndPoint server)
        {
            EventHandler<SocketAsyncEventArgs> handler = (sender, e) =>
            {
                if (e.SocketError != SocketError.Success)
                {
                    this.CloseOrError(true);
                }
                else
                {
                    SHCreateThread(this.Handshake);
                }
            };
            try
            {
                SocketAsyncEventArgs e = new SocketAsyncEventArgs();
                e.Completed += handler;
                e.RemoteEndPoint = server;
                if (!_socket.ConnectAsync(e))
                {
                    handler(_socket, e);
                }
            }
            catch
            {
                CloseOrError(true);
            }
        }

        private WebSocket()
        {
            this._buffer = new byte[SocketExtension.MSS];
            this._rcvAc = this.ProcessReceive;
        }

        public WebSocket(Socket socket) : this()
        {
            this._socket = socket;
            this._clientMode = false;
        }

        public WebSocket(string uri) : this()
        {
            if (string.IsNullOrEmpty(uri))
            {
                throw new ArgumentNullException("uri");
            }
            Uri url = new Uri(uri);
            if (url.Scheme != "ws")
            {
                throw new ArgumentException("uri");
            }
            if (string.IsNullOrEmpty(url.LocalPath))
            {
                throw new ArgumentNullException("uri");
            }
            if (url.LocalPath[0] != '/')
            {
                throw new ArgumentNullException("uri");
            }
            IPEndPoint server = new IPEndPoint(IPAddress.Parse(url.Host), url.Port);
            this._clientMode = true;
            this._connectUri = url;
            this._serverEP = server;
            this._socket = new NetworkSocket(AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp);
            this._socket.IPv6Only(false);
            this._socket.SetFastOpen();
            this._socket.SetTypeOfService();
        }

        ~WebSocket()
        {
            this.Close();
        }

        private static void SHCreateThread(ThreadStart startRoute)
        {
            Thread main = new Thread(startRoute);
            main.IsBackground = true;
            main.Priority = ThreadPriority.Lowest;
            main.Start();
        }

        public void Close()
        {
            this.Dispose();
        }

        public virtual bool NoDelay
        {
            get
            {
                return _socket.NoDelay;
            }
            set
            {
                _socket.NoDelay = true;
            }
        }

        protected virtual bool AutoReceived
        {
            get;
            private set;
        }

        private void CloseOrError(bool error)
        {
            bool events = false;
            lock (this._syncobj)
            {
                if (!this._cleanUp)
                {
                    events = !this._cleanUp;
                    SocketExtension.Closesocket(Interlocked.Exchange(ref this._socket, null));
                    this._cleanUp = true;
                }
                this._buffer = null;
                this._rcvAc = null;
            }
            GC.SuppressFinalize(this);
            if (events)
            {
                if (error)
                {
                    this.DoError(new ErrorEventArgs());
                }
                else
                {
                    this.DoClose(new CloseEventArgs());
                }
            }
        }

        protected virtual void DoError(ErrorEventArgs e)
        {
            if (OnError != null)
            {
                OnError(this, e);
            }
        }

        protected virtual void DoClose(CloseEventArgs e)
        {
            if (OnClose != null)
            {
                OnClose(this, e);
            }
        }

        protected virtual void DoOpen(EventArgs e)
        {
            if (OnOpen != null)
            {
                OnOpen(this, e);
            }
        }

        private void Handshake()
        {
            WebSocketSessionHandshake handshakeSession = null;
            WebSocketServerHandshake handshakeServer = null;
            lock (this._syncobj)
            {
                if (this._clientMode)
                {
                    handshakeSession = WebSocketSessionHandshake.Handshake(this, this._socket, this._connectUri);
                }
                else
                {
                    handshakeServer = WebSocketServerHandshake.Handshake(this, this._socket);
                    if (handshakeServer != null)
                    {
                        this._rawUri = handshakeServer.RawUri;
                    }
                }
            }
            if (handshakeServer == null && handshakeSession == null)
            {
                this.CloseOrError(true);
            }
            else
            {
                this.DoOpen(EventArgs.Empty);
                this.ProcessReceive(null);
            }
        }

        private unsafe void ProcessReceive(IAsyncResult ar)
        {
            if (ar == null)
            {
                int len = SocketExtension.MSS;
                if (_frame != null)
                {
                    long surplus = _frame.payload_surplus;
                    if (surplus < len)
                    {
                        len = (int)surplus;
                    }
                }
                AsyncCallback ac = this._rcvAc;
                if (ac != null)
                {
                    if (!SocketExtension.BeginReceive(_socket, _buffer, 0, len, ac))
                    {
                        CloseOrError(true);
                    }
                }
            }
            else
            {
                int len = SocketExtension.EndReceive(_socket, ar);
                if (len < 1)
                {
                    CloseOrError(false);
                }
                else
                {
                    fixed (byte* pinned = _buffer)
                    {
                        if (pinned != null)
                        {
                            ProcessReceive(pinned, len);
                        }
                    }
                }
            }
        }

        private unsafe void ProcessReceive(byte* buffer, int len)
        {
            bool error = false;
            do
            {
                if (this._frame == null)
                {
                    this._frame = WebSocketFrame.Unpack(buffer, len);
                    if (this._frame == null)
                    {
                        error = true;
                        break;
                    }
                }
                else
                {
                    WebSocketFrame.PayloadAdditional(_frame, buffer, len);
                }
                long surplus = this._frame.payload_surplus;
                if (surplus < 1)
                {
                    WebSocketFrame frame = this._frame;
                    do
                    {
                        this._frame = null;
                        ProcessFrame(frame);
                    } while (false);
                    if (this.AutoReceived)
                    {
                        this.RepullListen();
                    }
                }
                else
                {
                    this.ProcessReceive(null);
                }
            } while (false);
            if (error)
            {
                this.CloseOrError(true);
            }
        }

        protected virtual void RepullListen() => this.ProcessReceive(null);

        private unsafe void ProcessFrame(WebSocketFrame frame)
        {
            if (frame == null || !frame.fin) // 不支持多个分片帧
            {
                CloseOrError(true);
            }
            else
            {
                DoMessage(new MessageEventArgs((OpCode)frame.opcode, frame.payload_data));
            }
        }

        protected virtual void DoMessage(MessageEventArgs e)
        {
            if (OnMessage != null)
            {
                OnMessage(this, e);
            }
        }

        public virtual bool Send(string message, Action<bool> ok)
        {
            if (message == null)
            {
                return false;
            }
            lock (this._syncobj)
            {
                if (!_socket.Connected)
                {
                    return false;
                }
                byte[] buffer;
                if (message.Length < 1)
                {
                    buffer = BufferSegment.Empty;
                }
                else
                {
                    buffer = _encoding.GetBytes(message);
                }
                return Send(OpCode.Text, buffer, ok);
            }
        }

        public virtual bool Send(byte[] buffer, Action<bool> ok)
        {
            return Send(OpCode.Binary, buffer, ok);
        }

        public bool Send(OpCode opcode, byte[] buffer, Action<bool> ok)
        {
            return this.Send(opcode, buffer, buffer.Length, ok);
        }

        public bool Send(OpCode opcode, byte[] buffer, int length, Action<bool> ok)
        {
            return this.Send(opcode, buffer, 0, length, ok);
        }

        public virtual bool Send(OpCode opcode, byte[] buffer, int offset, int length, Action<bool> ok)
        {
            if (buffer == null || offset < 0 || length < 1)
            {
                return false;
            }
            if ((offset + length) > buffer.Length)
            {
                return false;
            }
            lock (this._syncobj)
            {
                if (!_socket.Connected)
                {
                    return false;
                }
                WebSocketFrame frame = new WebSocketFrame();
                frame.opcode = (byte)opcode;
                frame.fin = true;
                frame.rsv1 = false;
                frame.rsv2 = false;
                frame.rsv3 = false;
                frame.masked = _clientMode; // 客户端需要加密；服务器禁止加密（chrome）
                frame.payload_data = buffer;
                frame.payload_offset = offset;
                frame.payload_length = length;
                using (MemoryStream s = WebSocketFrame.Pack(frame))
                {
                    return SocketExtension.BeginSend(_socket, s.GetBuffer(), 0, (int)s.Position, (ar) =>
                    {
                        bool success = SocketExtension.EndSend(_socket, ar);
                        if (ok != null)
                        {
                            ok(success);
                        }
                    });
                }
            }
        }

        public virtual void Dispose()
        {
            this.CloseOrError(false);
        }
    }
}
