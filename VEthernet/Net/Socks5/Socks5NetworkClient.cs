namespace VEthernet.Net.Socks5
{
    using System;
    using System.IO;
    using System.Net;
    using System.Net.Sockets;
    using System.Text;
    using System.Threading;
    using VEthernet.Converter;
    using VEthernet.Net.Auxiliary;

    public unsafe class Socks5NetworkClient : IDisposable
    {
        private NetworkAddress _remoteEP; // 远程网路端点
        private Socket _session; // 代理客户端
        private ISocks5NetworkTunnel _tunnel; // 代理网路隧道
        private bool _udptype; // 协议类型
        private Socket _udpsockc = null;
        private int _disposed = 0;
        private readonly object _syncobj = new object();

        public event EventHandler Disposing;

        public Socks5NetworkClient(ISocks5Communication communication, Socket session)
        {
            this.Communication = communication ?? throw new ArgumentNullException(nameof(communication));
            this._session = session ?? throw new ArgumentNullException(nameof(session));
        }

        ~Socks5NetworkClient() => this.Dispose();

        protected virtual void OnDisposing(EventArgs e)
        {
            this.Disposing?.Invoke(this, e);
        }

        public virtual void Dispose()
        {
            bool disposing = false;
            ISocks5NetworkTunnel tunnel = null;
            if (Interlocked.CompareExchange(ref this._disposed, 1, 0) == 0)
            {
                disposing = true;
                SocketExtension.Closesocket(Interlocked.Exchange(ref this._session, null));
                SocketExtension.Closesocket(Interlocked.Exchange(ref this._udpsockc, null));
                tunnel = this._tunnel;
                this._tunnel = null;
                this.Communication = null;
            }
            if (tunnel != null)
            {
                tunnel.Dispose();
            }
            if (disposing)
            {
                this.OnDisposing(EventArgs.Empty);
            }
            this.Disposing = null;
            GC.SuppressFinalize(this);
        }

        public virtual void Run()
        {
            Thread handshake = new Thread(() =>
            {
                if (!this.Handshake())
                {
                    this.Dispose();
                }
                if (this.RequireValidate && !this.Authentication())
                {
                    this.Dispose();
                }
                if (!this.Requirement())
                {
                    this.Dispose();
                }
                else
                {
                    ISocks5NetworkTunnel tunnel = this.CreateTunnel();
                    if (tunnel == null)
                    {
                        this.Dispose();
                    }
                    else
                    {
                        tunnel.Disconnected += (sender, e) => this.Dispose();
                        this._tunnel = tunnel;
                        try
                        {
                            tunnel.Open();
                        }
                        catch
                        {
                            this.Dispose();
                        }
                    }
                }
            });
            handshake.IsBackground = true;
            handshake.Priority = ThreadPriority.Lowest;
            handshake.Start();
        }

        protected virtual NetworkAddress RemoteEP => this._remoteEP;

        public ISocks5Communication Communication { get; private set; }

        protected virtual ISocks5NetworkTunnel CreateTunnel() // 建立隧道
        {
            ISocks5NetworkTunnelFactory factory = this.SelectedFactory;
            return factory.CreateTunnel(this.Communication,
                this._session, this._udpsockc, this._remoteEP);
        }

        protected virtual ISocks5NetworkTunnelFactory SelectedFactory => this.Communication.Factory;

        public ProtocolType ProtocolType => this._udptype ? ProtocolType.Udp : ProtocolType.Tcp;

        public Socket GetSocket(ProtocolType protocolType)
        {
            if (protocolType == ProtocolType.Udp)
            {
                return this._udpsockc;
            }
            if (protocolType == ProtocolType.Tcp)
            {
                return this._session;
            }
            return default(Socket);
        }

        private bool Requirement()
        {
            try
            {
                // 协议版本号（1字节）+ 目的端连接方式（1字节）+ 保留位（1字节）+ 目的地址格式（1字节）+ 目的地址(可变长度）+ 目的端口（2字节）
                /*
                    +----+-----+-------+------+----------+----------+
    　　            |VER | CMD |　RSV　| ATYP | DST.ADDR | DST.PORT |
    　　            +----+-----+-------+------+----------+----------+
    　　            | 1　| 　1 | X'00' | 　1　| Variable |　　 2　　|
    　　            +----+-----+-------+------+----------+----------+
                */
                NetworkAddress remoteEP = null;
                byte[] buffer;
                byte cmd = 0x07; // 不支持的命令
                byte atype = 0; // 地址类型
                if (SocketExtension.Receive(this._session, 4, out buffer) && buffer != null) // 取前4字节
                {
                    this._udptype = (buffer[1] == 0x03);
                    atype = buffer[3];
                    switch (atype) // 判断地址类型
                    {
                        case 0x01: // IPv4
                            if (SocketExtension.Receive(this._session, 4, out buffer))
                            {
                                remoteEP = new NetworkAddress
                                {
                                    Host = buffer,
                                    Type = atype,
                                    Udp = this._udptype
                                };
                            }
                            break;
                        case 0x03: // 域名
                            if (SocketExtension.Receive(this._session, 1, out buffer) && SocketExtension.Receive(this._session, buffer[0], out buffer))
                            {
                                string hostname = Encoding.Default.GetString(buffer);
                                remoteEP = new NetworkAddress
                                {
                                    Host = hostname,
                                    Type = atype,
                                    Udp = this._udptype
                                };
                            }
                            break;
                        case 0x04: // IPv6
                            if (SocketExtension.Receive(this._session, 16, out buffer))
                            {
                                remoteEP = new NetworkAddress
                                {
                                    Host = buffer,
                                    Type = atype,
                                    Udp = this._udptype
                                };
                            }
                            break;
                        default:
                            cmd = 0x08; // 不支持的地址类型
                            break;
                    }
                }
                if (remoteEP != null && cmd == 0x07)
                {
                    if (SocketExtension.Receive(this._session, 2, out buffer)) // 取得端口号
                    {
                        cmd = 0x00;
                        fixed (byte* pinned = buffer)
                        {
                            byte* port = pinned;
                            remoteEP.Port = BitConverterr.ToUInt16(ref port);
                            this._remoteEP = remoteEP;
                        }
                    }
                }
                // +----+-----+-------+------+----------+----------+
                // |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
                // +----+-----+-------+------+----------+----------+
                // | 1  |  1  | X'00' |  1   | Variable |    2     |
                // +----+-----+-------+------+----------+----------+
                using (MemoryStream ms = new MemoryStream()) // 输出应答
                {
                    ms.WriteByte(0x05);
                    ms.WriteByte(cmd);
                    ms.WriteByte(0x00);
                    ms.WriteByte(0x01);
                    try
                    {
                        if (this._udptype)
                        {
                            this._udpsockc = new NetworkSocket(AddressFamily.InterNetworkV6, SocketType.Dgram, ProtocolType.Udp);
                            this._udpsockc.SetTypeOfService();
                            this._udpsockc.IPv6Only(false);
                            SocketExtension.SioUdpConnectReset(this._udpsockc);

                            IPEndPoint sessionEP = (IPEndPoint)this._session?.LocalEndPoint;
                            this._udpsockc?.Bind(new IPEndPoint(sessionEP.Address, 0));

                            IPEndPoint localEP = (IPEndPoint)this._udpsockc?.LocalEndPoint;
                            byte[] localIP = localEP.Address.GetAddressBytes();
                            ms.Write(localIP, 0, localIP.Length);

                            byte[] localPort = new byte[] { (byte)(localEP.Port >> 8), (byte)localEP.Port };
                            ms.Write(localPort, 0, localPort.Length);
                        }
                        else
                        {
                            IPEndPoint sessionEP = (IPEndPoint)this._session?.LocalEndPoint;
                            byte[] sessionIP = sessionEP?.Address.GetAddressBytes();
                            ms.Write(sessionIP, 0, sessionIP?.Length ?? 0);

                            IPEndPoint localEP = this.Communication.LocalEndPoint;
                            byte[] localPort = new byte[] { (byte)(localEP.Port >> 8), (byte)localEP.Port };
                            ms.Write(localPort, 0, localPort.Length);
                        }
                        SocketExtension.BeginSend(this._session, ms.GetBuffer(), 0, (int)ms.Position, (ar) => SocketExtension.EndSend(this._session, ar));
                    }
                    catch
                    {
                        return false;
                    }
                }
                return (this._remoteEP != null);
            }
            catch
            {
                return false;
            }
        }

        private bool RequireValidate
        {
            get
            {
                ISocks5Communication communication = this.Communication;
                if (communication == null)
                {
                    return false;
                }
                return !string.IsNullOrEmpty(this.Communication.UserName) || !string.IsNullOrEmpty(this.Communication.Password);
            }
        }

        private bool Handshake()
        {
            try
            {
                /*
                    +----+----------+----------+
                    | VER | NMETHODS | METHODS |
                    +----+----------+----------+
                    | 1 | 1 | 1 to 255 |
                    +----+----------+----------+
                 */
                byte method = 0xFF; // 命令不支持
                byte[] buffer;
                if (SocketExtension.Receive(this._session, 2, out buffer))
                {
                    if (buffer == null || (buffer[0] != 0x05 && buffer[1] > 0)) // 如果客户端包头不符合要求或者没有提供支持鉴权类型列表长度
                    {
                        return false;
                    }
                    if (!SocketExtension.Receive(this._session, buffer[1], out buffer)) // 获取客户端支持的鉴权类型列表
                    {
                        return false;
                    }
                    if (!this.RequireValidate)
                    {
                        method = 0x00;
                    }
                    else
                    {
                        for (int i = 0; i < buffer.Length; i++)
                        {
                            byte mode = buffer[i];
                            if (mode == 0x02) // 客户端支持用户名与密码验证
                            {
                                method = mode;
                            }
                        }
                    }
                }
                if (!SocketExtension.BeginSend(this._session, new byte[] { 0x05, method }, 0, 2, (ar) => SocketExtension.EndSend(this._session, ar)))
                {
                    return false;
                }
                return method != 0xFF;
            }
            catch
            {
                return false;
            }
        }

        private bool Authentication()
        {
            // 报文格式: 0x01 + 用户名长度（1字节）+ 用户名（可变长度） + 口令长度（1字节） + 口令（可变长度）
            byte error = 0xFF;
            byte[] buffer;
            if (SocketExtension.Receive(this._session, 2, out buffer))
            {
                if (buffer[1] == 0x00) // 用户名为空
                {
                    if (string.IsNullOrEmpty(this.Communication.UserName))
                    {
                        error = 0x00;  //用户名为空
                    }
                }
                else if (SocketExtension.Receive(this._session, buffer[1], out buffer))
                {
                    string username = Encoding.ASCII.GetString(buffer);
                    if (!string.IsNullOrEmpty(this.Communication.UserName))
                    {
                        error = (byte)(username.Equals(this.Communication.UserName) ? 0x00 : 0xFF);
                    }
                }
                if (error == 0x00)
                {
                    error = 0xFF;
                    if (SocketExtension.Receive(this._session, 1, out buffer)) // 判断密码
                    {
                        if (buffer[0] == 0x00)
                        {
                            if (!string.IsNullOrEmpty(this.Communication.Password))
                            {
                                error = 0x00; // 密码为空
                            }
                        }
                        else if (SocketExtension.Receive(this._session, buffer[0], out buffer))
                        {
                            string password = Encoding.ASCII.GetString(buffer);
                            if (!string.IsNullOrEmpty(this.Communication.Password))
                            {
                                error = (byte)(password.Equals(this.Communication.Password) ? 0x00 : 0xFF);
                            }
                        }
                    }
                }
            }
            SocketExtension.BeginSend(this._session, new byte[] { 0x01, error }, 0, 2, (ar) => SocketExtension.EndSend(this._session, ar)); // 输出应答
            return (error == 0x00);
        }
    }
}
