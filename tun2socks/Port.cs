namespace tun2socks
{
    using System;
    using System.Collections;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.IO;
    using System.Net;
    using System.Net.Sockets;
    using System.Security;
    using System.Threading;
    using VEthernet.Core;
    using VEthernet.Coroutines;
    using VEthernet.Net.Auxiliary;
    using VEthernet.Net.IP;
    using VEthernet.Net.Udp;
    using VEthernet.Utilits;

    public class Port : IDisposable
    {
        private readonly Stopwatch _agingsw = new Stopwatch();
        private IPEndPoint _localEP = null;
        private Datagram _datagram = null;
        private int _disposed = 0;
        private int _open = 0;
        private int _onlydnsport = 0;
        private Socket _server = null;
        private Socket _socket = null;
        private byte[] _buffer = null;
        private byte[] _monitorbuf = null;
        private IPEndPoint _sendtoEP = null;
        private readonly IList<UdpFrame> _sendqueues = new List<UdpFrame>();

        public const int MaxAgingTime = 150000;
        public const int DnsAgingTime = 3000;

        [SecurityCritical]
        [SecuritySafeCritical]
        public Port(Datagram datagram, IPEndPoint localEP)
        {
            this._datagram = datagram ?? throw new ArgumentNullException(nameof(datagram));
            this._localEP = localEP ?? throw new ArgumentNullException(nameof(localEP));
            this._agingsw.Start();
        }

        ~Port() => this.Dispose();

        public virtual bool IsDisposed => Interlocked.CompareExchange(ref this._disposed, 0, 0) != 0;

        public virtual bool IsPortAging
        {
            get
            {
                if (this.IsDisposed)
                {
                    return true;
                }
                long ticks = this._agingsw.ElapsedMilliseconds;
                long maxAgingTime = MaxAgingTime;
                if (Interlocked.CompareExchange(ref this._onlydnsport, 0, 0) == 1)
                {
                    maxAgingTime = DnsAgingTime;
                }
                return ticks >= maxAgingTime;
            }
        }

        public virtual bool Listen()
        {
            bool ok = this.OpenTunnelAsync();
            if (!ok)
            {
                this.Dispose();
            }
            return ok;
        }

        public virtual bool Input(UdpFrame packet)
        {
            if (packet == null || this.IsDisposed)
            {
                return false;
            }
            this._agingsw.Restart();
            try
            {
                lock (this._sendqueues)
                {
                    if (Interlocked.CompareExchange(ref this._open, 0, 0) == 0)
                    {
                        this._sendqueues.Add(packet.Depth());
                        return true;
                    }
                }
                return this.SendToServer(packet.Payload, packet.Destination);
            }
            finally
            {
                IPEndPoint destinationEP = packet.Destination;
                if (destinationEP.Port == Dnss.Port)
                {
                    Interlocked.CompareExchange(ref this._onlydnsport, 1, 0);
                }
                else
                {
                    Interlocked.Exchange(ref this._onlydnsport, 2);
                }
            }
        }

        public virtual void Dispose()
        {
            if (Interlocked.CompareExchange(ref this._disposed, 1, 0) == 0)
            {
                using (Socket socket = Interlocked.Exchange(ref this._server, null))
                {
                    if (socket != null)
                    {
                        SocketExtension.Closesocket(socket);
                    }
                }
                using (Socket socket = Interlocked.Exchange(ref this._socket, null))
                {
                    if (socket != null)
                    {
                        SocketExtension.Closesocket(socket);
                    }
                }
                lock (this._sendqueues)
                {
                    this._sendqueues.Clear();
                    Interlocked.Exchange(ref this._open, 0);
                }
                Interlocked.Exchange(ref this._sendtoEP, null);
                Interlocked.Exchange(ref this._buffer, null);
                Interlocked.Exchange(ref this._monitorbuf, null);
                Interlocked.Exchange(ref this._localEP, null);
                Interlocked.Exchange(ref this._datagram, null);
            }
            GC.SuppressFinalize(this);
        }

        private bool OpenTunnelAsync()
        {
            if (this.IsDisposed)
            {
                return false;
            }
            Datagram datagram = this._datagram;
            if (datagram == null)
            {
                return false;
            }
            IPEndPoint serverEP = datagram.Ethernet.Server;
            if (serverEP == null)
            {
                return false;
            }
            try
            {
                this._buffer = new byte[ushort.MaxValue];
                this._monitorbuf = new byte[1];
                this._server = new Socket(serverEP.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                this._server.BeginConnect(serverEP, (ar) =>
                {
                    bool closing = true;
                    try
                    {
                        Socket socket = this._server;
                        if (socket != null)
                        {
                            socket.EndConnect(ar);
                            if (socket.Connected)
                            {
                                closing = false;
                                YieldContext.Run(this.HandshakeTunnelAsync);
                            }
                        }
                    }
                    catch (Exception) { }
                    if (closing)
                    {
                        this.Dispose();
                    }
                }, null);
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        private IEnumerable HandshakeTunnelAsync(YieldContext y)
        {
            Socket socket = this._server;
            bool success = false;
            do
            {
                if (this.IsDisposed)
                {
                    break;
                }

                YieldContext.Integer outlen = new YieldContext.Integer();
                byte[] messages = this._buffer;
                messages[0] = 0x05;    // VER 
                messages[1] = 0x01;    // NMETHODS
                messages[2] = 0x00;    // METHODS 

                yield return y.Send(socket, messages, 0, 3, outlen);
                if (outlen < 0)
                {
                    break;
                }

                yield return y.Receive(socket, messages, 0, 2, outlen);
                if (outlen <= 0 || messages[1] != 0x00)
                {
                    break;
                }
                IPEndPoint bindEP = default(IPEndPoint);
                try
                {
                    IPEndPoint interfaceEP = (IPEndPoint)socket.LocalEndPoint;
                    {
                        bindEP = new IPEndPoint(interfaceEP.Address, 0);
                    }
                    this._socket = new Socket(interfaceEP.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
                    this._socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                    this._socket.Bind(bindEP);
                    bindEP = (IPEndPoint)this._socket.LocalEndPoint;
                }
                catch (Exception)
                {
                    break;
                }
                using (MemoryStream ms = new MemoryStream(messages))
                {
                    using (BinaryWriter bw = new BinaryWriter(ms))
                    {
                        bw.Write((byte)0x05); // VAR 
                        bw.Write((byte)0x03); // CMD 
                        bw.Write((byte)0x00); // RSV 
                        bw.Write((byte)0x01); // ATYPE(IPv4) 
                        bw.Write(0);
                        bw.Write(CheckSum.htons((ushort)bindEP.Port));

                        yield return y.Send(socket, messages, 0, (int)ms.Position, outlen);
                        if (outlen < 0)
                        {
                            break;
                        }
                    }
                }

                yield return y.Receive(socket, messages, 0, 10, outlen);
                if (outlen <= 0 || messages[1] != 0x00)
                {
                    break;
                }

                IPAddress proxyAddress = this._datagram?.Ethernet?.Server?.Address;
                if (proxyAddress != null)
                {
                    int proxyPort = (messages[8] << 8) | (messages[9] & 0xff);
                    success = true;
                    this._sendtoEP = new IPEndPoint(proxyAddress, proxyPort);
                }
            } while (false);
            if (!success)
            {
                this.Dispose();
            }
            else
            {
                this.OnOpen(EventArgs.Empty);
            }
        }

        private void PullWatchOnlineCheck(IAsyncResult ar)
        {
            if (this.IsDisposed)
            {
                return;
            }
            byte[] buffer = this._monitorbuf;
            if (buffer == null)
            {
                return;
            }
            bool success = false;
            if (ar == null)
            {
                success = SocketExtension.BeginReceive(this._server, buffer, 0, buffer.Length, this.PullWatchOnlineCheck);
            }
            else
            {
                success = SocketExtension.EndReceive(this._server, ar) > 0;
                if (success)
                {
                    this.PullWatchOnlineCheck(null);
                }
            }
            if (!success)
            {
                this.Dispose();
            }
        }

        private void ProcessReceiveFrom(IAsyncResult ar)
        {
            if (this.IsDisposed)
            {
                return;
            }
            byte[] buffer = this._buffer;
            if (buffer == null)
            {
                return;
            }
            Socket socket = this._socket;
            if (socket == null)
            {
                return;
            }
            EndPoint listenEP = null;
            try
            {
                listenEP = socket.LocalEndPoint;
            }
            catch (Exception) { }
            if (listenEP == null)
            {
                return;
            }
            if (ar == null)
            {
                SocketExtension.BeginReceiveFrom(socket, buffer, 0, buffer.Length, ref listenEP, this.ProcessReceiveFrom);
            }
            else
            {
                int count = SocketExtension.EndReceiveFrom(socket, ar, ref listenEP);
                if (count > 0)
                {
                    IPEndPoint remoteEP = listenEP as IPEndPoint;
                    if (remoteEP != null && this.OnWanInput(buffer, count, remoteEP))
                    {
                        this._agingsw.Restart();
                    }
                }
                this.ProcessReceiveFrom(null);
            }
        }

        protected unsafe virtual bool OnWanInput(byte[] buffer, int length, IPEndPoint remoteEP)
        {
            if (IPFrame.Equals(remoteEP, this._sendtoEP)) // 从服务器上收到报文
            {
                int offset;
                NetworkAddress address = Socks5Extension.ResolveEP(buffer, &offset, length);
                if (address == null || offset < 0 || offset >= length)
                {
                    return false;
                }
                IPEndPoint sourceEP = address.EndPoint;
                if (sourceEP == null)
                {
                    return false;
                }
                return this.SendToLocal(new BufferSegment(buffer, offset, length), sourceEP);
            }
            else // 收到被穿透报文不知道是什么数据
            {
                return this.SendToLocal(new BufferSegment(buffer, 0, length), remoteEP);
            }
        }

        protected virtual bool SendToLocal(BufferSegment messages, IPEndPoint sourceEP)
        {
            Datagram datagram = this._datagram;
            if (datagram == null)
            {
                return false;
            }
            IPEndPoint localEP = this._localEP;
            if (localEP == null)
            {
                return false;
            }
            IPFrame packet = UdpLayer.ToIPFrame(new UdpFrame(sourceEP, localEP, messages));
            return datagram.Ethernet.Tap.Output(IPv4Layer.ToArray(packet));
        }

        protected virtual bool SendToServer(BufferSegment messages, IPEndPoint destinationEP)
        {
            Socket socket = this._socket;
            if (socket == null)
            {
                return false;
            }
            IPEndPoint sendtoEP = this._sendtoEP;
            if (sendtoEP == null)
            {
                return false;
            }
            IPEndPoint localEP = this._localEP;
            if (localEP == null)
            {
                return false;
            }
            if (!Socks5Extension.SendTo(socket, messages.Buffer, messages.Offset, messages.Length, sendtoEP, destinationEP))
            {
                return false;
            }
            Console.WriteLine($"[{DateTime.Now}][UDP]{localEP.ToString().PadRight(16)} sendto {destinationEP}");
            return true;
        }

        protected virtual void OnOpen(EventArgs e)
        {
            lock (this._sendqueues)
            {
                foreach (UdpFrame frame in this._sendqueues)
                {
                    this.SendToServer(frame.Payload, frame.Destination);
                }
                this._sendqueues.Clear();
                Interlocked.CompareExchange(ref this._open, 1, 0);
            }
            this.ProcessReceiveFrom(null);
            this.PullWatchOnlineCheck(null);
        }
    }
}
