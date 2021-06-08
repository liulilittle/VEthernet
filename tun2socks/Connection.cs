namespace tun2socks
{
    using System;
    using System.Collections;
    using System.IO;
    using System.Net;
    using System.Net.Sockets;
    using System.Threading;
    using VEthernet.Core;
    using VEthernet.Coroutines;
    using VEthernet.Net;
    using VEthernet.Net.Auxiliary;
    using VEthernet.Net.Tun;

    public class Connection : TapTap2Socket.TapTcpClient
    {
        private byte[] _buffer = null;
        private Socket _server = null;

        public Connection(Socks5Ethernet ethernet, IPEndPoint localEP, IPEndPoint remoteEP) : base(ethernet, localEP, remoteEP)
        {

        }

        public override void Dispose()
        {
            base.Dispose();
            this.CloseMany();
            GC.SuppressFinalize(this);
        }

        public override void BeginAccept()
        {
            Console.WriteLine($"[{DateTime.Now}][TCP]{this.SourceEndPoint.ToString().PadRight(16)} syn    {this.RemoteEndPoint}");
            base.BeginAccept();
        }

        public override void EndAccept()
        {
            bool success = this.OpenTunnelAsync();
            if (!success)
            {
                this.Dispose();
            }
        }

        protected virtual void OnOpen(EventArgs e)
        {
            Console.WriteLine($"[{DateTime.Now}][TCP]{this.SourceEndPoint.ToString().PadRight(16)} open   {this.RemoteEndPoint}");
            base.EndAccept();
            this.PullTunnelReceive(null);
        }

        protected override void OnMessage(BufferSegment e)
        {
            if (!SocketExtension.BeginSend(this._server, e.Buffer, e.Offset, e.Length, (ar) =>
            {
                bool ok = SocketExtension.EndSend(this._server, ar);
                if (ok)
                {
                    ok = this.PullListener();
                }
                if (!ok)
                {
                    this.Dispose();
                }
            }))
            {
                this.Dispose();
            }
        }

        protected virtual bool OnTunnelInput(byte[] buffer, int offset, int length)
        {
            BufferSegment messages = new BufferSegment(buffer, offset, length);
            return this.Send(messages, (ok) =>
            {
                if (!ok)
                {
                    this.Dispose();
                    return;
                }
                this.PullTunnelReceive(null);
            });
        }

        private void PullTunnelReceive(IAsyncResult ar)
        {
            if (this.IsAbort)
            {
                return;
            }
            byte[] buffer = this._buffer;
            if (buffer == null)
            {
                return;
            }
            bool success = false;
            if (ar == null)
            {
                success = SocketExtension.BeginReceive(this._server, buffer, 0, buffer.Length, this.PullTunnelReceive);
            }
            else
            {
                int count = SocketExtension.EndReceive(this._server, ar);
                if (count > 0)
                {
                    success = this.OnTunnelInput(buffer, 0, count);
                }
            }
            if (!success)
            {
                this.Dispose();
            }
        }

        private bool OpenTunnelAsync()
        {
            if (this.IsAbort)
            {
                return false;
            }
            Socks5Ethernet ethernet = (Socks5Ethernet)this.Tap;
            try
            {
                this._buffer = new byte[Layer3Netif.MSS];
                this._server = new Socket(ethernet.Server.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                this._server.BeginConnect(ethernet.Server, (ar) =>
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
                if (this.IsAbort)
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

                IPEndPoint destinationEP = this.RemoteEndPoint;
                using (MemoryStream ms = new MemoryStream(messages))
                {
                    using (BinaryWriter bw = new BinaryWriter(ms))
                    {
                        bw.Write((byte)0x05); // VAR 
                        bw.Write((byte)0x01); // CMD 
                        bw.Write((byte)0x00); // RSV 
                        bw.Write((byte)0x01); // ATYPE(IPv4) 
                        bw.Write(destinationEP.Address.GetAddressBytes());
                        bw.Write(CheckSum.htons((ushort)destinationEP.Port));

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

                success = true;
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

        private void CloseMany()
        {
            Socket socket = Interlocked.Exchange(ref this._server, null);
            if (socket != null)
            {
                SocketExtension.Closesocket(socket);
            }
            Interlocked.Exchange(ref this._buffer, null);
        }
    }
}
