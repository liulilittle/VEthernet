namespace VEthernet.Net
{
    using System;
    using System.Collections.Concurrent;
    using System.Diagnostics;
    using System.Net;
    using System.Net.Sockets;
    using System.Threading;
#if NETCOREAPP
    using System.Runtime.CompilerServices;
#endif
#if !AARCH
    using SOCKET = global::VEthernet.Net.Auxiliary.AsyncSocket;
#else
    using SOCKET = global::System.Net.Sockets.Socket;
#endif
    using Timer = global::VEthernet.Threading.Timer;
    using SocketExtension = global::VEthernet.Net.Auxiliary.SocketExtension;

    public sealed class QoS : IDisposable
    {
        private sealed class ReceiveTransaction
        {
            public Socket socket;
            public byte[] buffer;
            public int offset;
            public int length;
            public Action<int> callback;
        }

        private sealed class ReceiveFromTransaction
        {
            public Socket socket;
            public byte[] buffer;
            public int offset;
            public int length;
            public EndPoint sourceEP;
            public Action<int, EndPoint> callback;
        }

        private sealed class AsyncSocketReceiveFromTransaction
        {
            public SOCKET socket;
            public byte[] buffer;
            public int offset;
            public int length;
            public Action<int, EndPoint> callback;
        }

        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private readonly ConcurrentDictionary<Socket, ReceiveTransaction> _recv_tcps
            = new ConcurrentDictionary<Socket, ReceiveTransaction>();
        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private readonly ConcurrentDictionary<Socket, ReceiveFromTransaction> _recv_iips
            = new ConcurrentDictionary<Socket, ReceiveFromTransaction>();
        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private readonly ConcurrentDictionary<SOCKET, AsyncSocketReceiveFromTransaction> _recv_aios
            = new ConcurrentDictionary<SOCKET, AsyncSocketReceiveFromTransaction>();

        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private readonly Stopwatch _per_seconds = new Stopwatch();
        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private int _current_traffic = 0;
        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private int _disposed = 0;
        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private Timer _work_timer = null;
        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private AsyncCallback _recv_pkg_ac = null;
        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private AsyncCallback _recvfrom_pkg_ac = null;

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public QoS(int bandwidth)
        {
            if (bandwidth < 0)
            {
                bandwidth = 0;
            }
            this.Bandwidth = bandwidth;
            if (bandwidth > 0)
            {
                this._per_seconds.Restart();
                this._work_timer = new Timer(1);
                this._work_timer.Tick += (__, _) => this.Update();
                this._work_timer.Start();
            }
            this._recv_pkg_ac = this.HandleReceiveCallback;
            this._recvfrom_pkg_ac = this.HandleReceiveFromCallback;
        }

        public int Bandwidth
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            get;
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            set;
        } // Byte

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        ~QoS() => this.Dispose();

        public bool IsDisposed
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            get => Interlocked.CompareExchange(ref this._disposed, 0, 0) != 0;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public void Dispose()
        {
            if (Interlocked.CompareExchange(ref this._disposed, 1, 0) != 0)
            {
                return;
            }
            using (Timer worktimer = Interlocked.Exchange(ref this._work_timer, null))
            {
                this._recv_pkg_ac = null;
                this._recvfrom_pkg_ac = null;
                if (worktimer != null)
                {
                    worktimer.Stop();
                }
                foreach (ReceiveTransaction r in this._recv_tcps.Values)
                {
                    r?.callback?.Invoke(-1);
                }
                this._recv_tcps.Clear();
                foreach (ReceiveFromTransaction r in this._recv_iips.Values)
                {
                    r?.callback?.Invoke(-1, r.sourceEP);
                }
                this._recv_iips.Clear();
                foreach (AsyncSocketReceiveFromTransaction r in this._recv_aios.Values)
                {
                    r?.callback?.Invoke(-1, null);
                }
                this._recv_aios.Clear();
            }
            GC.SuppressFinalize(this);
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        private void Update()
        {
            if (this.Bandwidth < 1)
            {
                return;
            }
            else
            {
                if (this._per_seconds.ElapsedMilliseconds < 1000)
                {
                    return;
                }
                this._per_seconds.Restart();
            }
            Interlocked.Exchange(ref this._current_traffic, 0);
            foreach (ReceiveTransaction r in this._recv_tcps.Values)
            {
                if (this._recv_tcps.TryRemove(r.socket, out ReceiveTransaction p) &&
                    !this.ReceiveImpl(r.socket, r.buffer, r.offset, r.length, r))
                {
                    r.callback(-1);
                }
            }
            foreach (ReceiveFromTransaction r in this._recv_iips.Values)
            {
                if (this._recv_iips.TryRemove(r.socket, out ReceiveFromTransaction p) &&
                    !this.ReceiveFromImpl(r.socket, r.buffer, r.offset, r.length, ref r.sourceEP, r))
                {
                    r.callback(-1, r.sourceEP);
                }
            }
            foreach (AsyncSocketReceiveFromTransaction r in this._recv_aios.Values)
            {
                bool success = this._recv_aios.TryRemove(r.socket, out AsyncSocketReceiveFromTransaction p);
                if (success)
                {
#if !AARCH
                    success = !r.socket.ReceiveFrom(r.buffer, r.offset, r.length, r.callback);
#else
                    success = !SocketExtension.ReceiveFrom(r.socket, r.buffer, r.offset, r.length, r.callback);
#endif
                    if (success)
                    {
                        r.callback(-1, null);
                    }
                }
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        private bool IsPeek()
        {
            if (this.Bandwidth < 1)
            {
                return false;
            }
            else
            {
                this.Update();
            }
            int traffic = Interlocked.CompareExchange(ref this._current_traffic, 0, 0);
            return traffic >= this.Bandwidth;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        private void HandleReceiveCallback(IAsyncResult ar)
        {
            this.Update();
            {
                ReceiveTransaction r = (ReceiveTransaction)ar.AsyncState;
                int count = SocketExtension.EndReceive(r.socket, ar);
                if (count > 0)
                {
                    Interlocked.Add(ref this._current_traffic, count);
                }
                r.callback(count);
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        private void HandleReceiveFromCallback(IAsyncResult ar)
        {
            this.Update();
            {
                ReceiveFromTransaction r = (ReceiveFromTransaction)ar.AsyncState;
                int count = SocketExtension.EndReceiveFrom(r.socket, ar, ref r.sourceEP);
                if (count > 0)
                {
                    Interlocked.Add(ref this._current_traffic, count);
                }
                r.callback(count, r.sourceEP);
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        private bool ReceiveImpl(Socket socket, byte[] buffer, int offset, int length, ReceiveTransaction receive)
        {
            if (SocketExtension.CleanedUp(socket))
            {
                return false;
            }
            SocketError error = SocketError.SocketError;
            try
            {
                AsyncCallback callback = this._recv_pkg_ac;
                if (callback == null)
                {
                    return false;
                }
                socket.BeginReceive(buffer, offset, length,
                    SocketFlags.None, out error, callback, receive);
            }
            catch { }
            return error == SocketError.Success || error == SocketError.IOPending;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        private bool ReceiveFromImpl(Socket socket, byte[] buffer, int offset, int length, ref EndPoint sourceEP, ReceiveFromTransaction receive)
        {
            if (SocketExtension.CleanedUp(socket))
            {
                return false;
            }
            try
            {
                AsyncCallback callback = this._recvfrom_pkg_ac;
                if (callback == null)
                {
                    return false;
                }
                socket.BeginReceiveFrom(buffer, offset, length,
                    SocketFlags.None, ref sourceEP, callback, receive);
                return true;
            }
            catch
            {
                return false;
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public bool Receive(Socket socket, byte[] buffer, int offset, int length, Action<int> callback)
        {
            if (this.IsDisposed)
            {
                return false;
            }
            if (socket == null || callback == null || SocketExtension.CleanedUp(socket))
            {
                return false;
            }
            if (this.Bandwidth < 1)
            {
                return this.ReceiveImpl(socket, buffer, offset, length, new ReceiveTransaction()
                {
                    socket = socket,
                    buffer = buffer,
                    offset = offset,
                    length = length,
                    callback = callback
                });
            }
            if (buffer == null && (offset != 0 || length != 0))
            {
                return false;
            }
            if (offset < 0 || length < 0 || (offset + length) > buffer.Length)
            {
                return false;
            }
            if (this._recv_tcps.TryGetValue(socket, out ReceiveTransaction p) && p != null)
            {
                return p.callback == callback;
            }
            ReceiveTransaction receive = new ReceiveTransaction()
            {
                socket = socket,
                buffer = buffer,
                offset = offset,
                length = length,
                callback = callback
            };
            if (this.IsPeek())
            {
                this._recv_tcps[socket] = receive;
                return true;
            }
            else
            {
                return this.ReceiveImpl(socket, buffer, offset, length, receive);
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public bool ReceiveFrom(Socket socket, byte[] buffer, int offset, int length, ref EndPoint sourceEP, Action<int, EndPoint> callback)
        {
            if (this.IsDisposed)
            {
                return false;
            }
            if (socket == null || callback == null || sourceEP == null || SocketExtension.CleanedUp(socket))
            {
                return false;
            }
            if (this.Bandwidth < 1)
            {
                return this.ReceiveFromImpl(socket, buffer, offset, length, ref sourceEP, new ReceiveFromTransaction()
                {
                    socket = socket,
                    buffer = buffer,
                    offset = offset,
                    length = length,
                    callback = callback,
                    sourceEP = sourceEP
                });
            }
            if (buffer == null && (offset != 0 || length != 0))
            {
                return false;
            }
            if (offset < 0 || (offset + length) > buffer.Length)
            {
                return false;
            }
            if (this._recv_iips.TryGetValue(socket, out ReceiveFromTransaction p) && p != null)
            {
                return p.callback == callback;
            }
            ReceiveFromTransaction receive = new ReceiveFromTransaction()
            {
                socket = socket,
                buffer = buffer,
                offset = offset,
                length = length,
                callback = callback,
                sourceEP = sourceEP
            };
            if (this.IsPeek())
            {
                this._recv_iips[socket] = receive;
                return true;
            }
            else
            {
                return this.ReceiveFromImpl(socket, buffer, offset, length, ref sourceEP, receive);
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public bool ReceiveFrom(SOCKET socket, byte[] buffer, int offset, int length, Action<int, EndPoint> callback)
        {
            if (this.IsDisposed)
            {
                return false;
            }
            if (socket == null || callback == null)
            {
                return false;
            }
#if !AARCH
            if (SocketExtension.CleanedUp(socket.Socket))
            {
                return false;
            }
#endif
            if (this.Bandwidth < 1)
            {
#if !AARCH
                return socket.ReceiveFrom(buffer, offset, length, callback);
#else
                return SocketExtension.ReceiveFrom(socket, buffer, offset, length, callback);
#endif
            }
            if (buffer == null && (offset != 0 || length != 0))
            {
                return false;
            }
            if (offset < 0 || (offset + length) > buffer.Length)
            {
                return false;
            }
            if (this._recv_aios.TryGetValue(socket, out AsyncSocketReceiveFromTransaction p) && p != null)
            {
                return p.callback == callback;
            }
            AsyncSocketReceiveFromTransaction receive = new AsyncSocketReceiveFromTransaction()
            {
                socket = socket,
                buffer = buffer,
                offset = offset,
                length = length,
                callback = callback,
            };
            if (this.IsPeek())
            {
                this._recv_aios[socket] = receive;
                return true;
            }
            else
            {
#if !AARCH
                return socket.ReceiveFrom(buffer, offset, length, callback);
#else
                return SocketExtension.ReceiveFrom(socket, buffer, offset, length, callback);
#endif
            }
        }
    }
}
