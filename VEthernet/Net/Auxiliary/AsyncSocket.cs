#if !AARCH
namespace VEthernet.Net.Auxiliary
{
    using System;
    using System.Collections.Concurrent;
    using System.Diagnostics;
    using System.Net;
    using System.Net.Sockets;
#if NETCOREAPP
    using System.Runtime.CompilerServices;
#endif
    using System.Runtime.InteropServices;
    using System.Threading;
    using VEthernet.Net.IP;

    public unsafe sealed class AsyncSocket : IDisposable
    {
#if (WIN32 || WIN64)
        private const string DLLNAME = "libasio.dll";
#else
        private const string DLLNAME = "libasio.so";
#endif

        [DllImport(DLLNAME, EntryPoint = "libasio_createsocket", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        private static extern IntPtr libasio_createsocket(IntPtr context_, int sockfd_, bool v4_or_v6_);

        [DllImport(DLLNAME, EntryPoint = "libasio_closesocket", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        private static extern void libasio_closesocket(IntPtr socket_);

        [DllImport(DLLNAME, EntryPoint = "libasio_sendto", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        private static extern bool libasio_sendto(IntPtr socket_, long key_, void* buf_, int size_,
            libasio_endpoint* endpoint_, [MarshalAs(UnmanagedType.FunctionPtr)] libasio_sendto_callback callback_);

        [DllImport(DLLNAME, EntryPoint = "libasio_sendto2", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        private static extern int libasio_sendto2(IntPtr socket_, void* buf_, int size_, libasio_endpoint* endpoint_);

        [DllImport(DLLNAME, EntryPoint = "libasio_recvfrom", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        private static extern bool libasio_recvfrom(IntPtr socket_, long key_, void* buf_, int size_,
            [MarshalAs(UnmanagedType.FunctionPtr)] libasio_recvfrom_callback callback_);

        [DllImport(DLLNAME, EntryPoint = "libasio_recvfrom2", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        private static extern int libasio_recvfrom2(IntPtr socket_, void* buf_, int size_, libasio_endpoint* endpoint_);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate void libasio_sendto_callback(IntPtr socket_, long key_, int length_);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate void libasio_recvfrom_callback(IntPtr socket_, long key_, int length_, libasio_endpoint* remoteEP_);

        [StructLayout(LayoutKind.Explicit, Pack = 1)]
        private struct libasio_endpoint
        {
            [StructLayout(LayoutKind.Sequential, Pack = 1)]
            public struct in4
            {
                public uint address_;
                public int port_;
            }
            [StructLayout(LayoutKind.Sequential, Pack = 1)]
            public struct in6
            {
                public long address_1_;
                public long address_2_;
                public int port_;
            }

            [FieldOffset(0)]
            public uint v4_or_v6_;

            [FieldOffset(4)]
            public in4 in4_;

            [FieldOffset(4)]
            public in6 in6_;

            [FieldOffset(0)]
            public long data_1_;
            [FieldOffset(8)]
            public long data_2_;
            [FieldOffset(16)]
            public long data_3_;
        };

        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private readonly object _synobj = new object();
        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private readonly Socket _socket = null;
        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private readonly AsyncContext _context = null;
        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private bool _disposed = false;
        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private IntPtr _handle = IntPtr.Zero;
        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private long _mapkey = 0;
        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private AddressFamily _af = AddressFamily.InterNetwork;
        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private static readonly libasio_recvfrom_callback _recvfrom_callback = (socket_, key_, length_, remoteEP_) =>
        {
            _recvfrom_callbacks.TryGetValue(socket_, out ConcurrentDictionary<long, Action<int, EndPoint>> callbacks);
            if (callbacks == null)
            {
                return;
            }
            callbacks.TryRemove(key_, out Action<int, EndPoint> callback_);
            if (callback_ == null)
            {
                return;
            }
            callback_(length_, ToEndPoint(remoteEP_));
        };
        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private static readonly ConcurrentDictionary<IntPtr, ConcurrentDictionary<long, Action<int, EndPoint>>> _recvfrom_callbacks =
            new ConcurrentDictionary<IntPtr, ConcurrentDictionary<long, Action<int, EndPoint>>>();
        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private static readonly libasio_sendto_callback _sendto_callback = (socket_, key_, length_) =>
        {
            _sendto_callbacks.TryGetValue(socket_, out ConcurrentDictionary<long, Action<int>> callbacks);
            if (callbacks == null)
            {
                return;
            }
            callbacks.TryRemove(key_, out Action<int> callback_);
            if (callback_ == null)
            {
                return;
            }
            callback_(length_);
        };
        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private static readonly ConcurrentDictionary<IntPtr, ConcurrentDictionary<long, Action<int>>> _sendto_callbacks =
            new ConcurrentDictionary<IntPtr, ConcurrentDictionary<long, Action<int>>>();

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        static AsyncSocket()
        {
            GCHandle.Alloc(_sendto_callback);
            GCHandle.Alloc(_recvfrom_callback);
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        private ConcurrentDictionary<long, Action<int, EndPoint>> GetAllReceiveFromCallback()
        {
            lock (this._synobj)
            {
                if (this._disposed)
                {
                    return null;
                }
                lock (_recvfrom_callbacks)
                {
                    _recvfrom_callbacks.TryGetValue(this._handle, out ConcurrentDictionary<long, Action<int, EndPoint>> d);
                    if (d == null)
                    {
                        d = new ConcurrentDictionary<long, Action<int, EndPoint>>();
                        if (!_recvfrom_callbacks.TryAdd(this._handle, d))
                        {
                            d = null;
                        }
                    }
                    return d;
                }
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        private long BindReceiveFromCallback(Action<int, EndPoint> callback)
        {
            ConcurrentDictionary<long, Action<int, EndPoint>> callbacks = this.GetAllReceiveFromCallback();
            if (callbacks == null)
            {
                return 0;
            }
            for (; ; )
            {
                long key_ = Interlocked.Increment(ref this._mapkey);
                if (key_ == 0)
                {
                    continue;
                }
                if (callbacks.TryAdd(key_, callback))
                {
                    return key_;
                }
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        private ConcurrentDictionary<long, Action<int>> GetAllSendToCallback()
        {
            lock (this._synobj)
            {
                if (this._disposed)
                {
                    return null;
                }
                lock (_sendto_callbacks)
                {
                    _sendto_callbacks.TryGetValue(this._handle, out ConcurrentDictionary<long, Action<int>> d);
                    if (d == null)
                    {
                        d = new ConcurrentDictionary<long, Action<int>>();
                        if (!_sendto_callbacks.TryAdd(this._handle, d))
                        {
                            d = null;
                        }
                    }
                    return d;
                }
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        private long BindSendToCallback(Action<int> callback)
        {
            ConcurrentDictionary<long, Action<int>> callbacks = this.GetAllSendToCallback();
            if (callbacks == null)
            {
                return 0;
            }
            long key_ = 0;
            do
            {
                while (key_ == 0)
                {
                    key_ = Interlocked.Increment(ref this._mapkey);
                }
            } while (!callbacks.TryAdd(key_, callback));
            return key_;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        internal AsyncSocket(AsyncContext context, Socket socket)
        {
            this._af = socket.AddressFamily;
            IntPtr handle = libasio_createsocket(context.Handle, socket.Handle.ToInt32(), this.AddressFamily == AddressFamily.InterNetwork);
            if (handle == IntPtr.Zero)
            {
                throw new InvalidOperationException("Unable to attach to socket file descriptor handle object.");
            }
            this._handle = handle;
            this._socket = socket;
            this._context = context;
        }

        public AddressFamily AddressFamily
        {
#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            get => this._af;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        ~AsyncSocket() => this.Dispose();

        public IntPtr Handle
        {
#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            get => Interlocked.CompareExchange(ref this._handle, IntPtr.Zero, IntPtr.Zero);
        }

        public Socket Socket
        {
#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            get => this._socket;
        }

        public AsyncContext Context
        {
#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            get => this._context;
        }

        public object Tag
        {
#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            get;
#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            set;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        private void ToEndPoint(libasio_endpoint* dst, IPEndPoint src)
        {
            if (this._af == AddressFamily.InterNetworkV6)
            {
                src = IPFrame.V4ToV6(src);
            }
            if (src.AddressFamily == AddressFamily.InterNetwork)
            {
                dst->v4_or_v6_ = 1;
                dst->in4_.port_ = src.Port;
                fixed (byte* pb = src.Address.GetAddressBytes())
                {
                    dst->in4_.address_ = *(uint*)pb;
                }
            }
            else
            {
                dst->v4_or_v6_ = 0;
                dst->in6_.port_ = src.Port;
                fixed (byte* pb = src.Address.GetAddressBytes())
                {
                    long* pl = (long*)pb;
                    dst->in6_.address_1_ = pl[0];
                    dst->in6_.address_2_ = pl[1];
                }
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        private static IPEndPoint ToEndPoint(libasio_endpoint* p)
        {
            if (p == null)
            {
                return null;
            }
            if (p->v4_or_v6_ != 0)
            {
                return new IPEndPoint(new IPAddress(p->in4_.address_), p->in4_.port_);
            }
            byte[] address_bytes = new byte[16];
            fixed (byte* paddr_bytes = address_bytes)
            {
                long* paddr_i64 = (long*)paddr_bytes;
                paddr_i64[0] = p->in6_.address_1_;
                paddr_i64[1] = p->in6_.address_2_;
            }
            IPEndPoint localEP = new IPEndPoint(new IPAddress(address_bytes), p->in6_.port_);
            return IPFrame.V6ToV4(localEP) ?? localEP;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public int SendTo(byte[] buffer, int offset, int length, EndPoint destinationEP)
        {
            if (this._disposed ||
                buffer == null ||
                offset < 0 ||
                length < 1 ||
                (offset + length) > buffer.Length ||
                SocketExtension.CleanedUp(this._socket))
            {
                return -1;
            }
            IPEndPoint serverEP = destinationEP as IPEndPoint;
            if (serverEP == null)
            {
                return -1;
            }
            libasio_endpoint* localEP = stackalloc libasio_endpoint[1];
            ToEndPoint(localEP, serverEP);
            fixed (byte* p = buffer)
            {
                return libasio_sendto2(this.Handle, p + offset, length, localEP);
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public bool SendTo(byte[] buffer, int offset, int length, EndPoint destinationEP, Action<int> callback)
        {
            if (buffer == null ||
                offset < 0 ||
                length < 1 ||
                callback == null ||
                (offset + length) > buffer.Length ||
                SocketExtension.CleanedUp(this._socket))
            {
                return false;
            }
            IPEndPoint serverEP = destinationEP as IPEndPoint;
            if (serverEP == null)
            {
                return false;
            }
            libasio_endpoint* localEP = stackalloc libasio_endpoint[1];
            ToEndPoint(localEP, serverEP);
            fixed (byte* p = buffer)
            {
                lock (this._synobj)
                {
                    if (this._disposed)
                    {
                        return false;
                    }
                    long key_ = this.BindSendToCallback(callback);
                    if (key_ == 0)
                    {
                        return false;
                    }
                    return libasio_sendto(this.Handle, key_, p + offset, length, localEP, _sendto_callback);
                }
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public bool ReceiveFrom(byte[] buffer, int offset, int length, Action<int, EndPoint> callback)
        {
            if (buffer == null ||
                callback == null ||
                offset < 0 ||
                length < 1 ||
                (offset + length) > buffer.Length ||
                SocketExtension.CleanedUp(this._socket))
            {
                return false;
            }
            fixed (byte* p = buffer)
            {
                lock (this._synobj)
                {
                    if (this._disposed)
                    {
                        return false;
                    }
                    long key_ = this.BindReceiveFromCallback(callback);
                    if (key_ == 0)
                    {
                        return false;
                    }
                    return libasio_recvfrom(this.Handle, key_, p + offset, length, _recvfrom_callback);
                }
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public int ReceiveFrom(byte[] buffer, int offset, int length, out EndPoint sourceEP)
        {
            sourceEP = null;
            if (this._disposed ||
                buffer == null ||
                offset < 0 ||
                length < 1 ||
                (offset + length) > buffer.Length ||
                SocketExtension.CleanedUp(this._socket))
            {
                return -1;
            }
            fixed (byte* p = buffer)
            {
                libasio_endpoint* localEP = stackalloc libasio_endpoint[1];
                int by = libasio_recvfrom2(this.Handle, p + offset, length, localEP);
                if (by > -1)
                {
                    sourceEP = ToEndPoint(localEP);
                }
                return by;
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public void Close() => this.Dispose();

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public void Dispose()
        {
            lock (this._synobj)
            {
                if (!this._disposed)
                {
                    this._disposed = true;
                    lock (this._synobj)
                    {
                        SocketExtension.Closesocket(this._socket);
                        libasio_closesocket(this._handle);
                    }
                }
            }
            _sendto_callbacks.TryRemove(this._handle, out ConcurrentDictionary<long, Action<int>> _);
            _recvfrom_callbacks.TryRemove(this._handle, out ConcurrentDictionary<long, Action<int, EndPoint>> __);
            GC.SuppressFinalize(this);
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public void Post(Action<object> callback, object state) => this._context.Post(callback, state);

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static AsyncSocket CreateSocket(Socket socket)
        {
            AsyncContext context = AsyncContext.GetContext();
            if (context == null)
            {
                throw new InvalidOperationException(nameof(context));
            }
            return context.CreateSocket(socket);
        }
    }
}
#endif