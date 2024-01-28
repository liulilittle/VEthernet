#if !AARCH
namespace VEthernet.Net.Auxiliary
{
    using System;
    using System.Collections.Concurrent;
    using System.Diagnostics;
    using System.Net.Sockets;
    using System.Threading;
#if NETCOREAPP
    using System.Runtime.CompilerServices;
#endif
    using System.Runtime.InteropServices;

    public unsafe sealed class AsyncContext : IDisposable
    {
#if (WIN32 || WIN64)
        private const string DLLNAME = "libasio.dll";
#else
        private const string DLLNAME = "libasio.so";
#endif

        [DllImport(DLLNAME, EntryPoint = "libasio_newcontext", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        private static extern IntPtr libasio_new_context();

        [DllImport(DLLNAME, EntryPoint = "libasio_closecontext", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        private static extern void libasio_closecontext(IntPtr context_);

        [DllImport(DLLNAME, EntryPoint = "libasio_postcontext", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        private static extern bool libasio_postcontext(IntPtr context_, long key_, [MarshalAs(UnmanagedType.FunctionPtr)] libasio_post_callback callback_);

        [DllImport(DLLNAME, EntryPoint = "libasio_opendelay", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        private static extern bool libasio_opendelay(IntPtr context_, long key_, int timeout_, [MarshalAs(UnmanagedType.FunctionPtr)] libasio_delay_callback callback_);

        [DllImport(DLLNAME, EntryPoint = "libasio_stopdelay", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        private static extern bool libasio_stopdelay(long key_);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate void libasio_post_callback(IntPtr context_, long key_);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate void libasio_delay_callback(IntPtr context_, long key_, int err_);

        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private IntPtr _handle = IntPtr.Zero;
        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private bool _disposed = false;
        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private long _mapkey = 0;
        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private readonly object _synobj = new object();
        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private readonly byte[] _buffer = new byte[ushort.MaxValue];
        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private GCHandle _buffer_gc = default(GCHandle);

        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private static readonly AsyncScheduler _scheduler = new AsyncScheduler(NetIo.Concurrent);
        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private static readonly libasio_post_callback _postcallback = (context_, key_) =>
        {
            _callbacks.TryGetValue(context_, out ConcurrentDictionary<long, IOCompletionCallback> callbacks);
            if (callbacks == null)
            {
                return;
            }
            callbacks.TryRemove(key_, out IOCompletionCallback callback_);
            if (callback_ != null)
            {
                callback_.post_callback_(callback_.state_);
            }
        };
        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private static readonly libasio_delay_callback _delaycallback = (context_, key_, err_) =>
        {
            _callbacks.TryGetValue(context_, out ConcurrentDictionary<long, IOCompletionCallback> callbacks);
            if (callbacks == null)
            {
                return;
            }
            callbacks.TryRemove(key_, out IOCompletionCallback callback_);
            if (callback_ != null)
            {
                callback_.delay_context_.Dispose();
                callback_.delay_callback_(err_);
            }
        };
        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private static readonly ConcurrentDictionary<IntPtr, ConcurrentDictionary<long, IOCompletionCallback>> _callbacks =
            new ConcurrentDictionary<IntPtr, ConcurrentDictionary<long, IOCompletionCallback>>();

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        static AsyncContext()
        {
            GCHandle.Alloc(_postcallback);
            GCHandle.Alloc(_delaycallback);
        }

        private sealed class IOCompletionCallback
        {
            public DelayContext delay_context_;
            public object state_;
            public Action<object> post_callback_;
            public Action<int> delay_callback_;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        private ConcurrentDictionary<long, IOCompletionCallback> GetAllCallback()
        {
            lock (this._synobj)
            {
                if (this._disposed)
                {
                    return null;
                }
                lock (_callbacks)
                {
                    _callbacks.TryGetValue(this._handle, out ConcurrentDictionary<long, IOCompletionCallback> d);
                    if (d == null)
                    {
                        d = new ConcurrentDictionary<long, IOCompletionCallback>();
                        if (!_callbacks.TryAdd(this._handle, d))
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
        private bool UnbindCallback(long key)
        {
            lock (this._synobj)
            {
                if (this._disposed)
                {
                    return false;
                }
                _callbacks.TryGetValue(this._handle, out ConcurrentDictionary<long, IOCompletionCallback> d);
                if (d == null)
                {
                    return false;
                }
                return d.TryRemove(key, out IOCompletionCallback _);
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        private long BindCallback(Action<object> callback, object state)
        {
            lock (this._synobj)
            {
                ConcurrentDictionary<long, IOCompletionCallback> callbacks = this.GetAllCallback();
                if (callbacks == null)
                {
                    return 0;
                }
                IOCompletionCallback cb = new IOCompletionCallback()
                {
                    post_callback_ = callback,
                    state_ = state,
                };
                for (; ; )
                {
                    long key_ = Interlocked.Increment(ref this._mapkey);
                    if (key_ == 0)
                    {
                        continue;
                    }
                    if (callbacks.TryAdd(key_, cb))
                    {
                        return key_;
                    }
                }
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        private long BindCallback(Action<int> callback, out DelayContext context)
        {
            context = null;
            lock (this._synobj)
            {
                ConcurrentDictionary<long, IOCompletionCallback> callbacks = this.GetAllCallback();
                if (callbacks == null)
                {
                    return 0;
                }
                IOCompletionCallback cb = new IOCompletionCallback()
                {
                    delay_callback_ = callback,
                };
                long key_;
                for (; ; )
                {
                    key_ = Interlocked.Increment(ref this._mapkey);
                    if (key_ == 0)
                    {
                        continue;
                    }
                    if (callbacks.TryAdd(key_, cb))
                    {
                        break;
                    }
                }
                cb.delay_context_ = context = new DelayContext(this, key_);
                return key_;
            }
        }

        public static AsyncScheduler Scheduler
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            get => AsyncContext._scheduler;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public AsyncContext()
        {
            this._handle = libasio_new_context();
            this._buffer_gc = GCHandle.Alloc(this._buffer, GCHandleType.Pinned);
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        ~AsyncContext() => this.Dispose();

        public IntPtr Handle
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            get => Interlocked.CompareExchange(ref this._handle, IntPtr.Zero, IntPtr.Zero);
        }

        public byte[] Buffer
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            get => this._buffer;
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
        public AsyncSocket CreateSocket(Socket socket)
        {
            if (socket == null)
            {
                throw new ArgumentNullException(nameof(socket));
            }
            return new AsyncSocket(this, socket);
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public bool Post(Action<object> callback, object state)
        {
            if (callback == null)
            {
                return false;
            }
            lock (this._synobj)
            {
                if (this._disposed)
                {
                    return false;
                }
                long key_ = this.BindCallback(callback, state);
                if (key_ == 0)
                {
                    return false;
                }
                if (!libasio_postcontext(this._handle, key_, _postcallback))
                {
                    this.UnbindCallback(key_);
                    return false;
                }
                return true;
            }
        }

        private sealed class DelayContext : IDisposable
        {
            private readonly AsyncContext context_;
            private long key_;

#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            public DelayContext(AsyncContext context_, long key_)
            {
                this.key_ = key_;
                this.context_ = context_;
            }

#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            public void Dispose()
            {
                long key = Interlocked.Exchange(ref this.key_, 0);
                if (key != 0)
                {
                    libasio_stopdelay(key);
                    this.context_.UnbindCallback(key);
                }
                GC.SuppressFinalize(this);
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public IDisposable Delay(Action<int> callback, int timeout)
        {
            if (callback == null)
            {
                return null;
            }
            lock (this._synobj)
            {
                if (this._disposed)
                {
                    return null;
                }
                long key_ = this.BindCallback(callback, out DelayContext context_);
                if (key_ == 0)
                {
                    return null;
                }
                if (!libasio_opendelay(this._handle, key_, timeout, _delaycallback))
                {
                    this.UnbindCallback(key_);
                    return null;
                }
                return context_;
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public void Dispose()
        {
            lock (this._synobj)
            {
                if (!this._disposed)
                {
                    this.Post((state) =>
                    {
                        var gc = __makeref(this._buffer_gc);
                        if (__refvalue(gc, GCHandle).IsAllocated)
                        {
                            __refvalue(gc, GCHandle).Free();
                        }
                        libasio_closecontext(this._handle);
                        _callbacks.TryRemove(this._handle, out ConcurrentDictionary<long, IOCompletionCallback> _);
                    }, default(object));
                    this._disposed = true;
                }
            }
            GC.SuppressFinalize(this);
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static AsyncContext GetContext() => AsyncContext._scheduler.GetContext();
    }
}
#endif