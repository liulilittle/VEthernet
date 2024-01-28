namespace VEthernet.Threading
{
    using System;
    using System.Collections.Concurrent;
    using System.Diagnostics;
#if NETCOREAPP
    using System.Runtime.CompilerServices;
#endif
    using System.Threading;

    public sealed class ThreadProtection : IDisposable
    {
        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private static readonly ConcurrentDictionary<Thread, Context> _into_rrc = new ConcurrentDictionary<Thread, Context>();
        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private static readonly Timer _into_rrc_timer = null;
        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private static readonly object _globalsync = new object();

        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private readonly object _syncobj = new object();
        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private Thread _into_thread = null;

        public const int MaxRecursiveLayers = 100;

        private sealed class Context
        {
            public int rrc = 0;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        static ThreadProtection()
        {
            _into_rrc_timer = new Timer();
            _into_rrc_timer.Interval = 1000;
            _into_rrc_timer.Tick += (sender, e) =>
            {
                foreach (var kv in _into_rrc)
                {
                    Thread thread = kv.Key;
                    if (!thread.IsAlive)
                    {
                        _into_rrc.TryRemove(thread, out Context context);
                    }
                }
            };
            _into_rrc_timer.Start();
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public ThreadProtection() : this(MaxRecursiveLayers)
        {

        }

        ~ThreadProtection() => this.Dispose();

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public ThreadProtection(int maxInto)
        {
            if (maxInto < MaxRecursiveLayers)
            {
                maxInto = MaxRecursiveLayers;
            }
            this.MaximumInto = maxInto;
        }

        public event EventHandler<ThreadExceptionEventArgs> UnhandledException;

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        private static Context GetContext()
        {
            lock (_globalsync)
            {
                Thread thread = Thread.CurrentThread;
                _into_rrc.TryGetValue(thread, out Context context);
                if (context == null)
                {
                    context = new Context();
                    _into_rrc[thread] = context;
                }
                return context;
            }
        }

        public int CurrentInto
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            get => Interlocked.CompareExchange(ref GetContext().rrc, 0, 0);
        }

        public int MaximumInto
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            get;
        }

        public Thread IntoThread
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            get => this._into_thread;
        }

        public Thread CurrentThread
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            get => Thread.CurrentThread;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public void Execute(WaitCallback critical) => this.Execute(critical, null);

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public void Execute(WaitCallback critical, object state)
        {
            if (critical == null)
            {
                throw new ArgumentNullException(nameof(critical));
            }
            bool can_into = false;
            Thread current_thread = Thread.CurrentThread;
            Context current_context = GetContext();
            lock (this._syncobj)
            {
                Thread into_thread = Interlocked.CompareExchange(ref this._into_thread, null, current_thread);
                if (into_thread != current_thread)
                {
                    Interlocked.Exchange(ref current_context.rrc, 0);
                }
                can_into = this.MaximumInto >= Interlocked.Increment(ref current_context.rrc);
                if (!can_into)
                {
                    Interlocked.Exchange(ref current_context.rrc, 0);
                }
            }
            if (can_into)
            {
                try
                {
                    critical(state);
                }
                catch (Exception e)
                {
                    this.OnUnhandledException(e);
                }
            }
            else
            {
                WaitCallback into_callback = (input_state) =>
                {
                    try
                    {
                        critical(input_state);
                    }
                    catch (Exception e)
                    {
                        this.OnUnhandledException(e);
                    }
                };
                ThreadPool.QueueUserWorkItem(into_callback, state);
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        private void OnUnhandledException(Exception e)
        {
            if (e == null)
            {
                return;
            }
            ThreadExceptionEventArgs p = new ThreadExceptionEventArgs(e);
            try
            {
                this.UnhandledException?.Invoke(this, p);
            }
            catch { }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public void Dispose()
        {
            Interlocked.Exchange(ref this.UnhandledException, null);
            GC.SuppressFinalize(this);
        }
    }
}
