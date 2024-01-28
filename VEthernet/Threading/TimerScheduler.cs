#if !AARCH
namespace VEthernet.Threading
{
    using System;
    using System.Diagnostics;
#if NETCOREAPP
    using System.Runtime.CompilerServices;
#endif
    using global::VEthernet.Net.Auxiliary;

    public sealed class TimerScheduler : IDisposable
    {
        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        internal readonly AsyncContext Context = new AsyncContext();

        public static TimerScheduler Default { get; }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        static TimerScheduler() => TimerScheduler.Default = new TimerScheduler();

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        ~TimerScheduler() => this.Dispose();

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public void Dispose()
        {
            this.Context.Dispose();
            GC.SuppressFinalize(this);
        }
    }
}
#else
namespace Ppp.Threading
{
    using System;
    using System.Collections.Generic;
    using System.Threading;
#if NETCOREAPP
    using System.Runtime.CompilerServices;
#endif

    public sealed class TimerScheduler : IDisposable
    {
        private static readonly TimerScheduler _default = new TimerScheduler();
        private readonly object _syncobj = new object();
        private Thread _mta;
        private bool _disposed;
        private readonly AutoResetEvent _onCompleteEvent = new AutoResetEvent(false); // 完成事件
        private readonly LinkedList<Timer> _tickTimers = new LinkedList<Timer>();
        private readonly IDictionary<Timer, QueueTimerContext> _timers = new Dictionary<Timer, QueueTimerContext>();

        private sealed class QueueTimerContext
        {
            public Timer pt;
            public System.Threading.Timer st;

#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            public QueueTimerContext(Timer pt) => this.pt = pt;

#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            public bool WaitAsync(TimerCallback tc)
            {
                int interval = pt.Interval;
                if (interval < 1)
                {
                    return false;
                }
                this.st = new System.Threading.Timer(tc, this, interval, 0);
                return true;
            }
        }

        public static TimerScheduler Default => TimerScheduler._default;

        public int Id => this._mta.ManagedThreadId;

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        ~TimerScheduler() => this.Dispose();

        public int Count => this._timers.Count;

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        private bool Run()
        {
            lock (this._syncobj)
            {
                if (this._disposed || this._mta != null)
                {
                    return false;
                }
                this._mta = new Thread(() =>
                {
                    while (!this._disposed)
                    {
                        Timer[] timers = null;
                        try
                        {
                            this._onCompleteEvent.WaitOne();
                        }
                        catch
                        {
                            break;
                        }
                        var linkedlist = this._tickTimers;
                        lock (linkedlist)
                        {
                            timers = new Timer[linkedlist.Count];
                            var node = linkedlist.First;
                            var index = 0;
                            while (node != null)
                            {
                                var timer = node.Value;
                                try
                                {
                                    var deln = node;
                                    node = node.Next;
                                    linkedlist.Remove(deln);
                                }
                                finally
                                {
                                    timers[index++] = timer;
                                }
                            }
                        }
                        foreach (var timer in timers)
                        {
                            try
                            {
                                timer.OnTick(EventArgs.Empty);
                            }
                            catch { }
                            if (!this.Start(timer))
                            {
                                this.Stop(timer);
                            }
                        }
                    }
                    this.Dispose();
                });
                this._mta.IsBackground = true;
                this._mta.Priority = ThreadPriority.Lowest;
                this._mta.Start();
                return true;
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        private static bool CloseTimer(QueueTimerContext context)
        {
            if (context == null)
            {
                return false;
            }
            var st = Interlocked.Exchange(ref context.st, null);
            if (st == null)
            {
                return false;
            }
            try
            {
                st.Dispose();
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
        internal bool Start(Timer timer)
        {
            if (timer == null)
            {
                return false;
            }
            QueueTimerContext context = null;
            lock (this._syncobj)
            {
                if (this._disposed)
                {
                    return false;
                }
                else
                {
                    this.Stop(timer);
                }
                context = new QueueTimerContext(timer);
                if (!this._timers.TryAdd(timer, context))
                {
                    return false;
                }
                if (context.WaitAsync(this.QueueTimerCallback))
                {
                    this.Run();
                    return true;
                }
                else
                {
                    this.Stop(timer);
                    return false;
                }
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        private void QueueTimerCallback(object state)
        {
            var context = (QueueTimerContext)state;
            var timer = context.pt;
            if (this.Stop(timer) && timer.Enabled)
            {
                var linkedlist = this._tickTimers;
                lock (linkedlist)
                {
                    linkedlist.AddLast(context.pt);
                }
                try
                {
                    this._onCompleteEvent.Set(); // 投递信号
                }
                catch { }
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        internal bool Stop(Timer timer)
        {
            if (timer == null)
            {
                return false;
            }
            lock (this._syncobj)
            {
                QueueTimerContext context;
                if (!this._timers.TryGetValue(timer, out context))
                {
                    return false;
                }
                else
                {
                    this._timers.Remove(timer);
                }
                if (context != null)
                {
                    CloseTimer(context);
                }
                return !this._disposed;
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public void Dispose()
        {
            lock (this._syncobj)
            {
                if (!this._disposed)
                {
                    this._disposed = true;
                    foreach (var context in this._timers.Values)
                    {
                        CloseTimer(context);
                    }
                    this._timers.Clear();
                    this._tickTimers.Clear();
                    try
                    {
                        this._onCompleteEvent.Dispose();
                    }
                    catch { }
                }
            }
            GC.SuppressFinalize(this);
        }
    }
}
#endif