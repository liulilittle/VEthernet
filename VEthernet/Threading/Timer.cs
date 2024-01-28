#if !AARCH
namespace VEthernet.Threading
{
    using System;
    using System.Threading;
#if NETCOREAPP
    using System.Runtime.CompilerServices;
#endif

    public class Timer : IDisposable
    {
        private readonly object _syncobj = new object();
        private bool _disposed;
        private bool _enabled;
        private int _interval;
        private IDisposable _stopper = null;

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public Timer(int interval, TimerScheduler scheduler) : this(scheduler) => this.Interval = interval;

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public Timer(int interval) : this(interval, TimerScheduler.Default)
        {

        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public Timer() : this(TimerScheduler.Default)
        {

        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public Timer(TimerScheduler scheduler) => this.Scheduler = scheduler ?? throw new ArgumentNullException("scheduler");

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        ~Timer() => this.Dispose();

        public event EventHandler Tick = default(EventHandler);

        public TimerScheduler Scheduler
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
            get;
        }

        public int Interval
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            get
            {
                return _interval;
            }
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            set
            {
                if (value < 0)
                {
                    throw new ArgumentOutOfRangeException("value");
                }
                lock (this._syncobj)
                {
                    int original = value;
                    _interval = value;
                    if (original != value)
                    {
                        this.Enabled = (value > 0);
                    }
                }
            }
        }

        public bool Enabled
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            get
            {
                return this._enabled;
            }
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            set
            {
                lock (this._syncobj)
                {
                    if (this._disposed)
                    {
                        return;
                    }

                    this._enabled = value;
                    if (value)
                    {
                        this.AddScheduler();
                    }
                    else
                    {
                        this.RemoveScheduler();
                    }
                }
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public void Dispose()
        {
            lock (this._syncobj)
            {
                this.Tick = null;
                this.Stop();
                this._disposed = true;
            }
            GC.SuppressFinalize(this);
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public void Close() => this.Dispose();

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public void Start() => this.Enabled = true;

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public void Stop() => this.Enabled = false;

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        protected virtual void OnTick(EventArgs e) => this.Tick?.Invoke(this, e);

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        private bool AddScheduler()
        {
            lock (this._syncobj)
            {
                this.RemoveScheduler();
                if (this._disposed || !this._enabled)
                {
                    return false;
                }
                IDisposable disposable = this.Scheduler.Context.Delay(err =>
                {
                    bool cleanAll = true;
                    do
                    {
                        if (err != 0 || !this.RemoveScheduler())
                        {
                            break;
                        }
                        if (!this._enabled)
                        {
                            cleanAll = false;
                            break;
                        }
                        try
                        {
                            this.OnTick(EventArgs.Empty);
                        }
                        catch
                        {
                            break;
                        }
                        if (this.AddScheduler())
                        {
                            cleanAll = false;
                        }
                    } while (false);
                    if (cleanAll)
                    {
                        this.Dispose();
                    }
                }, this._interval);
                return Interlocked.Exchange(ref this._stopper, disposable) == null;
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        private bool RemoveScheduler()
        {
            lock (this._syncobj)
            {
                IDisposable disposable = Interlocked.Exchange(ref this._stopper, null);
                if (disposable == null)
                {
                    return false;
                }
                else
                {
                    disposable.Dispose();
                    return true;
                }
            }
        }
    }
}
#else
namespace Ppp.Threading
{
    using System;
#if NETCOREAPP
    using System.Runtime.CompilerServices;
#endif

    public sealed class Timer : IDisposable
    {
        private readonly object _syncobj = new object();
        private bool _disposed;
        private bool _enabled;
        private int _interval;

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public Timer(int interval, TimerScheduler scheduler) : this(scheduler) => this.Interval = interval;

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public Timer(int interval) : this(interval, TimerScheduler.Default)
        {

        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public Timer() : this(TimerScheduler.Default)
        {

        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public Timer(TimerScheduler scheduler) => this.Scheduler = scheduler ?? throw new ArgumentNullException("scheduler");

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        ~Timer() => this.Dispose();

        public event EventHandler Tick = default(EventHandler);

        public TimerScheduler Scheduler
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            get;
        }

        public int Interval
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            get
            {
                return _interval;
            }
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            set
            {
                if (value < 0)
                {
                    throw new ArgumentOutOfRangeException("value");
                }
                lock (this._syncobj)
                {
                    int original = value;
                    _interval = value;
                    if (original != value)
                    {
                        this.Enabled = (value > 0);
                    }
                }
            }
        }

        public bool Enabled
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            get
            {
                return this._enabled;
            }
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            set
            {
                lock (this._syncobj)
                {
                    if (this._disposed)
                    {
                        return;
                    }

                    bool bOriginal = this._enabled;
                    this._enabled = value;

                    if (bOriginal != value)
                    {
                        if (value)
                        {
                            this.Scheduler.Start(this);
                        }
                        else
                        {
                            this.Scheduler.Stop(this);
                        }
                    }
                }
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public void Dispose()
        {
            lock (this._syncobj)
            {
                this.Tick = null;
                this.Stop();
                this._disposed = true;
            }
            GC.SuppressFinalize(this);
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public void Close() => this.Dispose();

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public void Start() => this.Enabled = true;

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public void Stop() => this.Enabled = false;

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        internal void OnTick(EventArgs e) => this.Tick?.Invoke(this, e);
    }
}
#endif