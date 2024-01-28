namespace VEthernet.Hooking
{
    using System;
    using System.Reflection;
    using VEthernet.Core;

    public class Interceptor : IDisposable
    {
        private readonly Hooker _hooking = null;
        private bool _disposed = false;

        public delegate void CriticalHandler();

        private sealed class NativeInterceptor : Hooker
        {
            protected override bool AdjustProtectMemoryPermissions(IntPtr address)
            {
                if (Environments.Platform != PlatformID.Win32NT)
                {
                    return true;
                }
                return base.AdjustProtectMemoryPermissions(address);
            }
        }

        public Interceptor(MethodBase sources, MethodBase destination)
        {
            this.Source = sources ?? throw new ArgumentNullException(nameof(sources));
            this.Destination = destination ?? throw new ArgumentNullException(nameof(destination));
            this._hooking = new NativeInterceptor();
            this._hooking.Install(Hooker.GetProcAddress(sources), Hooker.GetProcAddress(destination));
        }

        ~Interceptor()
        {
            this.Dispose();
        }

        public virtual Hooker SynchronizingObject { get => this._hooking; }

        public virtual MethodBase Source { get; private set; }

        public virtual MethodBase Destination { get; private set; }

        public virtual bool Suspend()
        {
            lock (this._hooking)
            {
                if (this._disposed)
                {
                    return false;
                }
                this._hooking.Suspend();
                return true;
            }
        }

        public virtual bool Resume()
        {
            lock (_hooking)
            {
                if (_disposed)
                {
                    return false;
                }
                _hooking.Resume();
                return true;
            }
        }

        public virtual void Execute(CriticalHandler critical)
        {
            Exception exception = this.Invoke(critical);
            if (exception != null)
            {
                throw exception;
            }
        }

        public virtual Exception Invoke(CriticalHandler critical)
        {
            Exception exception = null;
            if (critical != null)
            {
                lock (this._hooking)
                {
                    if (this._disposed)
                    {
                        exception = new ObjectDisposedException(typeof(Interceptor).FullName);
                    }
                    else
                    {
                        this.Suspend();
                        try
                        {
                            critical();
                        }
                        catch (Exception e)
                        {
                            exception = e;
                        }
                        finally
                        {
                            this.Resume();
                        }
                    }
                }
            }
            return exception;
        }

        public virtual void Dispose()
        {
            lock (this._hooking)
            {
                if (!this._disposed)
                {
                    this._hooking.Uninstall();
                    this._disposed = true;
                }
            }
            GC.SuppressFinalize(this);
        }
    }
}
