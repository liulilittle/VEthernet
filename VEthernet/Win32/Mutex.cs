namespace VEthernet.Win32
{
    using System;
    using System.Diagnostics;
    using System.Runtime.InteropServices;
    using System.Threading;

    public class Mutex : IDisposable
    {
        private static class NativeMethods
        {
            [DllImport("kernel32.dll", SetLastError = false, CharSet = CharSet.Ansi)]
            public static extern IntPtr CreateEvent(IntPtr lpEventAttributes, bool bManualReset, bool bInitialState, string lpName);

            [DllImport("kernel32.dll", SetLastError = false)]
            public static extern IntPtr OpenEvent(uint dwDesiredAccess, bool bInheritHandle, string lpName);

            [DllImport("kernel32.dll", SetLastError = false)]
            public static extern bool SetEvent(IntPtr hEvent);

            [DllImport("kernel32.dll", SetLastError = false)]
            public static extern bool ResetEvent(IntPtr hEvent);

            [DllImport("kernel32.dll", SetLastError = false)]
            public static extern int CloseHandle(IntPtr hSysObj);

            [DllImport("kernel32.dll", SetLastError = false)]
            public static extern int WaitForSingleObject(IntPtr hHandle, int dwMilliseconds);

            public const int EVENT_ALL_ACCESS = 2031619;
            public const int WAIT_OBJECT_T = 0;
            public static readonly IntPtr NULL = IntPtr.Zero;
        }

        public static bool Exists(string name)
        {
            IntPtr hEvt = NativeMethods.OpenEvent(NativeMethods.EVENT_ALL_ACCESS, false, name);
            NativeMethods.CloseHandle(hEvt);
            return hEvt != NativeMethods.NULL;
        }

        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private readonly IntPtr hKrlEvt = NativeMethods.NULL;

        public Mutex(string name) : this(name, true, EventResetMode.AutoReset)
        {

        }

        public Mutex(string name, EventResetMode mode) : this(name, true, mode)
        {

        }

        public Mutex(string name, bool initialState, EventResetMode mode)
            : this(name, initialState, mode, false)
        {

        }

        public Mutex(string name, bool initialState, EventResetMode mode, bool openOrCreate)
        {
            if (!openOrCreate)
            {
                if (Mutex.Exists(name))
                {
                    throw new ArgumentException(name);
                }
            }
            else
            {
                hKrlEvt = NativeMethods.OpenEvent(NativeMethods.EVENT_ALL_ACCESS, false, name);
            }
            if (hKrlEvt == IntPtr.Zero)
            {
                if (mode == EventResetMode.AutoReset)
                {
                    hKrlEvt = NativeMethods.CreateEvent(NativeMethods.NULL, false, initialState, name);
                }
                else if (mode == EventResetMode.ManualReset)
                {
                    hKrlEvt = NativeMethods.CreateEvent(NativeMethods.NULL, true, initialState, name);
                }
                else
                {
                    throw new NotSupportedException(nameof(mode));
                }
            }
            if (hKrlEvt == IntPtr.Zero)
            {
                throw new InvalidOperationException("Cannot kernel event synchronization object, this may be because the event name has been used or the name string is incorrect");
            }
        }

        ~Mutex()
        {
            this.Dispose();
        }

        public IntPtr Handle
        {
            get
            {
                return this.hKrlEvt;
            }
        }

        public bool WaitOne(int millisecondsTimeout)
        {
            return NativeMethods.WaitForSingleObject(hKrlEvt, millisecondsTimeout) == NativeMethods.WAIT_OBJECT_T;
        }

        public bool WaitOne()
        {
            return this.WaitOne(Timeout.Infinite);
        }

        public bool Set()
        {
            return NativeMethods.SetEvent(hKrlEvt);
        }

        public bool Reset()
        {
            return NativeMethods.ResetEvent(hKrlEvt);
        }

        public void Close()
        {
            this.Dispose();
        }

        public virtual void Dispose()
        {
            NativeMethods.CloseHandle(hKrlEvt);
            GC.SuppressFinalize(this);
        }
    }
}
