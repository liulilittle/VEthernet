namespace VEthernet.Win32
{
    using System;
    using System.Runtime.InteropServices;

    public static class Memory
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct SYSTEM_INFO
        {
            public ushort wProcessorArchitecture;
            public ushort wReserved;
            public uint dwPageSize;
            public IntPtr lpMinimumApplicationAddress;
            public IntPtr lpMaximumApplicationAddress;
            public IntPtr dwActiveProcessorMask;
            public uint dwNumberOfProcessors;
            public uint dwProcessorType;
            public uint dwAllocationGranularity;
            public ushort wProcessorLevel;
            public ushort wProcessorRevision;
        }

        [DllImport("kernel32.dll", SetLastError = false)]
        public static extern void GetSystemInfo(out SYSTEM_INFO si);

        public static uint PageSize
        {
            get
            {
                GetSystemInfo(out SYSTEM_INFO si);
                return si.dwPageSize;
            }
        }

        public static uint AllocationGranularity
        {
            get
            {
                GetSystemInfo(out SYSTEM_INFO si);
                return si.dwAllocationGranularity;
            }
        }
    }
}
