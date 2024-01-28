namespace VEthernet.Hooking
{
    using System;
    using System.Reflection;
    using System.Runtime.InteropServices;
    using VEthernet.Core;

    public unsafe class Hooker // E9 00 00 00 00
    {
        private readonly object syncobj = new object();
        private IntPtr mOldMethodAddress;
        private IntPtr mNewMethodAddress;
        private byte[] mOldMethodAsmCode;
        private byte[] mNewMethodAsmCode;
        private IntPtr mJmpMethodAsmCode;

        public IntPtr NewMethodAddress => mNewMethodAddress;

        public IntPtr OldMethodAddress => mOldMethodAddress;

        public byte[] OldAssemblyInstructions => mOldMethodAsmCode;

        public byte[] NewAssemblyInstructions => mNewMethodAsmCode;

        ~Hooker()
        {
            this.Uninstall();
            GC.SuppressFinalize(this);
        }

        public virtual void Install(IntPtr oldMethodAddress, IntPtr newMethodAddress)
        {
            if (oldMethodAddress == NativeMethods.NULL || newMethodAddress == NativeMethods.NULL)
                throw new Exception("The address is invalid.");
            if (!this.AdjustProtectMemoryPermissions(oldMethodAddress))
                throw new Exception("Unable to modify memory protection.");
            this.mOldMethodAddress = oldMethodAddress;
            this.mNewMethodAddress = newMethodAddress;
            this.mOldMethodAsmCode = this.GetHeadCode(this.mOldMethodAddress);
            this.mNewMethodAsmCode = this.ConvetToBinary(Convert.ToInt32(this.mNewMethodAddress.ToInt64() - (this.mOldMethodAddress.ToInt64() + 5)));
            this.mNewMethodAsmCode = this.CombineOfArray(new byte[] { 0xE9 }, this.mNewMethodAsmCode);
            if (!this.WriteToMemory(this.mNewMethodAsmCode, this.mOldMethodAddress, 5))
                throw new Exception("Cannot be written to memory.");
        }

        private int AfterIndexOf(byte* sources, int length, params byte[] searchs)
        {
            if (sources == null)
            {
                return -1;
            }
            if (searchs == null)
            {
                return -1;
            }
            if (searchs.Length < 1)
            {
                return -1;
            }
            if (length < 1)
            {
                return -1;
            }
            for (int i = 0; i < length; i++)
            {
                bool f = true;
                for (int j = 0; j < searchs.Length; j++)
                {
                    if (sources[i + j] != searchs[j])
                    {
                        f = false;
                        break;
                    }
                }
                if (f)
                {
                    return i + searchs.Length;
                }
            }
            return -1;
        }

        protected virtual bool AdjustProtectMemoryPermissions(IntPtr address)
        {
            return AdjustProtectMemoryPermissions(address, 12,
                      ProtectMemoryPermissions.Execute |
                      ProtectMemoryPermissions.Read |
                      ProtectMemoryPermissions.Write);
        }

        public virtual void Suspend()
        {
            if (this.mOldMethodAddress == NativeMethods.NULL)
                throw new Exception("Unable to suspend.");
            this.WriteToMemory(this.mOldMethodAsmCode, this.mOldMethodAddress, 5);
        }

        public virtual void Resume()
        {
            if (this.mOldMethodAddress == NativeMethods.NULL)
            {
                throw new Exception("Unable to resume.");
            }
            this.WriteToMemory(this.mNewMethodAsmCode, this.mOldMethodAddress, 5);
        }

        public virtual void Uninstall()
        {
            lock (this.syncobj)
            {
                if (this.mOldMethodAddress != NativeMethods.NULL)
                {
                    if (!this.WriteToMemory(this.mOldMethodAsmCode, this.mOldMethodAddress, 5))
                        throw new Exception("Cannot be written to memory.");
                }
                if (this.mJmpMethodAsmCode != NativeMethods.NULL)
                    Marshal.FreeHGlobal(this.mJmpMethodAsmCode);
                this.mOldMethodAsmCode = null;
                this.mNewMethodAsmCode = null;
                this.mOldMethodAddress = NativeMethods.NULL;
                this.mNewMethodAddress = NativeMethods.NULL;
                this.mJmpMethodAsmCode = NativeMethods.NULL;
            }
        }

        private byte[] GetHeadCode(IntPtr ptr)
        {
            byte[] buffer = new byte[5];
            Marshal.Copy(ptr, buffer, 0, 5);
            return buffer;
        }

        private byte[] ConvetToBinary(int num)
        {
            byte[] buffer = new byte[4];
            unsafe
            {
                fixed (byte* p = buffer)
                {
                    *(int*)p = num;
                }
            }
            return buffer;
        }

        private byte[] CombineOfArray(byte[] x, byte[] y)
        {
            int i = 0, len = x.Length;
            byte[] buffer = new byte[len + y.Length];
            while (i < len)
            {
                buffer[i] = x[i];
                i++;
            }
            while (i < buffer.Length)
            {
                buffer[i] = y[i - len];
                i++;
            }
            return buffer;
        }

        private bool WriteToMemory(byte[] buffer, IntPtr address, int size)
        {
            if (size < 0 || (buffer == null && 0 != size))
            {
                return false;
            }
            if (address == IntPtr.Zero && 0 != size)
            {
                return false;
            }
            lock (this.syncobj)
            {
                Marshal.Copy(buffer, 0, address, Convert.ToInt32(size));
                return true;
            }
        }

        public static IntPtr GetProcAddress(Delegate d)
        {
            if (d == null)
            {
                return IntPtr.Zero;
            }
            return Marshal.GetFunctionPointerForDelegate(d);
        }

        public static IntPtr GetProcAddress(MethodBase m)
        {
            if (m == null)
            {
                return IntPtr.Zero;
            }
            return m.MethodHandle.GetFunctionPointer();
        }

        private static class NativeMethods
        {
            public static readonly IntPtr NULL = IntPtr.Zero;

            [DllImport("kernel32.dll", SetLastError = false, ExactSpelling = true)]
            public static extern bool VirtualProtect(IntPtr lpAddress, int dwSize, int flNewProtect, out int lpflOldProtect);

            [DllImport("libc", SetLastError = false, ExactSpelling = true)]
            public unsafe static extern int mprotect(IntPtr start, int len, int prot);
        }

        public enum ProtectMemoryPermissions
        {
            NoAccess = 0,
            Write = 1,
            Read = 2,
            Execute = 4,
        }

        private enum VirtualAllocationProtect
        {
            PAGE_EXECUTE = 0x00000010,
            PAGE_EXECUTE_READ = 0x00000020,
            PAGE_EXECUTE_READWRITE = 0x00000040,
            PAGE_EXECUTE_WRITECOPY = 0x00000080,
            PAGE_NOACCESS = 0x00000001,
            PAGE_READONLY = 0x00000002,
            PAGE_READWRITE = 0x00000004,
            PAGE_WRITECOPY = 0x00000008,
            PAGE_GUARD = 0x00000100,
            PAGE_NOCACHE = 0x00000200,
            PAGE_WRITECOMBINE = 0x00000400
        }

        private enum UnixAllocationProtect
        {
            PROT_NONE = 0x0, /* page can not be accessed */
            PROT_READ = 0x1, /* page can be read */
            PROT_WRITE = 0x2, /* page can be written */
            PROT_EXEC = 0x4, /* page can be executed */
        }

        public static bool AdjustProtectMemoryPermissions(IntPtr memory, int counts, ProtectMemoryPermissions permissions)
        {
            if (memory == IntPtr.Zero && counts != 0)
            {
                return false;
            }
            if (counts == 0)
            {
                return true;
            }
            int privileges = 0;
            if (Environments.Platform == PlatformID.Win32NT)
            {
                if (permissions == ProtectMemoryPermissions.NoAccess)
                {
                    privileges |= (int)VirtualAllocationProtect.PAGE_NOACCESS;
                }
                else
                {
                    bool executing = 0 != (permissions & ProtectMemoryPermissions.Execute);
                    if (0 != (permissions & ProtectMemoryPermissions.Read))
                    {
                        if (executing)
                        {
                            privileges = (int)VirtualAllocationProtect.PAGE_EXECUTE_READ;
                        }
                        else
                        {
                            privileges = (int)VirtualAllocationProtect.PAGE_READONLY;
                        }
                    }
                    if (0 != (permissions & ProtectMemoryPermissions.Write))
                    {
                        if (executing)
                        {
                            privileges = (int)VirtualAllocationProtect.PAGE_EXECUTE_READWRITE;
                        }
                        else
                        {
                            privileges = (int)VirtualAllocationProtect.PAGE_READWRITE;
                        }
                    }
                }
                return NativeMethods.VirtualProtect(memory, counts, privileges, out int flOldProtect);
            }
            else
            {
                if (permissions == ProtectMemoryPermissions.NoAccess)
                {
                    privileges = (int)UnixAllocationProtect.PROT_NONE;
                }
                else
                {
                    if (0 != (permissions & ProtectMemoryPermissions.Read))
                    {
                        privileges |= (int)UnixAllocationProtect.PROT_READ;
                    }
                    if (0 != (permissions & ProtectMemoryPermissions.Write))
                    {
                        privileges |= (int)UnixAllocationProtect.PROT_WRITE;
                    }
                    if (0 != (permissions & ProtectMemoryPermissions.Write))
                    {
                        privileges |= (int)UnixAllocationProtect.PROT_EXEC;
                    }
                }
                return NativeMethods.mprotect(memory, counts, privileges) >= 0;
            }
        }
    }
}