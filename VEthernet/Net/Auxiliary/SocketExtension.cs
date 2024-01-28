namespace VEthernet.Net.Auxiliary
{
    using System;
    using System.Diagnostics;
    using System.Linq.Expressions;
    using System.Net;
    using System.Net.Sockets;
    using System.Reflection;
    using System.Runtime.InteropServices;
#if NETCOREAPP
    using System.Runtime.CompilerServices;
#endif
    using global::VEthernet.Core;
    using Timer = global::VEthernet.Threading.Timer;

    public unsafe static class SocketExtension
    {
        public const ushort TCP_MSS = 536;
        public const ushort MSS = 1400;
        public const ushort PPP = 8;    // PPP
        public const ushort MTU = 1514; // 路由芯片最大传输单元
        public const ushort DnsPort = 53;
        internal const int Backlog = ushort.MaxValue;

        private const long SIO_UDP_CONNRESET = IOC_IN | IOC_VENDOR | 0x0000000C;
        private const long IOC_IN = 0x80000000;
        private const long IOC_VENDOR = 0x18000000;

        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private static readonly Timer gcCollectTimer = null;

        [UnmanagedFunctionPointer(CallingConvention.FastCall)]
        private delegate bool GetCleanedUp(Socket socket);

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static int SioUdpConnectReset(Socket socket, byte[] optionInValue, byte[] optionOutValue)
        {
            if (SocketExtension.CleanedUp(socket))
            {
                return ~0;
            }
            PlatformID platform = Environments.Platform;
            if (platform != PlatformID.Win32NT)
            {
                return ~0;
            }
            if (socket.SocketType != SocketType.Dgram)
            {
                return ~0;
            }
            try
            {
                return socket.IOControl((IOControlCode)SIO_UDP_CONNRESET, optionInValue, optionOutValue);
            }
            catch
            {
                return ~0;
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static void SioUdpConnectReset(Socket s) => SioUdpConnectReset(s, new byte[4], new byte[] { 0 });

        private static class NativeMethods
        {
            [DllImport("kernel32.dll", SetLastError = false, EntryPoint = "SetProcessWorkingSetSize", CallingConvention = CallingConvention.StdCall, ExactSpelling = true)]
            public static extern bool SetProcessWorkingSetSize_x86(IntPtr hProcess, int dwMinimumWorkingSetSize, int dwMaximumWorkingSetSize);

            [DllImport("kernel32.dll", SetLastError = false, EntryPoint = "SetProcessWorkingSetSize", CallingConvention = CallingConvention.StdCall, ExactSpelling = true)]
            public static extern bool SetProcessWorkingSetSize_x64(IntPtr hProcess, long dwMinimumWorkingSetSize, long dwMaximumWorkingSetSize);

            [DllImport("ws2_32.dll", SetLastError = false, EntryPoint = "shutdown", CallingConvention = CallingConvention.StdCall, ExactSpelling = true)]
            public static extern SocketError win32_shutdown(int socketHandle, SocketShutdown how);

            [DllImport("ws2_32.dll", EntryPoint = "setsockopt", CallingConvention = CallingConvention.StdCall, ExactSpelling = true)]
            public static extern int win32_setsockopt(int s, int level, int option_name, IntPtr optval, int optlen);

            [DllImport("ws2_32.dll", EntryPoint = "sendto", CallingConvention = CallingConvention.StdCall, ExactSpelling = true)]
            public static extern int win32_sendto(int s, byte* buf, int len, int flags, byte* to, int tolen);

            [DllImport("ws2_32.dll", EntryPoint = "recvfrom", CallingConvention = CallingConvention.StdCall, ExactSpelling = true)]
            public static extern int win32_recvfrom(int s, byte* pinnedBuffer, int len, SocketFlags socketFlags, byte* socketAddress, ref int socketAddressSize);

            [DllImport("ws2_32.dll", CharSet = CharSet.Unicode, SetLastError = false, ExactSpelling = true)]
            public static extern int closesocket(IntPtr s);

            [DllImport("libc", EntryPoint = "close", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
            public static extern int close(int s);

            [DllImport("libc", EntryPoint = "shutdown", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
            public static extern SocketError linux_shutdown(int s, SocketShutdown how);

            [DllImport("libc", EntryPoint = "setsockopt", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
            public static extern int linux_setsockopt(int socket, int level, int option_name, IntPtr option_value, int option_len);

            [DllImport("libc", EntryPoint = "sendmsg", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
            public static extern int linux_sendmsg(int fd, msghdr* msg, int flags);

            [DllImport("libc", EntryPoint = "sendto", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
            public static extern int linux_sendto(int socketHandle, byte* pinnedBuffer, int len, int socketFlags, byte* socketAddress, int socketAddressSize);

            [DllImport("libc", EntryPoint = "recvfrom", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
            public static extern int linux_recvfrom(int socketHandle, byte* pinnedBuffer, int len, int socketFlags, byte* socketAddress, ref int socketAddressSize);

            [StructLayout(LayoutKind.Sequential, Size = 16, Pack = 1)]
            public struct in6_addr
            {
                public long sa_1;
                public long sa_2;
            }

            [StructLayout(LayoutKind.Sequential, Size = 24, Pack = 1)]
            public struct sockaddr_in6_old
            {
                public ushort sin6_family;
                public ushort sin6_port;
                public uint sin6_flowinfo;
                public in6_addr sin6_addr;
            }

            [StructLayout(LayoutKind.Sequential, Size = 4, Pack = 1)]
            public struct in_addr
            {
                public uint S_addr;
            }

            [StructLayout(LayoutKind.Sequential, Size = 16, Pack = 1)]
            public struct sockaddr_in
            {
                public ushort sin_family;
                public ushort sin_port;
                public in_addr sin_addr;
                public long sin_zero;
            }

            /* Structure for scatter/gather I/O.  */
            [StructLayout(LayoutKind.Sequential)]
            public struct iovec
            {
                public void* iov_base; /* Pointer to data.  */
                public uint iov_len; /* Length of data.  */
            };

            [StructLayout(LayoutKind.Sequential)]
            public struct msghdr
            {
                public void* msg_name; /* Address to send to/receive from.  */
                public uint msg_namelen; /* Length of address data.  */
                public iovec* msg_iov; /* Vector of data to send/receive into.  */
                public int msg_iovlen; /* Number of elements in the vector.  */
                public void* msg_control; /* Ancillary data (eg BSD filedesc passing). */
                public uint msg_controllen; /* Ancillary data buffer length.
                    !! The type should be socklen_t but the
				    definition of the kernel is incompatible
				    with this.  */
                public int msg_flags; /* Flags on received message.  */
            }

            public const int MSG_NOSIGNAL = 0x4000; /* Do not generate SIGPIPE. */

#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            public static int linux_sendmsg(int fd, byte* data, int datalen, byte* sockaddr, int sockaddr_len)
            {
                iovec* io = stackalloc iovec[1];
                io->iov_base = data;
                io->iov_len = (uint)datalen;

                msghdr* msg = stackalloc msghdr[1];
                msg->msg_name = sockaddr;
                msg->msg_namelen = (uint)sockaddr_len;

                msg->msg_iov = io;
                msg->msg_iovlen = 1;

                msg->msg_flags = 0;
                msg->msg_control = null;
                msg->msg_controllen = 0;

                return linux_sendmsg(fd, msg, 0);
            }

#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            public static bool ToSocketAddressBytes(byte* buffer, IPEndPoint addressEP, out int length)
            {
                if (addressEP == null)
                {
                    length = 0;
                    return false;
                }
                if (addressEP.AddressFamily == AddressFamily.InterNetwork)
                {
                    byte* p = buffer;
                    *(ushort*)p = 2; // AF_INET
                    p += 2;

                    *(ushort*)p = CheckSum.htons((ushort)addressEP.Port);
                    p += 2;

                    byte[] addrbytes = addressEP.Address.GetAddressBytes();
                    fixed (byte* addrp = addrbytes)
                    {
                        *(uint*)p = *(uint*)addrp;
                        p += 4;
                    }

                    *(long*)p = 0;
                    p += 8;

                    length = (int)(p - buffer);
                    return true;
                }
                else if (addressEP.AddressFamily == AddressFamily.InterNetworkV6)
                {
                    byte[] addrbytes = addressEP.Address.GetAddressBytes();
                    fixed (byte* bsrc = addrbytes)
                    {
                        sockaddr_in6_old* in6 = (sockaddr_in6_old*)buffer;
                        if (Environments.Platform == PlatformID.Win32NT)
                        {
                            in6->sin6_family = 23; // AF_INET6
                        }
                        else
                        {
                            in6->sin6_family = 10;
                        }
                        in6->sin6_flowinfo = 0;
                        in6->sin6_port = CheckSum.htons((ushort)addressEP.Port);

                        long* dst = (long*)&in6->sin6_addr;
                        long* src = (long*)bsrc;
                        dst[0] = src[0];
                        dst[1] = src[1];

                        length = sizeof(sockaddr_in6_old);
                        return true;
                    }
                }
                else
                {
                    length = 0;
                    return false;
                }
            }

#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            public static IPEndPoint FromSocketAddressBytes(byte* address)
            {
                if (address == null)
                {
                    return null;
                }
                sockaddr_in* in4 = (sockaddr_in*)address;
                if (in4->sin_family == (int)AddressFamily.InterNetwork)
                {
                    return new IPEndPoint(new IPAddress(in4->sin_addr.S_addr), CheckSum.ntohs(in4->sin_port));
                }
                else
                {
                    sockaddr_in6_old* in6 = (sockaddr_in6_old*)address;
                    if (in6->sin6_family == (int)AddressFamily.InterNetworkV6)
                    {
                        byte[] addrbytes = new byte[sizeof(in6_addr)];
                        long* src = (long*)&in6->sin6_addr;
                        fixed (byte* bdst = addrbytes)
                        {
                            long* dst = (long*)bdst;
                            dst[0] = src[0];
                            dst[1] = src[1];
                        }
                        return new IPEndPoint(new IPAddress(addrbytes), CheckSum.ntohs(in6->sin6_port));
                    }
                    else
                    {
                        return null;
                    }
                }
            }
        }

        public static Func<Socket, bool> CleanedUp
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            get;
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            private set;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        static SocketExtension()
        {
            SocketExtension.TypeOfService = 0x68;
            SocketExtension.gcCollectTimer = new Timer(10000);
            SocketExtension.gcCollectTimer.Tick += (sender, e) =>
            {
                if (Environments.Platform == PlatformID.Win32NT)
                {
                    if (Environment.Is64BitProcess)
                    {
                        NativeMethods.SetProcessWorkingSetSize_x64(Process.GetCurrentProcess().Handle, -1, -1);
                    }
                    else
                    {
                        NativeMethods.SetProcessWorkingSetSize_x86(Process.GetCurrentProcess().Handle, -1, -1);
                    }
                }
                GC.Collect();
            };
            SocketExtension.gcCollectTimer.Start();
            SocketExtension.CleanedUp = SocketExtension.CompileCleanedUp();
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        private static Func<Socket, bool> CompileCleanedUp()
        {
            try
            {
                PropertyInfo piCleanedUp = typeof(Socket).GetProperty("CleanedUp", BindingFlags.NonPublic | BindingFlags.Instance);
                ParameterExpression s = Expression.Parameter(typeof(Socket), "s");
                Expression<Func<Socket, bool>> e = Expression.Lambda<Func<Socket, bool>>(Expression.Property(s, piCleanedUp), s);
                Func<Socket, bool> fCleanedUp = e.Compile();
                return (socket) =>
                {
                    if (socket == null)
                    {
                        return true;
                    }
                    if (socket is NetworkSocket NS)
                    {
                        return NS.CleanedUp;
                    }
                    return fCleanedUp(socket);
                };
            }
            catch
            {
                return (socket) =>
                {
                    if (socket == null)
                    {
                        return true;
                    }
                    if (socket is NetworkSocket NS)
                    {
                        return NS.CleanedUp;
                    }
                    return false;
                };
            }
        }

        public static byte TypeOfService
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

        public static int PeriodGCCollect
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            get
            {
                return gcCollectTimer.Interval;
            }
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            set
            {
                if (value < 1)
                {
                    gcCollectTimer.Interval = 0;
                    gcCollectTimer.Stop();
                }
                else
                {
                    gcCollectTimer.Stop();
                    gcCollectTimer.Interval = value;
                    gcCollectTimer.Start();
                }
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static bool SetFastOpen(this Socket socket, bool fastOpen = true)
        {
            if (SocketExtension.CleanedUp(socket))
            {
                return false; // https://github.com/dotnet/runtime/issues/1476#issue-547173361
            }
            if (socket.SocketType != SocketType.Stream)
            {
                return false;
            }
            PlatformID platform = Environments.Platform;
            if (platform == PlatformID.Win32NT)
            {
                // #define TCP_FASTOPEN 15 
                try
                {
                    socket.SetSocketOption(SocketOptionLevel.Tcp, (SocketOptionName)15, fastOpen);
                    return true;
                }
                catch
                {
                    return false;
                }
            }
            else if (platform == PlatformID.Unix)
            {
                // #define TCP_FASTOPEN 23 /* Enable FastOpen on listeners */
                // #define SOL_TCP      6  /* TCP level */
                int v = fastOpen ? 1 : 0;
                int r = NativeMethods.linux_setsockopt(socket.Handle.ToInt32(), 6, 23,
                               (IntPtr)(&v), sizeof(int));
                return r == 0;
            }
            else
            {
                return false;
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static unsafe bool SetTypeOfService(this Socket socket, int? tos = null)
        {
            if (SocketExtension.CleanedUp(socket))
            {
                return false;
            }
            if (tos == null)
            {
                tos = SocketExtension.TypeOfService;
            }
            try
            {
                byte[] optVal = new byte[] { (byte)tos };
                if (socket.AddressFamily == AddressFamily.InterNetworkV6)
                {
                    socket.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.TypeOfService, optVal);
                }
                else
                {
                    socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.TypeOfService, optVal);
                }
                return true;
            }
            catch
            {
                return false;
            }
        }

        private const int SOL_SOCKET_OSX = 0xffff;
        private const int SO_REUSEADDR_OSX = 0x0004;
        private const int SOL_SOCKET_LINUX = 0x0001;
        private const int SO_REUSEADDR_LINUX = 0x0002;

        // Without setting SO_REUSEADDR on macOS and Linux, binding to a recently used endpoint can fail.
        // https://github.com/dotnet/corefx/issues/24562
        // https://github.com/aspnet/KestrelHttpServer/blob/1c0cf15b119c053d8db754fd8688c50655de8ce8/src/Kestrel.Transport.Sockets/SocketTransport.cs#L166-L196
#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static unsafe void EnableReuseAddress(this Socket listenSocket)
        {
            if (listenSocket == null)
            {
                throw new ArgumentNullException(nameof(listenSocket));
            }
            int optionValue = 1;
            int setsockoptStatus = 0;
            if (Environments.Platform == PlatformID.Unix)
            {
                setsockoptStatus = NativeMethods.linux_setsockopt(listenSocket.Handle.ToInt32(), SOL_SOCKET_LINUX, SO_REUSEADDR_LINUX,
                              (IntPtr)(&optionValue), sizeof(int));
            }
            else if (Environments.Platform == PlatformID.MacOSX)
            {
                setsockoptStatus = NativeMethods.linux_setsockopt(listenSocket.Handle.ToInt32(), SOL_SOCKET_OSX, SO_REUSEADDR_OSX,
                                 (IntPtr)(&optionValue), sizeof(int));
            }
            else
            {
                try
                {
                    listenSocket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                }
                catch { }
            }
            if (setsockoptStatus != 0)
            {
                throw new SystemException($"Setting SO_REUSEADDR failed with errno '{Marshal.GetLastWin32Error()}'.");
            }
        }

        private const int IPV6_V6ONLY_LINUX = 26;
        private const int SOL_IPV6_LINUX = 41;

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static bool IPv6Only(this Socket socket, bool value)
        {
            if (socket == null)
            {
                return false;
            }
            if (Environments.Platform == PlatformID.Win32NT)
            {
                try
                {
                    socket.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.IPv6Only, value);
                    return true;
                }
                catch { }
            }
            else if (Environments.Platform == PlatformID.Unix)
            {
                int flag = value ? 1 : 0;
                int size = sizeof(int);
                int errc = NativeMethods.linux_setsockopt(socket.Handle.ToInt32(), SOL_IPV6_LINUX, IPV6_V6ONLY_LINUX,
                    (IntPtr)(&flag), size);
                return errc != -1;
            }
            return false;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static void Listen(Socket socket, int backlog)
        {
            Exception exception = null;
            if (socket == null)
            {
                exception = new NullReferenceException(nameof(socket));
            }
            else
            {
                if (backlog < 1)
                {
                    backlog = 511;
                }
                SocketExtension.EnableReuseAddress(socket);
                try
                {
                    socket.Listen(backlog);
                }
                catch (Exception e)
                {
                    exception = e;
                }
            }
            if (exception != null)
            {
                throw exception;
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        private static bool Shutdown(Socket socket)
        {
            if (SocketExtension.CleanedUp(socket))
            {
                return false;
            }
            if (socket.SocketType != SocketType.Stream)
            {
                return false;
            }
            PlatformID platform = Environments.Platform;
            if (platform == PlatformID.Win32NT)
            {
                return NativeMethods.win32_shutdown(socket.Handle.ToInt32(), SocketShutdown.Send) != SocketError.SocketError;
            }
            else if (platform == PlatformID.Unix)
            {
                return NativeMethods.linux_shutdown(socket.Handle.ToInt32(), SocketShutdown.Send) != SocketError.SocketError;
            }
            else
            {
                try
                {
                    socket.Shutdown(SocketShutdown.Send);
                    return true;
                }
                catch
                {
                    return false;
                }
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static bool Closesocket(Socket socket)
        {
            if (SocketExtension.CleanedUp(socket))
            {
                return false;
            }
            else
            {
                Shutdown(socket);
            }
            PlatformID platform = Environments.Platform;
            if (platform == PlatformID.Win32NT)
            {
                NativeMethods.closesocket(socket.Handle);
            }
            else if (platform == PlatformID.Unix)
            {
                NativeMethods.close(socket.Handle.ToInt32());
            }
            try
            {
                socket.Close();
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
        public static bool BeginSend(Socket s, byte[] buffer, int ofs, int size, AsyncCallback callback)
        {
            if (SocketExtension.CleanedUp(s))
            {
                return false;
            }
            try
            {
                s.BeginSend(buffer, ofs, size, SocketFlags.None, out SocketError error, callback, null);
                return error == SocketError.Success || error == SocketError.IOPending;
            }
            catch
            {
                return false;
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static bool EndSend(Socket s, IAsyncResult result)
        {
            if (SocketExtension.CleanedUp(s))
            {
                return false;
            }
            try
            {
                s.EndSend(result, out SocketError error);
                return error == SocketError.Success || error == SocketError.IOPending;
            }
            catch
            {
                return false;
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static bool BeginReceive(Socket s, byte[] buffer, int ofs, int size, AsyncCallback callback)
        {
            if (SocketExtension.CleanedUp(s))
            {
                return false;
            }
            try
            {
                s.BeginReceive(buffer, ofs, size, SocketFlags.None, out SocketError error, callback, null);
                return error == SocketError.Success || error == SocketError.IOPending;
            }
            catch
            {
                return false;
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static int EndReceive(Socket s, IAsyncResult result)
        {
            if (SocketExtension.CleanedUp(s))
            {
                return -1;
            }
            try
            {
                int by = s.EndReceive(result, out SocketError error);
                return error != SocketError.Success ? -1 : by;
            }
            catch
            {
                return -1;
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static int EndReceiveFrom(Socket s, IAsyncResult result, ref EndPoint remoteEP)
        {
            if (SocketExtension.CleanedUp(s))
            {
                return -1;
            }
            try
            {
                return s.EndReceiveFrom(result, ref remoteEP);
            }
            catch
            {
                return -1;
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static bool BeginReceiveFrom(Socket s, byte[] buffer, int ofs, int size, ref EndPoint remoteEP, AsyncCallback callback)
        {
            if (SocketExtension.CleanedUp(s))
            {
                return false;
            }
            try
            {
                s.BeginReceiveFrom(buffer, ofs, size, SocketFlags.None, ref remoteEP, callback, null);
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
        public static bool Receive(Socket s, int size, out byte[] buffer)
        {
            buffer = new byte[size];
            if (!SocketExtension.Receive(s, 0, size, buffer))
            {
                buffer = null;
            }
            return true;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static bool Receive(Socket s, int ofs, int size, byte[] buffer)
        {
            if (SocketExtension.CleanedUp(s))
            {
                return false;
            }
            try
            {
                SocketError error = SocketError.SocketError;
                int cursor = 0;
                while (cursor < size)
                {
                    int by = s.Receive(buffer, ofs + cursor, size - cursor, SocketFlags.None, out error);
                    if (by < 1 || error != SocketError.Success)
                    {
                        return false;
                    }
                    cursor += by;
                }
                if (cursor > 0 && cursor == size && error == SocketError.Success)
                {
                    return true;
                }
                return false;
            }
            catch
            {
                return false;
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static bool SetKeepAliveValues(Socket socket, int intervalTime = ~0, int retransmissionTime = ~0)
        {
            if (SocketExtension.CleanedUp(socket))
            {
                return false;
            }
            if (socket.SocketType != SocketType.Stream)
            {
                return false;
            }
            byte[] inOptionValues = new byte[12];
            byte[] outOptionValues = new byte[12];
            if (intervalTime < 0) // 缺省为每半分钟一次存活探测包
            {
                intervalTime = 30000;
            }
            if (retransmissionTime < 0) // 缺省为在一分钟内没有任何数据交互时则发送存活探测包
            {
                retransmissionTime = 60000;
            }
            fixed (byte* pinned = inOptionValues)
            {
                uint* pdwInOptionValues = (uint*)pinned;
                pdwInOptionValues[0] = 0;
                pdwInOptionValues[1] = (uint)retransmissionTime;
                pdwInOptionValues[2] = (uint)intervalTime;
            }
            try
            {
                int rc = socket.IOControl(IOControlCode.KeepAliveValues, inOptionValues, outOptionValues);
                return rc >= 0;
            }
            catch
            {
                return false;
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static bool SendTo(Socket s, byte[] buffer, int offset, int length, EndPoint destinationEP) =>
            SendTo(s, buffer, offset, length, destinationEP, out int bytesTransferred);

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static bool SendTo(Socket s, byte[] buffer, int offset, int length, EndPoint destinationEP, out int bytesTransferred)
        {
            if (SocketExtension.CleanedUp(s))
            {
                bytesTransferred = -1;
                return false;
            }
            try
            {
                bytesTransferred = s.SendTo(buffer, offset, length, SocketFlags.None, destinationEP);
                return bytesTransferred != -1;
            }
            catch
            {
                bytesTransferred = -1;
                return false;
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static int ReceiveFrom(Socket s, byte[] buffer, int offset, int length, out EndPoint destinationEP)
        {
            destinationEP = null;
            if (SocketExtension.CleanedUp(s))
            {
                return -1;
            }
            int bytesTransferred = -1;
            try
            {
                EndPoint localEP;
                switch (s.AddressFamily)
                {
                    case AddressFamily.InterNetwork:
                        localEP = new IPEndPoint(IPAddress.Any, 0);
                        break;
                    case AddressFamily.InterNetworkV6:
                        localEP = new IPEndPoint(IPAddress.IPv6Any, 0);
                        break;
                    default:
                        return bytesTransferred;
                }
                bytesTransferred = s.ReceiveFrom(buffer, offset, length, SocketFlags.None, ref localEP);
                if (bytesTransferred > 0)
                {
                    destinationEP = localEP;
                }
            }
            catch { }
            return bytesTransferred;
        }

#if AARCH
#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static bool ReceiveFrom(Socket socket, byte[] buffer, int offset, int length, Action<int, EndPoint> callback)
        {
            EndPoint localEP = null;
            switch (socket.AddressFamily)
            {
                case AddressFamily.InterNetwork:
                    localEP = new IPEndPoint(IPAddress.Any, 0);
                    break;
                case AddressFamily.InterNetworkV6:
                    localEP = new IPEndPoint(IPAddress.IPv6Any, 0);
                    break;
                default:
                    return false;
            }
            return SocketExtension.BeginReceiveFrom(socket, buffer, offset, length, ref localEP, (ar) =>
                callback(SocketExtension.EndReceiveFrom(socket, ar, ref localEP), localEP));
        }
#endif
    }
}
