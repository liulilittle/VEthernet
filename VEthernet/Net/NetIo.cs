namespace VEthernet.Net
{
    using System;
    using System.Diagnostics;
    using System.Net;
    using System.Net.Sockets;
    using System.Runtime.InteropServices;
    using System.Security;
#if NETCOREAPP
    using System.Runtime.CompilerServices;
#endif

    public unsafe static class NetIo
    {
#if (WIN32 || WIN64)
        private const string DLLNAME = "libnet.dll";
#else
        private const string DLLNAME = "libnet.so";
#endif

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static bool FillEndPoint(IPAddress src, ref __in_addr__ dst)
        {
            if (src == null)
            {
                return false;
            }
            if (src.AddressFamily == AddressFamily.InterNetworkV6)
            {
                fixed (__in_addr__* p = &dst)
                {
                    Marshal.Copy(src.GetAddressBytes(), 0, (IntPtr)(&p->in6), sizeof(__in6_addr__));
                    dst.bv6 = 1;
                }
            }
            else if (src.AddressFamily == AddressFamily.InterNetwork)
            {
                dst.bv6 = 0;
                dst.in4.value = BitConverter.ToUInt32(src.GetAddressBytes(), 0);
            }
            else
            {
                return false;
            }
            return true;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static bool FillEndPoint(IPAddress src, __in_addr__* dst)
        {
            if (dst == null)
            {
                return false;
            }
            return FillEndPoint(src, ref *dst);
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static __in_addr__ ToEndPoint(IPAddress p)
        {
            __in_addr__* in_ = stackalloc __in_addr__[1];
            if (FillEndPoint(p, in_))
            {
                return *in_;
            }
            return default(__in_addr__);
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static IPEndPoint ToEndPoint(__in_addr__* p, int port)
        {
            if (p == null)
            {
                return null;
            }
            if (p->bv6 != 0)
            {
                byte[] buff = new byte[sizeof(__in6_addr__)];
                Marshal.Copy((IntPtr)(&p->in6), buff, 0, buff.Length);

                return new IPEndPoint(new IPAddress(buff), port);
            }
            return new IPEndPoint(new IPAddress(p->in4.value), port);
        }

        [UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public delegate bool libnet_io_protect_fn(
            IntPtr iohost,
            int sockfd,
            __in_addr__* natAddr,
            int natPort,
            __in_addr__* srcAddr,
            int srcPort,
            __in_addr__* dstAddr,
            int dstPort);

        [DllImport(DLLNAME, EntryPoint = "libnet_io_protect", SetLastError = false, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        public static extern bool libnet_io_protect(IntPtr io_host_, [MarshalAs(UnmanagedType.FunctionPtr)] libnet_io_protect_fn protect);

        [DllImport(DLLNAME, EntryPoint = "libnet_get_default_cipher_suites", SetLastError = false, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        private static extern string libnet_get_default_cipher_suites_();

        [SuppressUnmanagedCodeSecurity]
        public static string libnet_get_default_cipher_suites()
        {
            try
            {
                return libnet_get_default_cipher_suites_();
            }
            catch
            {
                return "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256";
            }
        }

        [DllImport(DLLNAME, SetLastError = false, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        public static extern IntPtr libnet_new_io_host(int concurrent_);

        [DllImport(DLLNAME, SetLastError = false, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        public static extern bool libnet_release_io_host(IntPtr io_host);

        [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Ansi)]
        public struct WS_LINK
        {
            public int local_nagle;
            public __in_addr__ local_host;
            public int local_port;
            public int remote_nagle;
            public __in_addr__ remote_host;
            public int remote_port;
            public string path_;
        };

        [DllImport(DLLNAME, SetLastError = false, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        public static extern IntPtr libnet_new_ws_s_host(IntPtr io_host, ref WS_LINK link);

        [DllImport(DLLNAME, SetLastError = false, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        public static extern bool libnet_release_ws_s_host(IntPtr ws_host);

        [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Ansi)]
        public struct WS_CLIENT_LINK
        {
            public int local_nagle;
            public __in_addr__ local_host;
            public int local_port;
            public int remote_nagle;
            public __in_addr__ remote_host;
            public int remote_port;
            public string host_sni;
            public string path_;
        };

        [DllImport(DLLNAME, SetLastError = false, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        public static extern IntPtr libnet_new_ws_c_host(IntPtr io_host, ref WS_CLIENT_LINK link);

        [DllImport(DLLNAME, SetLastError = false, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        public static extern bool libnet_release_ws_c_host(IntPtr ws_host);

        [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Ansi)]
        public struct TLS_CLIENT_LINK
        {
            public int local_nagle;
            public __in_addr__ local_host;
            public int local_port;
            public int remote_nagle;
            public __in_addr__ remote_host;
            public int remote_port;
            public string host_sni;
            public int ssl_method;
            public string ssl_ciphersuites;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Ansi)]
        public struct WSS_CLIENT_LINK
        {
            public TLS_CLIENT_LINK tls_;
            public string path_;
        }

        [DllImport(DLLNAME, SetLastError = false, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        public static extern IntPtr libnet_new_wss_c_host(IntPtr io_host, ref WSS_CLIENT_LINK link);

        [DllImport(DLLNAME, SetLastError = false, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        public static extern bool libnet_release_wss_c_host(IntPtr ws_host);

        [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Ansi)]
        public struct WSS_LINK
        {
            public int local_nagle;
            public __in_addr__ local_host;
            public int local_port;
            public int remote_nagle;
            public __in_addr__ remote_host;
            public int remote_port;
            public string host_sni;
            public string path_;
            public string ssl_cert_file;
            public string ssl_private_cert;
            public string ssl_verity_pass;
            public int ssl_method;
            public string ssl_ciphersuites;
        };

        [DllImport(DLLNAME, SetLastError = false, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        public static extern IntPtr libnet_new_wss_s_host(IntPtr io_host, ref WSS_LINK link);

        [DllImport(DLLNAME, SetLastError = false, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        public static extern bool libnet_release_wss_s_host(IntPtr ws_host);

        [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Ansi)]
        public struct __in6_addr__
        {
            public long low;
            public long high;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Ansi)]
        public struct __in4_addr__
        {
            public uint value;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Ansi)]
        public struct __in_addr__
        {
            public int bv6;
            public __in4_addr__ in4;
            public __in6_addr__ in6;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Ansi)]
        public struct TCP_FORWARD_LINK
        {
            public int local_nagle;
            public __in_addr__ local_host;
            public int local_port;
            public int remote_nagle;
            public __in_addr__ remote_host;
            public int remote_port;
        }

        [DllImport(DLLNAME, SetLastError = false, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        public static extern IntPtr libnet_new_tcp_forward_host(IntPtr io_host, ref TCP_FORWARD_LINK link);

        [DllImport(DLLNAME, SetLastError = false, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        public static extern bool libnet_release_tcp_forward_host(IntPtr tcp_v6tov4_host);

        private static class IoHost
        {
            [DebuggerBrowsable(DebuggerBrowsableState.Never)]
            private static readonly IntPtr _io_host = IntPtr.Zero;

#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            static IoHost()
            {
                int concurrent = Math.Max(4, Environment.ProcessorCount);
                try
                {
                    IoHost._io_host = libnet_new_io_host(concurrent);
                }
                catch
                {
                    IoHost._io_host = IntPtr.Zero;
                }
                IoHost.Concurrent = concurrent;
            }

            public static IntPtr Handle
            {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
                get => _io_host;
            }

            public static int Concurrent
            {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
                get;
            }
        }

        public static IntPtr Handle
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            get => IoHost.Handle;
        }

        public static int Concurrent
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            get => IoHost.Concurrent;
        }
    }
}
