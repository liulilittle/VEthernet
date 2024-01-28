namespace VEthernet.Net.LwIP
{
    using System;
    using System.Diagnostics;
    using System.Net;
    using System.Runtime.InteropServices;
    using VEthernet.Net.IP;

    public unsafe sealed class Netstack
    {
        public delegate bool OuputEventHandler(byte[] packet, int length);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate bool LIBTCPIP_IPV4_OUTPUT(void* packet, int size);

        [DllImport("libtcpip.dll", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        private static extern bool libtcpip_loopback(int localhost, uint ip, uint gw, uint mask, [MarshalAs(UnmanagedType.FunctionPtr)] LIBTCPIP_IPV4_OUTPUT outputfn);

        [DllImport("libtcpip.dll", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        private static extern bool libtcpip_input(void* packet, int size);

        [DllImport("libtcpip.dll", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        private static extern bool libtcpip_link(int nat, out uint srcAddr, out int srcPort, out uint dstAddr, out int dstPort);

        public static IPAddress LocalAddress => IPAddress.Parse("10.0.0.1");

        public static IPAddress NetworkMask => IPAddress.Parse("255.255.255.255");

        public static IPAddress GatewayAddress => IPAddress.Parse("10.0.0.0");

        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private static readonly LIBTCPIP_IPV4_OUTPUT _OutputfnAgent;
        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private static readonly GCHandle _OutputfnAgentGC;

        public static event OuputEventHandler Ouput = default(OuputEventHandler);

        static Netstack()
        {
            _OutputfnAgent = (void* packet, int length) =>
            {
                OuputEventHandler handler = Netstack.Ouput;
                if (handler == null)
                {
                    return false;
                }

                byte[] frame = new byte[length];
                Marshal.Copy((IntPtr)packet, frame, 0, length);
                return handler(frame, length);
            };
            _OutputfnAgentGC = GCHandle.Alloc(_OutputfnAgent);
        }

        public static bool Loopback(int localhost)
        {
            if (localhost <= IPEndPoint.MinPort || localhost > IPEndPoint.MaxPort)
            {
                return false;
            }
            uint ip = IPFrame.GetAddressV4(LocalAddress);
            uint gw = IPFrame.GetAddressV4(GatewayAddress);
            uint mask = IPFrame.GetAddressV4(NetworkMask);
            libtcpip_loopback(localhost, ip, gw, mask, _OutputfnAgent);
            return true;
        }

        public static bool Link(int localPort, out IPEndPoint source, out IPEndPoint destination)
        {
            destination = null;
            source = null;
            if (localPort <= IPEndPoint.MinPort || localPort > IPEndPoint.MaxPort)
            {
                return false;
            }

            if (!libtcpip_link(localPort, out uint srcAddr, out int srcPort, out uint dstAddr, out int dstPort))
            {
                return false;
            }

            source = new IPEndPoint(new IPAddress(srcAddr), srcPort);
            destination = new IPEndPoint(new IPAddress(dstAddr), dstPort);
            return true;
        }

        public static bool Input(byte[] buffer, int offset, int length)
        {
            if (buffer == null || offset < 0 || length < 1)
            {
                return false;
            }
            int len = buffer.Length - (offset + length);
            if (len < 1)
            {
                return false;
            }
            fixed (byte* p = &buffer[offset])
            {
                return libtcpip_input(p, length);
            }
        }
    }
}
