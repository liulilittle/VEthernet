namespace VEthernet.Net.IP
{
    using System;
    using System.Net;
    using System.Net.Sockets;
#if NETCOREAPP
    using System.Runtime.CompilerServices;
#endif
    using System.Runtime.InteropServices;
    using VEthernet.Core;

    public enum IPFlags : ushort
    {
        IP_RF = 0x8000,        /* reserved fragment flag */
        IP_DF = 0x4000,        /* dont fragment flag */
        IP_MF = 0x2000,        /* more fragments flag */
        IP_OFFMASK = 0x1fff,   /* mask for fragmenting bits */
    }

    public unsafe sealed class IPFrame : EventArgs
    {
        public const int DefaultTtl = 64;

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public IPFrame(ProtocolType protocolType, IPAddress source, IPAddress destination, BufferSegment payload)
        {
            this.Destination = destination ?? throw new ArgumentNullException(nameof(destination));
            this.Source = source ?? throw new ArgumentNullException(nameof(source));
            if (source.AddressFamily != destination.AddressFamily)
            {
                throw new ArgumentOutOfRangeException("The original address is inconsistent with the target address protocol.");
            }
            this.Ttl = DefaultTtl;
            this.Tos = IPv4Layer.TOS_ROUTIN_MODE;
            this.Flags = IPFlags.IP_DF;
            this.ProtocolType = protocolType;
            this.Payload = payload ?? throw new ArgumentNullException(nameof(payload));
        }

        public AddressFamily AddressFamily
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            get
            {
                return this.Destination.AddressFamily;
            }
        }

        public object Tag
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

        public ushort Id
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

        public IPFlags Flags
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

        public int FragmentOffset
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            get
            {
                int offset = (ushort)this.Flags;
                offset = ((ushort)(offset << 3)) >> 3;
                offset <<= 3;
                return offset;
            }
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            set
            {
                int flags = (int)this.Flags >> 13;
                flags = flags << 13 | value >> 3;
                this.Flags = (IPFlags)flags;
            }
        }

        public IPAddress Source
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

        public IPAddress Destination
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

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static uint GetAddressV4(IPAddress address)
        {
            if (address == null || address.AddressFamily != AddressFamily.InterNetwork)
            {
                return 0;
            }

            byte[] addressBytes = address.GetAddressBytes();
            fixed (byte* p = addressBytes)
            {
                if (p == null)
                {
                    return 0;
                }

                return *(uint*)p;
            }
        }

        public uint SourceAddressV4
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            get
            {
                return GetAddressV4(this.Source);
            }
        }

        public uint DestinationAddressV4
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            get
            {
                return GetAddressV4(this.Destination);
            }
        }

        public BufferSegment Payload
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            get;
        }

        public BufferSegment Options
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

        public int Ttl
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

        public byte Tos
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

        public ProtocolType ProtocolType
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

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public bool HasFlag(IPFlags flags)
        {
            ushort v = CheckSum.ntohs((ushort)this.Flags);
            return (v & CheckSum.ntohs((ushort)(flags))) != 0;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public override string ToString()
        {
            return string.Format($"{this.Source} -> {this.Destination}");
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static bool Equals(IPAddress x, IPAddress y)
        {
            if (x == null && y == null)
            {
                return true;
            }

            if (x.AddressFamily != y.AddressFamily)
            {
                return false;
            }

            byte[] bx = x.GetAddressBytes();
            byte[] by = y.GetAddressBytes();
            if (bx.Length != by.Length)
            {
                return false;
            }

            fixed (byte* pinnedX = bx)
            {
                fixed (byte* pinnedY = by)
                {
                    if (bx.Length == 4)
                    {
                        return *(uint*)pinnedX == *(uint*)pinnedY; // 32bit
                    }
                    else if (bx.Length == 8)
                    {
                        return *(ulong*)pinnedX == *(ulong*)pinnedY; // 64bit
                    }
                    else if (bx.Length == 16)
                    {
                        return *(decimal*)pinnedX == *(decimal*)pinnedY; // 128bit
                    }
                    else if (bx.Length == 2)
                    {
                        return *(ushort*)pinnedX == *(ushort*)pinnedY; // 16bit
                    }
                    else if (bx.Length == 1)
                    {
                        return *pinnedX == *pinnedY;
                    }
                    else
                    {
                        for (int i = 0; i < bx.Length; ++i)
                        {
                            if (pinnedX[i] != pinnedY[i])
                            {
                                return false;
                            }
                        }
                        return true;
                    }
                }
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static bool Equals(IPEndPoint x, IPEndPoint y)
        {
            if (x == y)
            {
                return true;
            }
            if (IPFrame.Equals(x?.Address, y?.Address))
            {
                return x.Port == y.Port;
            }
            return false;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static IPEndPoint Transform(EndPoint address) => IPFrame.Transform(address, asFarAsPossibleTransform: false);

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static IPEndPoint Transform(EndPoint address, bool asFarAsPossibleTransform)
        {
            IPEndPoint ipep = address as IPEndPoint;
            if (ipep == null)
            {
                return null;
            }
            if (asFarAsPossibleTransform)
            {
                if (IPFrame.Equals(IPAddress.IPv6Any, ipep.Address) ||
                    IPFrame.Equals(IPAddress.IPv6Loopback, ipep.Address))
                {
                    return new IPEndPoint(IPAddress.Loopback, ipep.Port);
                }
            }
            IPEndPoint host = IPFrame.V6ToV4(ipep);
            return host != null ? host : ipep;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static IPEndPoint V6ToV4(IPEndPoint address)
        {
            if (address == null)
            {
                return null;
            }
            IPAddress host = IPFrame.V6ToV4(address.Address);
            if (host == null)
            {
                return null;
            }
            return new IPEndPoint(host, address.Port);
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static IPAddress V6ToV4(IPAddress address)
        {
            if (address == null)
            {
                return null;
            }

            if (address.AddressFamily == AddressFamily.InterNetwork)
            {
                return address;
            }

            byte[] buff = address.GetAddressBytes();
            fixed (byte* chunk = buff)
            {
                IPV62V4ADDR* p = (IPV62V4ADDR*)chunk;
                if (p->R1 != 0 || p->R2 != 0)
                {
                    return null;
                }
                if (p->R3 != ushort.MaxValue)
                {
                    return null;
                }
                return new IPAddress(p->R4);
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static IPEndPoint V4ToV6(IPEndPoint address)
        {
            if (address == null)
            {
                return null;
            }
            IPAddress host = IPFrame.V4ToV6(address.Address);
            if (host == null)
            {
                return null;
            }
            return new IPEndPoint(host, address.Port);
        }

        [StructLayout(LayoutKind.Explicit, Pack = 1, Size = 16)]
        private struct IPV62V4ADDR
        {
            [FieldOffset(0)]
            public long R1;

            [FieldOffset(8)]
            public ushort R2;

            [FieldOffset(10)]
            public ushort R3;

            [FieldOffset(12)]
            public uint R4;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static IPAddress V4ToV6(IPAddress address)
        {
            if (address == null)
            {
                return null;
            }
            if (address.AddressFamily == AddressFamily.InterNetwork)
            {
                byte[] buff = new byte[16];
                fixed (byte* chunk = buff)
                {
                    fixed (byte* v4 = address.GetAddressBytes())
                    {
                        IPV62V4ADDR* p = (IPV62V4ADDR*)chunk;
                        p->R3 = ushort.MaxValue;
                        p->R4 = *(uint*)v4;
                    }
                }
                return new IPAddress(buff);
            }
            return address;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static bool Any(IPEndPoint address)
        {
            if (address == null)
            {
                return false;
            }
            return IPFrame.Any(address.Address);
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static bool Any(IPAddress address)
        {
            if (address == null)
            {
                return false;
            }
            if (IPFrame.Equals(address, IPAddress.Any) ||
                IPFrame.Equals(address, IPAddress.IPv6Any))
            {
                return true;
            }
            if (address.AddressFamily == AddressFamily.InterNetworkV6)
            {
                address = IPFrame.V6ToV4(address);
                if (address != null)
                {
                    return IPFrame.Any(address);
                }
            }
            return false;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static bool Loopback(IPEndPoint address)
        {
            if (address == null)
            {
                return false;
            }
            return IPFrame.Loopback(address.Address);
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static bool Loopback(IPAddress address)
        {
            if (address == null)
            {
                return false;
            }
            if (IPFrame.Equals(address, IPAddress.Loopback) ||
                IPFrame.Equals(address, IPAddress.IPv6Loopback))
            {
                return true;
            }
            if (address.AddressFamily == AddressFamily.InterNetworkV6)
            {
                address = IPFrame.V6ToV4(address);
                if (address != null)
                {
                    return IPFrame.Loopback(address);
                }
            }
            return false;
        }
    }
}
