namespace VEthernet.Net.Icmp
{
    using System;
    using System.Net;
    using System.Net.Sockets;
#if NETCOREAPP
    using System.Runtime.CompilerServices;
#endif
    using VEthernet.Core;
    using VEthernet.Net.IP;

    public enum IcmpType : byte
    {
        ICMP_ER = 0,        /* echo reply */
        ICMP_DUR = 3,       /* destination unreachable */
        ICMP_SQ = 4,        /* source quench */
        ICMP_RD = 5,        /* redirect */
        ICMP_ECHO = 8,      /* echo */
        ICMP_TE = 11,       /* time exceeded */
        ICMP_PP = 12,       /* parameter problem */
        ICMP_TS = 13,       /* timestamp */
        ICMP_TSR = 14,      /* timestamp reply */
        ICMP_IRQ = 15,      /* information request */
        ICMP_IR = 16,       /* information reply */
        ICMP_AM = 17,       /* address mask request */
        ICMP_AMR = 18,      /* address mask reply */
    }

    public sealed class IcmpFrame : EventArgs
    {
        public IcmpType Type
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

        public byte Code
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
            get;
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            set;
        }

        public ushort Identification
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
            get;
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            set;
        }

        public ushort Sequence
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
            get;
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            set;
        }

        public IPAddress Source
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
            get;
        }

        public IPAddress Destination
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
            get;
        }

        public int Ttl
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
            get;
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            set;
        }

        public AddressFamily AddressFamily
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            get;
        }

        public BufferSegment Payload
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
            get;
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            set;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public IcmpFrame(IPAddress source, IPAddress destination, BufferSegment payload)
        {
            this.Ttl = IPFrame.DefaultTtl;
            this.Payload = payload ?? new BufferSegment(BufferSegment.Empty);
            this.Source = source ?? throw new ArgumentNullException(nameof(source));
            this.Destination = destination ?? throw new ArgumentNullException(nameof(Destination));
            this.AddressFamily = destination.AddressFamily;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public override string ToString()
        {
            return string.Format($"{Source} -> {Destination}");
        }
    }
}
