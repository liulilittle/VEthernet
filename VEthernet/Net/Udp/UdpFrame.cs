namespace VEthernet.Net.Udp
{
    using System;
    using System.Net;
    using System.Net.Sockets;
#if NETCOREAPP
    using System.Runtime.CompilerServices;
#endif
    using VEthernet.Core;
    using VEthernet.Net.IP;

    public class UdpFrame : EventArgs
    {
        public IPEndPoint Source
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

        public IPEndPoint Destination
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
# endif
            get
            {
                return this.Destination.AddressFamily;
            }
        }

        public BufferSegment Payload
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

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public UdpFrame(IPEndPoint source, IPEndPoint destination, BufferSegment payload)
        {
            this.Ttl = IPFrame.DefaultTtl;
            this.Source = source ?? throw new ArgumentNullException(nameof(source));
            this.Destination = destination ?? throw new ArgumentNullException(nameof(Destination));
            if (source.AddressFamily != destination.AddressFamily)
            {
                throw new ArgumentOutOfRangeException("The original address is inconsistent with the target address protocol.");
            }
            this.Payload = payload ?? throw new ArgumentNullException(nameof(payload));
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public UdpFrame Depth()
        {
            return new UdpFrame(this.Source, this.Destination, this.Payload.Depth())
            {
                Ttl = this.Ttl,
            };
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
