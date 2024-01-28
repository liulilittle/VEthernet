namespace VEthernet.Net
{
    using System;
#if NETCOREAPP
    using System.Runtime.CompilerServices;
#endif

    public sealed class NetworkStatistics : EventArgs
    {
        public class Statistics
        {
            public long OutgoingTrafficSize;
            public long IncomingTrafficSize;
            public long OutgoingUnicastPacket;
            public long IncomingUnicastPacket;

#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            public virtual void Reset()
            {
                this.OutgoingTrafficSize = 0;
                this.IncomingTrafficSize = 0;
                this.OutgoingUnicastPacket = 0;
                this.IncomingUnicastPacket = 0;
            }

#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            public virtual void Copy(Statistics statistics)
            {
                this.OutgoingTrafficSize = statistics.OutgoingTrafficSize;
                this.IncomingTrafficSize = statistics.IncomingTrafficSize;
                this.OutgoingUnicastPacket = statistics.OutgoingUnicastPacket;
                this.IncomingUnicastPacket = statistics.IncomingUnicastPacket;
            }
        }

        public class UdpStatistics : Statistics
        {
            public long ActivityAllPorts;

#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            public override void Copy(Statistics statistics)
            {
                base.Copy(statistics);
                if (statistics is UdpStatistics o)
                {
                    this.ActivityAllPorts = o.ActivityAllPorts;
                }
            }
        }

        public sealed class TcpStatistics : Statistics
        {
            public int ActiveConnections;
            public int ConnectConnections;
            public int DisconnectingConnections;
            public int ClosingConnections;
            public long IncomingTunnelTraffic;
            public long OutgoingTunnelTraffic;

#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            public override void Copy(Statistics statistics)
            {
                base.Copy(statistics);
                if (statistics is TcpStatistics o)
                {
                    this.ActiveConnections = o.ActiveConnections;
                    this.ConnectConnections = o.ConnectConnections;
                    this.DisconnectingConnections = o.DisconnectingConnections;
                    this.ClosingConnections = o.ClosingConnections;
                    this.IncomingTunnelTraffic = o.IncomingTunnelTraffic;
                    this.OutgoingTunnelTraffic = o.OutgoingTunnelTraffic;
                }
            }
        }

        public Statistics IPv4
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            get;
        } = new Statistics();

        public TcpStatistics Tcp
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
            get;
        } = new TcpStatistics();

        public UdpStatistics Udp
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
            get;
        } = new UdpStatistics();

        public Statistics Icmp
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            get;
        } = new Statistics();
    }
}
