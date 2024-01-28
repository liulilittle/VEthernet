namespace VEthernet.Net.Tcp
{
    using System.Net;
#if NETCOREAPP
    using System.Runtime.CompilerServices;
#endif
    using VEthernet.Core;
    using VEthernet.Net.Udp;

    public enum TcpState : byte
    {
        CLOSED = 0,
        LISTEN = 1,
        SYN_SENT = 2,
        SYN_RCVD = 3,
        ESTABLISHED = 4,
        FIN_WAIT_1 = 5,
        FIN_WAIT_2 = 6,
        CLOSE_WAIT = 7,
        CLOSING = 8,
        LAST_ACK = 9,
        TIME_WAIT = 10
    }

    public enum TcpFlags
    {
        TCP_FIN = 0x01,
        TCP_SYN = 0x02,
        TCP_RST = 0x04,
        TCP_PSH = 0x08,
        TCP_ACK = 0x10,
        TCP_UGR = 0x20,
        TCP_ECE = 0x40,
        TCP_CWR = 0x80,
        TCP_FLAGS = 0x3f
    }

    public sealed class TcpFrame : UdpFrame
    {
        public new static readonly BufferSegment Empty = new BufferSegment(BufferSegment.Empty);

        public TcpFlags Flags
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

        public uint SequenceNo
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

        public uint AcknowledgeNo
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

        public ushort WindowSize
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

        public BufferSegment Options
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

        public ushort UrgentPointer
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
# endif
        public TcpFrame(IPEndPoint source, IPEndPoint destination, BufferSegment payload) : base(source, destination, payload)
        {

        }
    }
}
