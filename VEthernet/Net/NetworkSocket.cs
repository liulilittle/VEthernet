namespace VEthernet.Net
{
    using System.Diagnostics;
    using System.Net.Sockets;
    using System.Threading;
#if NETCOREAPP
    using System.Runtime.CompilerServices;
#endif

    public sealed class NetworkSocket : Socket
    {
        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private int m_IntCleanedUp = 0;

        public bool CleanedUp
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            get => Interlocked.CompareExchange(ref this.m_IntCleanedUp, 0, 0) != 0;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public NetworkSocket(AddressFamily addressFamily, SocketType socketType, ProtocolType protocolType) : base(addressFamily, socketType, protocolType)
        {

        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        protected override void Dispose(bool disposing)
        {
            if (disposing && !this.CleanedUp)
            {
                base.Dispose(disposing);
            }
        }
    }
}
