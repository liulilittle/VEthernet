namespace VEthernet.Net
{
    using System;
    using System.Collections;
    using System.Collections.Concurrent;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.IO;
    using System.Linq;
    using System.Net;
    using System.Net.NetworkInformation;
    using System.Net.Sockets;
    using System.Runtime.InteropServices;
    using System.Threading;
    using VEthernet.Core;
    using VEthernet.Net.Auxiliary;
    using VEthernet.Net.Icmp;
    using VEthernet.Net.IP;
    using VEthernet.Net.LwIP;
    using VEthernet.Net.Tcp;
    using VEthernet.Net.Tun;
    using VEthernet.Net.Udp;
    using SOCKET = System.Net.Sockets.Socket;
    using TcpState = VEthernet.Net.Tcp.TcpState;
    using Timer = VEthernet.Threading.Timer;

    [TypeLibType(TypeLibTypeFlags.FHidden | TypeLibTypeFlags.FRestricted)]
    public unsafe class TapTap2Socket : IDisposable, IEnumerable<IConnection>
    {
        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private readonly IDictionary<string, TapTcpLink> privateLinkTable = new ConcurrentDictionary<string, TapTcpLink>();
        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private readonly IDictionary<int, TapTcpLink> publicLinkTable = new ConcurrentDictionary<int, TapTcpLink>();
        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private readonly IDictionary<string, Subpackage> subpackageTable = new ConcurrentDictionary<string, Subpackage>();

        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private volatile int aport = new global::VEthernet.Utilits.Random(Environment.TickCount).Next(1000, ushort.MaxValue);
        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private readonly Timer ticktmr = new Timer();
        private readonly object syncobj = new object();
        private bool checksum = false;
        private SOCKET loopback = null;
        private readonly NetworkStatistics networkStatistics = null;

        public const int MaxFinalTime = 5 * 1000;
        public const int MaxSynalTime = 20 * 1000;
        private const int MaxAllocPortCount = IPEndPoint.MaxPort;

        [TypeLibType(TypeLibTypeFlags.FHidden | TypeLibTypeFlags.FRestricted)]
        internal sealed class TapTcpLink : IDisposable, IConnection
        {
            public IPEndPoint Destination = null;
            public IPEndPoint Source = null;
            public IPEndPoint VirtualAddress = null;
            public IPFrame Connecting = null;
            public TapTcpClient Socket = null;
            public uint LocalSequenceNo = 0;
            public uint VirtualSequenceNo = 0;
            public Stopwatch ElapsedTime = new Stopwatch();

            public bool Syn { get; set; } = false; // SYN

            public bool Fin { get; set; } = false; // RST/FIN

            public TcpState LocalState { get; set; } = TcpState.CLOSED;

            public TcpState VirtualState { get; set; } = TcpState.CLOSED;

            public ConnectionState State
            {
                get
                {
                    bool lFin = unchecked(this.LocalState == TcpState.CLOSED || this.LocalState >= TcpState.LAST_ACK);
                    bool vFin = unchecked(this.VirtualState == TcpState.CLOSED || this.VirtualState >= TcpState.LAST_ACK);
                    bool rFin = unchecked(this.Fin || lFin || vFin);
                    if (this.Syn && !rFin)
                    {
                        return ConnectionState.Connection;
                    }
                    else if (rFin)
                    {
                        if (vFin && lFin)
                        {
                            return ConnectionState.Closed;
                        }
                        return ConnectionState.Disconnecting;
                    }
                    return ConnectionState.Connected;
                }
            }

            EndPoint IConnection.Source => this.Source;

            EndPoint IConnection.Destination => this.Destination;

            public TapTcpLink() => this.RestartWatch();

            public TapTcpLink RestartWatch()
            {
                Stopwatch stopwatch = this.ElapsedTime;
                if (stopwatch != null)
                {
                    stopwatch.Restart();
                }
                return this;
            }

            ~TapTcpLink() => this.Dispose();

            public TapTcpLink Activity()
            {
                if (!this.Fin && !this.Syn)
                {
                    this.RestartWatch();
                }
                return this;
            }

            public void Dispose()
            {
                using (TapTcpClient socket = Interlocked.Exchange(ref this.Socket, null))
                {
                    socket?.Abort();
                }
                this.Destination = null;
                this.Source = null;
                this.VirtualAddress = null;
                this.Syn = false;
                this.Fin = false;
                this.Connecting = null;
                Interlocked.Exchange(ref this.ElapsedTime, null);
                GC.SuppressFinalize(this);
            }

            public override string ToString()
            {
                return $"{this.Source} -> {this.Destination}";
            }
        }

        [TypeLibType(TypeLibTypeFlags.FHidden | TypeLibTypeFlags.FRestricted)]
        public class TapTcpClient : IDisposable
        {
            private readonly AsyncCallback _recvAc = null;
            private readonly AsyncCallback _sendAc = null;
            private TapTap2Socket _tap = null;
            private SOCKET _socket = null;
            private int _aborting = 0;
            internal TapTcpLink _link = null;
            private byte[] _buffer = null;
            private readonly IPEndPoint _remoteEP = null;
            private readonly IPEndPoint _localEP = null;

            public virtual IPEndPoint RemoteEndPoint => this._remoteEP;

            public virtual IPEndPoint LocalEndPoint => this._localEP;

            public virtual IPEndPoint SourceEndPoint => this._link?.Source;

            public virtual TapTap2Socket Tap => this._tap;

            public bool IsAbort => Interlocked.CompareExchange(ref this._aborting, 0, 0) != 0;

            public bool IsAccept { get; private set; }

            public virtual bool Connected { get; private set; }

            protected virtual int MSS => SocketExtension.MSS;

            protected virtual bool NoDelay
            {
                get
                {
                    TapTap2Socket tap = this._tap;
                    if (tap == null)
                    {
                        return false;
                    }
                    return tap.NoDelay;
                }
            }

            public TapTcpClient(TapTap2Socket tap, IPEndPoint localEP, IPEndPoint remoteEP)
            {
                this._localEP = localEP ?? throw new ArgumentNullException(nameof(localEP));
                this._remoteEP = remoteEP ?? throw new ArgumentNullException(nameof(remoteEP));
                this._tap = tap ?? throw new ArgumentNullException(nameof(tap));
                this._recvAc = this.ProcessRecv;
                this._sendAc = this.ProcessSend;
            }

            ~TapTcpClient() => this.Dispose();

            private void ProcessSend(IAsyncResult ar)
            {
                bool success = SocketExtension.EndSend(this._socket, ar);
                {
                    if (ar.AsyncState is Action<bool> ok)
                    {
                        ok(success);
                    }
                }
                if (!success)
                {
                    this.CloseOrAbort();
                }
            }

            private void ProcessRecv(IAsyncResult ar)
            {
                if (ar == null)
                {
                    bool aborting = true;
                    do
                    {
                        AsyncCallback recv = this._recvAc;
                        if (recv == null)
                        {
                            break;
                        }

                        byte[] buffer = this._buffer;
                        if (buffer == null)
                        {
                            break;
                        }

                        if (SocketExtension.BeginReceive(this._socket, buffer, 0, buffer.Length, recv))
                        {
                            aborting = false;
                        }
                    } while (false);
                    if (aborting)
                    {
                        this.CloseOrAbort();
                    }
                }
                else
                {
                    int length = SocketExtension.EndReceive(this._socket, ar);
                    if (length < 1)
                    {
                        this.CloseOrAbort();
                    }
                    else
                    {
                        byte[] buffer = this._buffer;
                        if (buffer == null)
                        {
                            this.CloseOrAbort();
                        }
                        else
                        {
                            BufferSegment message = null;
                            try
                            {
                                message = new BufferSegment(buffer, 0, length);
                                this.OnMessage(message);
                            }
                            catch
                            {
                                this.CloseOrAbort();
                            }
                        }
                    }
                }
            }

            internal void CloseOrAbort(bool aborting = true)
            {
                SocketExtension.Closesocket(Interlocked.Exchange(ref this._socket, null));
                this._tap = null;
                TapTcpLink link = this._link;
                if (link != null)
                {
                    link.Activity();
                    link.Socket = null;
                    link.Connecting = null;
                    link.Fin = true;
                    this._link = null;
                }
                this.Connected = false;
                if (Interlocked.CompareExchange(ref this._aborting, 1, 0) == 0)
                {
                    if (aborting)
                    {
                        this.OnAbort(EventArgs.Empty);
                    }
                    else
                    {
                        this.OnClose(EventArgs.Empty);
                    }
                    this.Dispose();
                }
            }

            public virtual void Abort()
            {
                this.CloseOrAbort(true);
                this.Dispose();
            }

            public virtual void Close() => this.Dispose();

            internal bool ProcessEndAccept(SOCKET socket)
            {
                if (socket == null)
                {
                    return false;
                }
                else
                {
                    try
                    {
                        socket.NoDelay = this.NoDelay;
                        socket.SetTypeOfService();
                    }
                    catch
                    {
                        return false;
                    }
                }
                if (this.IsAbort)
                {
                    return false;
                }
                else
                {
                    this._socket = socket;
                }
                TapTcpLink link = this._link;
                if (link != null)
                {
                    link.Connecting = null;
                    link.LocalState = TcpState.ESTABLISHED;
                    link.VirtualState = TcpState.ESTABLISHED;
                }
                this.EndAccept();
                return true;
            }

            protected virtual void OnMessage(BufferSegment message)
            {
                this.PullListener();
            }

            protected virtual void OnAbort(EventArgs e)
            {

            }

            protected virtual void OnClose(EventArgs e)
            {

            }

            public virtual bool Send(BufferSegment message, Action<bool> ok = null)
            {
                if (message == null || message.Length < 1)
                {
                    return true;
                }
                SOCKET s = this._socket;
                if (SocketExtension.CleanedUp(s))
                {
                    this.CloseOrAbort();
                    return false;
                }
                AsyncCallback sendAc = this._sendAc;
                if (sendAc == null)
                {
                    return false;
                }
                try
                {
                    s.BeginSend(message.Buffer,
                        message.Offset,
                        message.Length,
                        SocketFlags.None,
                        out SocketError error,
                        sendAc,
                        ok);
                    if (error != SocketError.Success && error != SocketError.IOPending)
                    {
                        this.CloseOrAbort();
                        return false;
                    }
                    return true;
                }
                catch
                {
                    this.CloseOrAbort();
                    return false;
                }
            }

            public virtual void EndAccept()
            {
                this.Connected = this.PullListener();
            }

            protected virtual bool PullListener()
            {
                AsyncCallback recv = this._recvAc;
                if (recv != null)
                {
                    recv(null);
                    return true;
                }
                return false;
            }

            public virtual void Dispose()
            {
                this.CloseOrAbort(false);
                GC.SuppressFinalize(this);
            }

            public virtual void BeginAccept()
            {
                IPFrame packet = null;
                if (this.IsAbort)
                {
                    this.CloseOrAbort();
                    return;
                }
                TapTcpLink link = this._link;
                if (link != null)
                {
                    packet = link.Connecting;
                    link.Connecting = null;
                    link.VirtualState = TcpState.SYN_SENT;
                }
                this.IsAccept = true;
                this._buffer = new byte[this.MSS];
                if (packet != null)
                {
                    this._tap?.Output(packet);
                }
            }
        }

        public event EventHandler Tick = default(EventHandler);

        public virtual Tap Tap { get; }

        protected virtual bool ValidateChecksum
        {
            get
            {
                Tap tap = this.Tap;
                if (tap != null)
                {
                    return tap.ValidateChecksum;
                }
                return this.checksum;
            }
            set
            {
                Tap tap = this.Tap;
                if (tap != null)
                {
                    tap.ValidateChecksum = value;
                }
                this.checksum = value;
            }
        }

        protected virtual IPEndPoint LocalEndPoint { get; private set; }

        protected virtual int MaxInactivityTime => 300000;

        protected virtual bool NoDelay => true;

        protected virtual bool Subnetstack { get; private set; }

        public TapTap2Socket(bool subnetstack, int port, NetworkStatistics networkStatistics)
        {
            try
            {
                if (port < IPEndPoint.MinPort || port > IPEndPoint.MaxPort)
                {
                    throw new ArgumentOutOfRangeException(nameof(port));
                }
                if (networkStatistics == null)
                {
                    networkStatistics = new NetworkStatistics();
                }
                this.Subnetstack = subnetstack;
                this.networkStatistics = networkStatistics;
                try
                {
                    this.loopback = new NetworkSocket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                    this.loopback.SetFastOpen();
                    this.loopback.SetTypeOfService();
                    this.loopback.EnableReuseAddress();
                    if (this.Subnetstack)
                    {
                        this.loopback.Bind(new IPEndPoint(IPAddress.Loopback, port));
                    }
                    else
                    {
                        this.loopback.Bind(new IPEndPoint(IPAddress.Any, port));
                    }
                }
                finally
                {
                    this.Tap = new Tap(componentId: Tap.FindAllComponentId().FirstOrDefault());
                    this.Tap.ValidateChecksum = this.checksum;
                    this.Tap.Input += (sender, e) => this.ProcessInput(e);
                    this.ticktmr.Interval = 1000;
                    this.ticktmr.Tick += (sender, e) =>
                    {
                        this.ProcessTickAlways();
                        this.ProcessTickSubpackage();
                        this.OnTick(EventArgs.Empty);
                    };
                }
                if (IPEndPoint.MinPort != port)
                {
                    this.LocalEndPoint = new IPEndPoint(this.Tap.LocalAddress, port);
                }
                else
                {
                    this.LocalEndPoint = new IPEndPoint(this.Tap.LocalAddress, ((IPEndPoint)this.loopback.LocalEndPoint).Port);
                }
                if (this.Subnetstack)
                {
                    Netstack.Loopback(this.LocalEndPoint.Port);
                }
                Netstack.Ouput += this.SunetstackOutput;
            }
            catch (SocketException e)
            {
                this.Dispose();
                throw e;
            }
            catch (Exception e)
            {
                this.Dispose();
                throw e;
            }
#pragma warning disable CS1058 // A previous catch clause already catches all exceptions
            catch
#pragma warning restore CS1058 // A previous catch clause already catches all exceptions
            {
                this.Dispose();
                throw new SystemException("Unable to run the VEthernet-Framework on your computer.");
            }
        }

        private bool SunetstackOutput(byte[] packet, int length)
        {
            if (packet == null || length < 1 || packet.Length < length)
            {
                return false;
            }
            Tap tap = this.Tap;
            if (tap == null)
            {
                return false;
            }
            if (!tap.Output(new BufferSegment(packet, length)))
            {
                return false;
            }
            fixed (byte* p = packet)
            {
                IPv4Layer.ip_hdr* iphdr = (IPv4Layer.ip_hdr*)p;
                int iphdr_hlen = IPv4Layer.ip_hdr.IPH_HL(iphdr) << 2; // IPH_HL_BYTES
                int ip_proto = IPv4Layer.ip_hdr.IPH_PROTO(iphdr);
                switch (ip_proto)
                {
                    case IPv4Layer.IP_PROTO_TCP:
                        {
                            var tcp_stat = this.networkStatistics.Tcp;
                            tcp_stat.IncomingUnicastPacket++;
                            tcp_stat.IncomingTrafficSize += Math.Max(0, length - iphdr_hlen);
                            break;
                        }
                    case IPv4Layer.IP_PROTO_UDP:
                        {
                            var udp_stat = this.networkStatistics.Udp;
                            udp_stat.IncomingUnicastPacket++;
                            udp_stat.IncomingTrafficSize += Math.Max(0, length - iphdr_hlen);
                            break;
                        }
                    case IPv4Layer.IP_PROTO_ICMP:
                        {
                            var icmp_stat = this.networkStatistics.Icmp;
                            icmp_stat.IncomingUnicastPacket++;
                            icmp_stat.IncomingTrafficSize += Math.Max(0, length - iphdr_hlen);
                            break;
                        }
                };
                var ip_stat = this.networkStatistics.IPv4;
                ip_stat.IncomingUnicastPacket++;
                ip_stat.IncomingTrafficSize += length;
            }
            return true;
        }

        ~TapTap2Socket() => this.Dispose();

        protected internal virtual NetworkStatistics GetNetworkStatisticsReferences() => this.networkStatistics;

        public virtual NetworkStatistics GetNetworkStatistics()
        {
            NetworkStatistics right = this.GetNetworkStatisticsReferences();
            NetworkStatistics left = new NetworkStatistics();
            left.IPv4.Copy(right.IPv4);
            left.Tcp.Copy(right.Tcp);
            left.Udp.Copy(right.Udp);
            left.Icmp.Copy(right.Icmp);
            return left;
        }

        public virtual int GetActiveConnectionCount()
        {
            int x = this.publicLinkTable?.Count ?? 0;
            int y = this.privateLinkTable?.Count ?? 0;
            return Math.Min(x, y);
        }

        protected virtual bool ProcessTickSubpackage()
        {
            IEnumerable<KeyValuePair<string, Subpackage>> shadowsSubpackageTable = null;
            lock (this.syncobj)
            {
                shadowsSubpackageTable = this.subpackageTable.ToList();
            }
            if (shadowsSubpackageTable == null)
            {
                return false;
            }
            int tick = Environment.TickCount;
            foreach (var kv in shadowsSubpackageTable)
            {
                Subpackage subpackage = kv.Value;
                if (tick >= subpackage.FinalizeTime || // 滴答时间是否发生数值溢出的现象？
                    (subpackage.FinalizeTime > Subpackage.MaxFinalizeTime && tick <= Subpackage.MaxFinalizeTime))
                {
                    lock (this.syncobj)
                    {
                        this.subpackageTable.Remove(kv.Key);
                    }
                }
            }
            return true;
        }

        protected virtual bool ProcessTickAlways()
        {
            IEnumerable<KeyValuePair<int, TapTcpLink>> shadowsLinkTable = null;
            lock (this.syncobj)
            {
                shadowsLinkTable = this.publicLinkTable.ToList();
            }
            ResetTcpStatistics(this.networkStatistics.Tcp);
            if (shadowsLinkTable == null)
            {
                return false;
            }
            int maxInactivityTime = this.MaxInactivityTime;
            foreach (var kv in shadowsLinkTable)
            {
                TapTcpLink link = kv.Value;
                if (link == null)
                {
                    lock (this.syncobj)
                    {
                        this.publicLinkTable.Remove(kv.Key, out link);
                    }
                    if (link == null)
                    {
                        continue;
                    }
                }
                Stopwatch elapsedWatchTime = link.ElapsedTime;
                ConnectionState connectionState = link.State;
                switch (connectionState)
                {
                    case ConnectionState.Connected:
                        if (elapsedWatchTime == null ||
                            elapsedWatchTime.ElapsedMilliseconds >= maxInactivityTime)
                        {
                            connectionState = ConnectionState.Disconnecting;
                            goto case ConnectionState.Disconnecting;
                        }
                        else
                        {
                            TapTcpClient socket = link.Socket;
                            if (socket != null && socket.Connected)
                            {
                                this.networkStatistics.Tcp.ActiveConnections++;
                            }
                            else
                            {
                                this.networkStatistics.Tcp.ConnectConnections++;
                            }
                        }
                        break;
                    case ConnectionState.Connection:
                        this.networkStatistics.Tcp.ConnectConnections++;
                        break;
                    case ConnectionState.Disconnecting:
                        this.networkStatistics.Tcp.DisconnectingConnections++;
                        if (this.Subnetstack)
                        {
                            connectionState = ConnectionState.Closed;
                            goto case ConnectionState.Closed;
                        }
                        break;
                    case ConnectionState.Closed:
                        this.networkStatistics.Tcp.ClosingConnections++;
                        break;
                };
                if (connectionState == ConnectionState.Connection)
                {
                    if (elapsedWatchTime != null)
                    {
                        long synTime = elapsedWatchTime.ElapsedMilliseconds;
                        if (synTime < MaxSynalTime)
                        {
                            continue;
                        }
                    }
                }
                else if (connectionState == ConnectionState.Closed || connectionState == ConnectionState.Disconnecting)
                {
                    link.Connecting = null;
                    using (TapTcpClient socket = link.Socket)
                    {
                        if (socket != null)
                        {
                            link.Socket = null;
                            socket.CloseOrAbort();
                        }
                    }
                    if (connectionState == ConnectionState.Closed)
                    {
                        goto closeTcpLink;
                    }
                    if (elapsedWatchTime != null)
                    {
                        long finalTime = elapsedWatchTime.ElapsedMilliseconds;
                        if (finalTime < MaxFinalTime)
                        {
                            continue;
                        }
                    }
                }
                else
                {
                    continue;
                }
            closeTcpLink:
                this.CloseTcpLink(link.Source, link.Destination);
            }
            return true;
        }

        [TypeLibType(TypeLibTypeFlags.FHidden | TypeLibTypeFlags.FRestricted)]
        private sealed class Subpackage
        {
            public const int MaxFinalizeTime = 1000;

            public int FinalizeTime { get; } = Environment.TickCount + MaxFinalizeTime;

            public IList<IPFrame> Frames { get; } = new List<IPFrame>();
        }

        protected virtual bool ProcessSubpackage(IPFrame packet)
        {
            if ((packet.Flags & IPFlags.IP_MF) != 0 ||
                ((packet.Flags & IPFlags.IP_OFFMASK) != 0 && packet.FragmentOffset > 0))
            {
                if (packet.Payload.Length < 1)
                {
                    return false;
                }
                packet = new IPFrame(packet.ProtocolType,
                    packet.Source,
                    packet.Destination,
                    packet.Payload.Depth())
                {
                    FragmentOffset = packet.FragmentOffset,
                    Flags = packet.Flags,
                    Id = packet.Id,
                    Options = packet.Options,
                    Tos = packet.Tos,
                    Ttl = packet.Ttl,
                };
                Subpackage subpackage;
                string key = $"{packet}/{packet.Id}";
                lock (this.syncobj)
                {
                    this.subpackageTable.TryGetValue(key, out subpackage);
                    if (subpackage == null)
                    {
                        subpackage = new Subpackage();
                        this.subpackageTable[key] = subpackage;
                    }
                }
                IList<IPFrame> frames = subpackage.Frames;
                int index = frames.Count;
                {
                    while (index > 0)
                    {
                        IPFrame left = frames[index - 1];
                        if (packet.FragmentOffset >= left.FragmentOffset)
                        {
                            break;
                        }
                        else
                        {
                            index--;
                        }
                    }
                    frames.Insert(index, packet);
                }
                int nextFragementOffset = 0;
                bool fullFragementOffset = true;
                {
                    int count = frames.Count;
                    for (index = 0; index < count; index++)
                    {
                        IPFrame left = frames[index];
                        if (left.FragmentOffset != nextFragementOffset)
                        {
                            fullFragementOffset = false;
                            break;
                        }
                        nextFragementOffset = left.FragmentOffset + left.Payload.Length;
                    }
                    if (fullFragementOffset)
                    {
                        IPFrame left = frames[frames.Count - 1];
                        if ((packet.Flags & IPFlags.IP_MF) == 0 &&
                            (packet.Flags & IPFlags.IP_OFFMASK) != 0 && left.FragmentOffset > 0)
                        {
                            left = unchecked(frames[0]);
                            lock (this.syncobj)
                            {
                                this.subpackageTable.Remove(key);
                            }
                            byte[] buffer = new byte[nextFragementOffset];
                            using (MemoryStream ms = new MemoryStream(buffer, true))
                            {
                                for (index = 0, count = frames.Count; index < count; index++)
                                {
                                    var payload = frames[index].Payload;
                                    ms.Write(payload.Buffer, payload.Offset, payload.Length);
                                }
                            }
                            IPFrame originNew = new IPFrame(left.ProtocolType,
                                left.Source,
                                left.Destination,
                                new BufferSegment(buffer))
                            {
                                Id = left.Id,
                                Options = left.Options,
                                Tos = left.Tos,
                                Ttl = left.Ttl,
                                Flags = IPFlags.IP_DF,
                                FragmentOffset = 0,
                            };
                            this.ProcessInput(packet: originNew);
                        }
                    }
                }
                return true;
            }
            else
            {
                return false;
            }
        }

        protected virtual void ProcessInput(IPFrame packet)
        {
            if (packet.ProtocolType == ProtocolType.Tcp)
            {
                if (this.Subnetstack)
                {
                    this.SunetstackInput(packet);
                    return;
                }
                TcpFrame frame = TcpLayer.ParseFrame(packet, this.ValidateChecksum);
                if (frame != null)
                {
                    if (!this.ProcessTcpInput(packet, frame))
                    {
                        this.RST(frame);
                    }
                }
            }
            else if (packet.ProtocolType == ProtocolType.Udp)
            {
                if (!this.ProcessSubpackage(packet))
                {
                    UdpFrame frame = UdpLayer.ParseFrame(packet, this.ValidateChecksum);
                    if (frame != null)
                    {
                        this.ProcessUdpInput(packet, frame);
                    }
                }
            }
            else if (packet.ProtocolType == ProtocolType.Icmp)
            {
                if (!this.ProcessSubpackage(packet))
                {
                    IcmpFrame frame = IcmpLayer.ParseFrame(packet, this.ValidateChecksum);
                    if (frame != null)
                    {
                        this.ProcessIcmpInput(packet, frame);
                    }
                }
            }
        }

        private bool SunetstackInput(IPFrame packet)
        {
            BufferSegment frame = packet.Tag as BufferSegment;
            if (frame == null)
            {
                return false;
            }
            if (!Netstack.Input(frame.Buffer, frame.Offset, frame.Length))
            {
                return false;
            }
            fixed (byte* p = &frame.Buffer[frame.Offset])
            {
                IPv4Layer.ip_hdr* iphdr = (IPv4Layer.ip_hdr*)p;
                int iphdr_hlen = IPv4Layer.ip_hdr.IPH_HL(iphdr) << 2;
                int ip_proto = IPv4Layer.ip_hdr.IPH_PROTO(iphdr);
                switch (ip_proto)
                {
                    case IPv4Layer.IP_PROTO_TCP:
                        {
                            var tcp_stat = this.networkStatistics.Tcp;
                            tcp_stat.OutgoingUnicastPacket++;
                            tcp_stat.OutgoingTrafficSize += Math.Max(0, frame.Length - iphdr_hlen);
                            break;
                        }
                    case IPv4Layer.IP_PROTO_UDP:
                        {
                            var udp_stat = this.networkStatistics.Udp;
                            udp_stat.OutgoingUnicastPacket++;
                            udp_stat.OutgoingTrafficSize += Math.Max(0, frame.Length - iphdr_hlen);
                            break;
                        }
                    case IPv4Layer.IP_PROTO_ICMP:
                        {
                            var icmp_stat = this.networkStatistics.Icmp;
                            icmp_stat.OutgoingUnicastPacket++;
                            icmp_stat.OutgoingTrafficSize += Math.Max(0, frame.Length - iphdr_hlen);
                            break;
                        }
                };
                var ip_stat = this.networkStatistics.IPv4;
                ip_stat.OutgoingUnicastPacket++;
                ip_stat.OutgoingTrafficSize += frame.Length;
            }
            return true;
        }

        public virtual void Listen()
        {
            Exception exception = null;
            lock (this.syncobj)
            {
                try
                {
                    if (this.loopback == null)
                    {
                        throw new InvalidOperationException();
                    }
                    this.loopback.NoDelay = this.NoDelay;
                    SocketExtension.Listen(this.loopback, SocketExtension.Backlog);
                    this.ticktmr.Start();
                    this.Tap.Listen();
                    Thread t = new Thread(this.AcceptLinkWorkThread);
                    t.IsBackground = true;
                    t.Priority = ThreadPriority.Lowest;
                    t.Start();
                }
                catch (Exception innerException)
                {
                    exception = innerException;
                }
            }
            if (exception != null)
            {
                throw exception;
            }
        }

        private static void ResetTcpStatistics(NetworkStatistics.TcpStatistics statistics)
        {
            if (statistics != null)
            {
                statistics.ActiveConnections = 0;
                statistics.ClosingConnections = 0;
                statistics.ConnectConnections = 0;
                statistics.DisconnectingConnections = 0;
            }
        }

        protected virtual void OnTick(EventArgs e)
        {
            EventHandler events = this.Tick;
            if (events != null)
            {
                events(this, e);
            }
        }

        private bool CloseTcpLink(IPEndPoint source, IPEndPoint destination)
        {
            if (source == null || destination == null)
            {
                return false;
            }
            string key = GetPrivateLinkKey(source, destination);
            lock (this.syncobj)
            {
                TapTcpLink link = null;
                if (IPFrame.Equals(destination.Address, this.Tap.GatewayAddress))
                {
                    this.publicLinkTable.Remove(destination.Port, out link);
                    if (link != null)
                    {
                        string rkey = GetPrivateLinkKey(link.Source, link.Destination);
                        this.privateLinkTable.Remove(rkey, out TapTcpLink l1);
                    }
                }
                else
                {
                    this.privateLinkTable.Remove(key, out link);
                    if (link != null)
                    {
                        this.publicLinkTable.Remove(link.VirtualAddress.Port, out TapTcpLink l1);
                    }
                }
                if (link == null)
                {
                    return false;
                }
                TapTcpClient socket = link.Socket;
                if (socket != null)
                {
                    socket.CloseOrAbort();
                    socket.Dispose();
                    link.Socket = null;
                }
            }
            return true;
        }

        private bool RST(TcpFrame packet)
        {
            if (packet == null)
            {
                return false;
            }
            else
            {
                bool closeTcpLink = this.CloseTcpLink(packet.Source, packet.Destination);
                if (0 != (packet.Flags & TcpFlags.TCP_RST))
                {
                    return closeTcpLink;
                }
            }
            uint tcplen = 0;
            BufferSegment payload = packet.Payload;
            if (payload != null)
            {
                tcplen = (uint)payload.Length;
            }
            if ((packet.Flags & (TcpFlags.TCP_FIN | TcpFlags.TCP_SYN)) != 0)
            {
                tcplen++;
            }
            IPFrame frame = TcpLayer.ToIPFrame(new TcpFrame(packet.Destination, packet.Source, BufferSegment.Empty)
            {
                Ttl = packet.Ttl,
                SequenceNo = packet.AcknowledgeNo,
                AcknowledgeNo = packet.SequenceNo + tcplen,
                WindowSize = packet.WindowSize,
                Flags = TcpFlags.TCP_RST | TcpFlags.TCP_ACK,
                UrgentPointer = 0,
                Options = BufferSegment.Empty
            });
            if (frame == null)
            {
                return false;
            }
            this.Output(frame);
            return true;
        }

        private static string GetPrivateLinkKey(IPEndPoint source, IPEndPoint destination)
        {
            if (source == null || destination == null)
            {
                return null;
            }
            return $"{source} -> {destination}";
        }

        private int AllocPort()
        {
            int port = 0;
            do
            {
                port = Interlocked.Increment(ref this.aport);
                if (port <= IPEndPoint.MinPort || port >= IPEndPoint.MaxPort)
                {
                    Interlocked.Exchange(ref this.aport, IPEndPoint.MinPort);
                }
                else
                {
                    break;
                }
            } while (true);
            return port;
        }

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

        private TapTcpLink AllocTcpLink(IPEndPoint source, IPEndPoint destination)
        {
            if (source == null || destination == null)
            {
                return null;
            }
            TcpConnectionInformation[] activeTcpConnections = null;
            try
            {
                activeTcpConnections = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections();
            }
            catch { }
            string key = GetPrivateLinkKey(source, destination);
            if (string.IsNullOrEmpty(key))
            {
                return null;
            }
            TapTcpLink link = null;
            lock (this.syncobj)
            {
                this.privateLinkTable.TryGetValue(key, out link);
                if (link == null)
                {
                    int port = 0;
                    for (int i = 0; i < MaxAllocPortCount; i++)
                    {
                        port = this.AllocPort();
                        if (this.publicLinkTable.ContainsKey(port))
                        {
                            continue;
                        }
                        if (activeTcpConnections != null)
                        {
                            TcpConnectionInformation connection = activeTcpConnections.FirstOrDefault(tci =>
                            {
                                if (tci == null)
                                {
                                    return false;
                                }
                                IPEndPoint remoteEP = tci.RemoteEndPoint;
                                if (remoteEP == null)
                                {
                                    return false;
                                }
                                if (!IPFrame.Equals(remoteEP.Address, this.Tap.GatewayAddress))
                                {
                                    return false;
                                }
                                return port == remoteEP.Port;
                            });
                            if (connection != null)
                            {
                                continue;
                            }
                        }
                        link = new TapTcpLink()
                        {
                            Destination = destination,
                            Source = source,
                            Syn = true,
                            Fin = false,
                            LocalState = TcpState.SYN_RCVD,
                            VirtualAddress = new IPEndPoint(this.Tap.GatewayAddress, port),
                        };
                        this.privateLinkTable[key] = link;
                        this.publicLinkTable[port] = link;
                        break;
                    }
                }
            }
            if (link == null)
            {
                return null;
            }
            return link.Activity();
        }

        protected virtual void Output(IPFrame packet)
        {
            do
            {
                if (packet == null)
                {
                    break;
                }
                Tap tap = this.Tap;
                if (tap == null)
                {
                    break;
                }
                foreach (IPFrame frame in IPv4Layer.Subpackages(packet))
                {
                    BufferSegment messages = null;
                    if (packet.Payload.Buffer != this.Tap.Buffer)
                    {
                        messages = IPv4Layer.ToArray(frame);
                    }
                    else
                    {
                        messages = IPv4Layer.ReassemblyHeader(frame);
                    }
                    if (messages == null)
                    {
                        continue;
                    }
                    if (!tap.Output(messages))
                    {
                        continue;
                    }
                    switch (frame.ProtocolType)
                    {
                        case ProtocolType.Udp:
                            Interlocked.Increment(ref this.networkStatistics.Udp.IncomingUnicastPacket);
                            Interlocked.Add(ref this.networkStatistics.Udp.IncomingTrafficSize, frame.Payload.Length);
                            break;
                        case ProtocolType.Icmp:
                            Interlocked.Increment(ref this.networkStatistics.Icmp.IncomingUnicastPacket);
                            Interlocked.Add(ref this.networkStatistics.Icmp.IncomingTrafficSize, frame.Payload.Length);
                            break;
                        default:
                            continue;
                    }
                    Interlocked.Increment(ref this.networkStatistics.IPv4.IncomingUnicastPacket);
                    Interlocked.Add(ref this.networkStatistics.IPv4.IncomingTrafficSize, messages.Length);
                }
            } while (false);
        }

        private void AcceptLinkWorkThread()
        {
            SOCKET server;
            while ((server = this.loopback) != null)
            {
                SOCKET socket;
                IPEndPoint natEP;
                try
                {
                    socket = server.Accept();
                }
                catch (ObjectDisposedException)
                {
                    break;
                }
                catch
                {
                    if (this.loopback == null)
                    {
                        break;
                    }
                    Thread.Sleep(10);
                    continue;
                }
                try
                {
                    socket.NoDelay = this.NoDelay;
                    natEP = socket.RemoteEndPoint as IPEndPoint;
                }
                catch
                {
                    SocketExtension.Closesocket(socket);
                    continue;
                }
                bool closing = true;
                if (natEP != null)
                {
                    TapTcpLink link = null;
                    if (this.Subnetstack)
                    {
                        do
                        {
                            if (!IPFrame.Equals(natEP.Address, IPAddress.Loopback))
                            {
                                break;
                            }
                            if (!Netstack.Link(natEP.Port, out IPEndPoint source, out IPEndPoint destination))
                            {
                                break;
                            }
                            link = this.AllocTcpLink(source, destination);
                            if (link == null || link.Fin)
                            {
                                break;
                            }
                            TapTcpClient session = this.BeginAcceptClient(link.VirtualAddress, link.Destination);
                            if (session == null)
                            {
                                break;
                            }
                            if (session.IsAccept)
                            {
                                session.Dispose();
                                break;
                            }
                            else
                            {
                                session._link = link;
                                link.Socket = session;
                            }
                            session.BeginAccept();
                        } while (false);
                    }
                    else
                    {
                        if (IPFrame.Equals(natEP.Address, this.Tap.GatewayAddress))
                        {
                            this.publicLinkTable.TryGetValue(natEP.Port, out link);
                        }
                    }
                    if (link != null)
                    {
                        if (this.EndAcceptClient(link.Socket, socket))
                        {
                            closing = false;
                            link.Syn = false;
                            link.Activity();
                        }
                        else
                        {
                            link.Fin = true;
                            link.Syn = false;
                            link.Activity();
                        }
                    }
                }
                if (closing)
                {
                    SocketExtension.Closesocket(socket);
                }
            }
        }

        protected virtual TapTcpClient BeginAcceptClient(IPEndPoint localEP, IPEndPoint remoteEP)
        {
            try
            {
                return new TapTcpClient(this, localEP, remoteEP);
            }
            catch
            {
                return null;
            }
        }

        protected virtual bool EndAcceptClient(TapTcpClient client, SOCKET socket)
        {
            if (client == null || socket == null)
            {
                return false;
            }
            try
            {
                return client.ProcessEndAccept(socket);
            }
            catch
            {
                client.Close();
                return false;
            }
        }

        protected virtual bool ProcessIcmpInput(IPFrame packet, IcmpFrame frame)
        {
            Interlocked.Increment(ref this.networkStatistics.Icmp.OutgoingUnicastPacket);
            Interlocked.Add(ref this.networkStatistics.Icmp.OutgoingTrafficSize, packet.Payload.Length);

            Interlocked.Increment(ref this.networkStatistics.IPv4.OutgoingUnicastPacket);
            Interlocked.Add(ref this.networkStatistics.IPv4.OutgoingTrafficSize, IPv4Layer.SizeOf(packet));
            return true;
        }

        protected virtual bool ProcessUdpInput(IPFrame packet, UdpFrame frame)
        {
            Interlocked.Increment(ref this.networkStatistics.Udp.OutgoingUnicastPacket);
            Interlocked.Add(ref this.networkStatistics.Udp.OutgoingTrafficSize, packet.Payload.Length);

            Interlocked.Increment(ref this.networkStatistics.IPv4.OutgoingUnicastPacket);
            Interlocked.Add(ref this.networkStatistics.IPv4.OutgoingTrafficSize, IPv4Layer.SizeOf(packet));
            return true;
        }

        protected virtual bool ProcessTcpInput(IPFrame packet, TcpFrame frame)
        {
            string key = GetPrivateLinkKey(frame.Source, frame.Destination);
            lock (this.syncobj)
            {
                TapTcpLink link = null;
                if (IPFrame.Equals(frame.Destination.Address, this.Tap.GatewayAddress)) // V->Local 
                {
                    this.publicLinkTable.TryGetValue(frame.Destination.Port, out link);
                    if (link == null)
                    {
                        return false;
                    }
                    Interlocked.Increment(ref this.networkStatistics.Tcp.IncomingUnicastPacket);
                    Interlocked.Add(ref this.networkStatistics.Tcp.IncomingTrafficSize, packet.Payload.Length);
                    try
                    {
                        frame.Source = link.Destination;
                        frame.Destination = link.Activity().Source;
                        if (0 != (frame.Flags & TcpFlags.TCP_FIN))
                        {
                            link.Syn = false;
                            if (link.VirtualState < TcpState.LAST_ACK)
                            {
                                link.VirtualState = TcpState.FIN_WAIT_1;
                                if (link.Socket == null)
                                {
                                    link.Fin = true;
                                }
                            }
                            link.VirtualSequenceNo = frame.SequenceNo;
                        }
                        else if (0 != (frame.Flags & TcpFlags.TCP_RST))
                        {
                            link.Fin = true;
                            link.Syn = false;
                            link.VirtualState = TcpState.CLOSED;
                        }
                        else if (0 != (frame.Flags & TcpFlags.TCP_ACK))
                        {
                            if (link.VirtualState < TcpState.LAST_ACK &&
                                link.LocalState >= TcpState.FIN_WAIT_1 &&
                                (1 + link.LocalSequenceNo) == frame.AcknowledgeNo)
                            {
                                link.VirtualState = TcpState.LAST_ACK;
                            }
                        }
                    }
                    finally
                    {
                        Interlocked.Increment(ref this.networkStatistics.IPv4.IncomingUnicastPacket);
                        Interlocked.Add(ref this.networkStatistics.IPv4.IncomingTrafficSize, IPv4Layer.SizeOf(packet));
                    }
                }
                else if (0 != (frame.Flags & TcpFlags.TCP_SYN))
                {
                    link = this.AllocTcpLink(frame.Source, frame.Destination);
                    if (link == null)
                    {
                        return false;
                    }
                    else if (link.Fin)
                    {
                        this.CloseTcpLink(link.Source, link.Destination);
                        return this.ProcessTcpInput(packet: packet, frame: frame);
                    }
                    else
                    {
                        Interlocked.Increment(ref this.networkStatistics.Tcp.OutgoingUnicastPacket);
                        Interlocked.Add(ref this.networkStatistics.Tcp.OutgoingTrafficSize, packet.Payload.Length);
                        try
                        {
                            bool accepting = false;
                            TapTcpClient socket = link.Socket;
                            if (socket == null)
                            {
                                socket = this.BeginAcceptClient(link.VirtualAddress, link.Destination);
                                if (socket == null)
                                {
                                    return false;
                                }
                                else
                                {
                                    accepting = true;
                                    socket._link = link;
                                    link.Socket = socket;
                                }
                            }
                            lock (socket)
                            {
                                if (!socket.IsAccept)
                                {
                                    frame.Destination = (IPEndPoint)this.LocalEndPoint;
                                    frame.Source = link.VirtualAddress;
                                    link.Connecting = CopyFrameHeaderParts(TcpLayer.ToIPFrame(frame), packet);
                                    if (accepting)
                                    {
                                        socket.BeginAccept();
                                    }
                                    return !socket.IsAbort;
                                }
                            }
                        }
                        finally
                        {
                            Interlocked.Increment(ref this.networkStatistics.IPv4.OutgoingUnicastPacket);
                            Interlocked.Add(ref this.networkStatistics.IPv4.OutgoingTrafficSize, IPv4Layer.SizeOf(packet));
                        }
                    }
                    frame.Source = link.VirtualAddress;
                    frame.Destination = (IPEndPoint)this.LocalEndPoint;
                }
                else // Local->V
                {
                    this.privateLinkTable.TryGetValue(key, out link);
                    if (link == null)
                    {
                        return false;
                    }
                    Interlocked.Increment(ref this.networkStatistics.Tcp.OutgoingUnicastPacket);
                    Interlocked.Add(ref this.networkStatistics.Tcp.OutgoingTrafficSize, packet.Payload.Length);
                    try
                    {
                        frame.Source = link.Activity().VirtualAddress;
                        frame.Destination = (IPEndPoint)this.LocalEndPoint;
                        if (0 != (frame.Flags & TcpFlags.TCP_FIN))
                        {
                            link.Syn = false;
                            if (link.LocalState < TcpState.LAST_ACK)
                            {
                                link.LocalState = TcpState.FIN_WAIT_1;
                                if (link.Socket == null)
                                {
                                    link.Fin = true;
                                }
                            }
                            link.LocalSequenceNo = frame.SequenceNo;
                        }
                        else if (0 != (frame.Flags & TcpFlags.TCP_RST))
                        {
                            link.Fin = true;
                            link.Syn = false;
                            link.LocalState = TcpState.CLOSED;
                        }
                        else if (0 != (frame.Flags & TcpFlags.TCP_ACK))
                        {
                            if (link.LocalState < TcpState.LAST_ACK &&
                                link.VirtualState >= TcpState.FIN_WAIT_1 &&
                                (1 + link.VirtualSequenceNo) == frame.AcknowledgeNo)
                            {
                                link.LocalState = TcpState.LAST_ACK;
                            }
                        }
                    }
                    finally
                    {
                        Interlocked.Increment(ref this.networkStatistics.IPv4.OutgoingUnicastPacket);
                        Interlocked.Add(ref this.networkStatistics.IPv4.OutgoingTrafficSize, IPv4Layer.SizeOf(packet));
                    }
                }
            }
            this.Output(TcpLayer.ReassemblyHeader(packet, frame)); // this.Output(CopyFrameHeaderParts(TcpLayer.ToIPFrame(frame), packet));
            return true;
        }

        private static IPFrame CopyFrameHeaderParts(IPFrame ip, IPFrame packet)
        {
            if (ip == null || packet == null)
            {
                return ip;
            }
            else
            {
                ip.Ttl = packet.Ttl;
                ip.Id = packet.Id;
                ip.Tos = packet.Tos;
                ip.Options = packet.Options;
                ip.Flags = packet.Flags;
            }
            return ip;
        }

        public virtual void Dispose()
        {
            IEnumerable<KeyValuePair<string, TapTcpLink>> privateLinkTable = null;
            IEnumerable<KeyValuePair<int, TapTcpLink>> publicLinkTable = null;
            lock (this.syncobj)
            {
                publicLinkTable = this.publicLinkTable.ToList();
                privateLinkTable = this.privateLinkTable.ToList();
            }
            using (this.Tap)
            {
                Netstack.Ouput -= this.SunetstackOutput;
                foreach (var kv in publicLinkTable)
                {
                    using (var link = kv.Value)
                    {
                        if (link != null)
                        {
                            this.CloseTcpLink(link.Source, link.Destination);
                        }
                    }
                }
                foreach (var kv in privateLinkTable)
                {
                    using (var link = kv.Value)
                    {
                        if (link != null)
                        {
                            this.CloseTcpLink(link.Source, link.Destination);
                        }
                    }
                }
                SocketExtension.Closesocket(Interlocked.Exchange(ref this.loopback, null));
            }
            lock (this.syncobj)
            {
                this.privateLinkTable.Clear();
                this.publicLinkTable.Clear();
                this.subpackageTable.Clear();
                this.ticktmr.Close();
                this.ticktmr.Dispose();
            }
            GC.SuppressFinalize(this);
        }

        public virtual IEnumerator<IConnection> GetEnumerator()
        {
            foreach (var kv in this.publicLinkTable.ToList())
            {
                yield return kv.Value;
            }
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return this.GetEnumerator();
        }
    }
}