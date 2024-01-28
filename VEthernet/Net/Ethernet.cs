namespace VEthernet.Net
{
    using System;
    using System.Collections.Generic;
    using System.Collections.ObjectModel;
    using System.Diagnostics;
    using System.Globalization;
    using System.Linq;
    using System.Net;
    using System.Net.NetworkInformation;
    using System.Net.Sockets;
#if NETCOREAPP
    using System.Runtime.CompilerServices;
#endif
    using System.Runtime.InteropServices;
    using System.Threading;
    using global::VEthernet.Core;
    using global::VEthernet.Net.Auxiliary;
    using global::VEthernet.Net.IP;

    public unsafe class Ethernet : IDisposable
    {
        [DllImport("wpcap.dll", EntryPoint = "pcap_close", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        private static extern void win32_pcap_close(void* p);

        [DllImport("wpcap.dll", EntryPoint = "pcap_findalldevs_ex", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        private static extern int win32_pcap_findalldevs_ex(
            string source,
            void* auth,
            pcap_if** alldevs,
            byte* errbuf);

        [DllImport("wpcap.dll", EntryPoint = "pcap_freealldevs", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        private static extern void win32_pcap_freealldevs(pcap_if* alldevs);

        [DllImport("wpcap.dll", EntryPoint = "pcap_open_live", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        private static extern void* win32_pcap_open_live(
            string device,
            int snaplen,
            int promisc,
            int to_ms,
            byte* ebuf);

        [DllImport("wpcap.dll", EntryPoint = "pcap_next_ex", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        private static extern int win32_pcap_next_ex(void* p, pcap_pkthdr** pkg_hdr, byte** pkg_data);

        [DllImport("wpcap.dll", EntryPoint = "pcap_datalink", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        private static extern int win32_pcap_datalink(void* P_0);

        [DllImport("wpcap.dll", EntryPoint = "pcap_set_datalink", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        private static extern int win32_pcap_set_datalink(void* P_0, int datalink);

        [DllImport("wpcap.dll", EntryPoint = "pcap_breakloop", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        private static extern void win32_pcap_breakloop(void* P_0);

        [DllImport("wpcap.dll", EntryPoint = "pcap_getnonblock", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        private static extern int win32_pcap_getnonblock(void* P_0);

        [DllImport("wpcap.dll", EntryPoint = "pcap_setnonblock", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        private static extern int win32_pcap_setnonblock(void* P_0,
            int nonblock,
            byte* errbuf);

        [DllImport("wpcap.dll", EntryPoint = "pcap_sendpacket", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        private static extern int win32_pcap_sendpacket(void* p,
            byte* buf,
            int size);
        /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        [DllImport("libpcap.so", EntryPoint = "pcap_close", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        private static extern void linux_pcap_close(void* p);

        [DllImport("libpcap.so", EntryPoint = "pcap_findalldevs_ex", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        private static extern int linux_pcap_findalldevs_ex(
            string source,
            void* auth,
            pcap_if** alldevs,
            byte* errbuf);

        [DllImport("libpcap.so", EntryPoint = "pcap_findalldevs", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        private static extern int linux_pcap_findalldevs(pcap_if** alldevs, byte* errbuf);

        [DllImport("libpcap.so", EntryPoint = "pcap_freealldevs", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        private static extern void linux_pcap_freealldevs(pcap_if* alldevs);

        [DllImport("libpcap.so", EntryPoint = "pcap_open_live", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        private static extern void* linux_pcap_open_live(
            string device,
            int snaplen,
            int promisc,
            int to_ms,
            byte* ebuf);

        [DllImport("libpcap.so", EntryPoint = "pcap_next_ex", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        private static extern int linux_pcap_next_ex(void* p, pcap_pkthdr** pkg_hdr, byte** pkg_data);

        [DllImport("libpcap.so", EntryPoint = "pcap_next", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        private static extern byte* linux_pcap_next(void* p, pcap_pkthdr* pkg_hdr);

        [DllImport("libpcap.so", EntryPoint = "pcap_datalink", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        private static extern int linux_pcap_datalink(void* P_0);

        [DllImport("libpcap.so", EntryPoint = "pcap_set_datalink", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        private static extern int linux_pcap_set_datalink(void* P_0, int datalink);

        [DllImport("libpcap.so", EntryPoint = "pcap_breakloop", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        private static extern void linux_pcap_breakloop(void* P_0);

        [DllImport("libpcap.so", EntryPoint = "pcap_getnonblock", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        private static extern int linux_pcap_getnonblock(void* P_0);

        [DllImport("libpcap.so", EntryPoint = "pcap_setnonblock", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        private static extern int linux_pcap_setnonblock(void* P_0,
            int nonblock,
            byte* errbuf);

        [DllImport("libpcap.so", EntryPoint = "pcap_sendpacket", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        private static extern int linux_pcap_sendpacket(void* p,
            byte* buf,
            int size);

        private const string PCAP_SRC_IF_STRING = "rpcap://";
        private const string PCAP_SRC_FILE_STRING = "file://";
        private const int PCAP_ERRBUF_SIZE = 256;

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct pcap_if
        {
            public pcap_if* next;
            public byte* name;
            public byte* description;
            public pcap_addr* addresses;
            public uint flags;
        };

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct pcap_addr
        {
            public pcap_addr* next;
            public sockaddr* addr;
            public sockaddr* netmask;
            public sockaddr* broadaddr;
            public sockaddr* dstaddr;
        }

        [StructLayout(LayoutKind.Sequential, Size = 16, Pack = 1)]
        private struct sockaddr
        {
            public ushort sa_family; /* address family, AF_xxx */
            public byte sa_data_1; /* 14 bytes of protocol address */
            public byte sa_data_2;
            public byte sa_data_3;
            public byte sa_data_4;
            public byte sa_data_5;
            public byte sa_data_6;
            public byte sa_data_7;
            public byte sa_data_8;
            public byte sa_data_9;
            public byte sa_data_10;
            public byte sa_data_11;
            public byte sa_data_12;
            public byte sa_data_13;
            public byte sa_data_14;
        };

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct timeval
        {
            public uint tv_sec;
            public uint tv_usec;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct pcap_pkthdr
        {
            public timeval ts;
            public uint caplen;
            public uint len;
        };


        [StructLayout(LayoutKind.Explicit, Size = 28, Pack = 1)]

        private struct sockaddr_in6
        {
            [FieldOffset(0)] public ushort sin6_family;
            [FieldOffset(2)] public ushort sin6_port;
            [FieldOffset(4)] public uint sin6_flowinfo;
            [FieldOffset(8)] public long sin6_addr_1;
            [FieldOffset(16)] public long sin6_addr_2;
            [FieldOffset(24)] public uint sin6_scope_id;
        }

        [Flags]
        public enum DeviceAttributes
        {
            /// <summary>
            /// Interface is loopback.
            /// </summary>
            Loopback = 0x1,
            /// <summary>
            /// No attributes apply.
            /// </summary>
            None = 0x0
        }

        [Flags]
        public enum PacketDeviceOpenAttributes
        {
            /// <summary>
            /// This flag configures the adapter for maximum responsiveness.
            /// In presence of a large value for nbytes, WinPcap waits for the arrival of several packets before copying the data to the user.
            /// This guarantees a low number of system calls, i.e. lower processor usage, i.e. better performance, which is good for applications like sniffers.
            /// If the user sets this flag, the capture driver will copy the packets as soon as the application is ready to receive them.
            /// This is suggested for real time applications (like, for example, a bridge) that need the best responsiveness. 
            /// </summary>
            MaximumResponsiveness = 0x10,
            /// <summary>
            /// Defines if the local adapter will capture its own generated traffic.
            /// This flag tells the underlying capture driver to drop the packets that were sent by itself.
            /// This is useful when building applications like bridges, that should ignore the traffic they just sent. 
            /// </summary>
            NoCaptureLocal = 0x8,
            /// <summary>
            /// Defines if the remote probe will capture its own generated traffic.
            /// In case the remote probe uses the same interface to capture traffic and to send data back to the caller,
            /// the captured traffic includes the RPCAP traffic as well.
            /// If this flag is turned on, the RPCAP traffic is excluded from the capture,
            /// so that the trace returned back to the collector does not include this traffic. 
            /// </summary>
            NoCaptureRemote = 0x4,
            /// <summary>
            /// Defines if the data trasfer (in case of a remote capture) has to be done with UDP protocol.
            /// Use this flag if you want a UDP data connection, don't use it if you want a TCP data connection; control connection is always TCP-based.
            /// A UDP connection is much lighter, but it does not guarantee that all the captured packets arrive to the client workstation.
            /// Moreover, it could be harmful in case of network congestion.
            /// This flag is meaningless if the source is not a remote interface. In that case, it is simply ignored. 
            /// </summary>
            DataTransferUdpRemote = 0x2,
            /// <summary>
            /// Defines if the adapter has to go in promiscuous mode.
            /// Note that even if this parameter is false, the interface could well be in promiscuous mode for some other reason
            /// (for example because another capture process with promiscuous mode enabled is currently using that interface).
            /// On on Linux systems with 2.2 or later kernels (that have the "any" device), this flag does not work on the "any" device;
            /// if an argument of "any" is supplied, the 'promisc' flag is ignored. 
            /// </summary>
            Promiscuous = 0x1,
            /// <summary>
            /// No flags.
            /// </summary>
            None = 0x0
        }

        [Flags]
        public enum PacketCommunicatorReceiveResult
        {
            /// <summary>This return value should never be returned</summary>
            None = 4,
            /// <summary>The loop has been broken by a call to Break() before all the requested packets could be read.</summary>
            BreakLoop = 3,
            /// <summary>EOF was reached reading from an offline capture.</summary>
            Eof = 2,
            /// <summary>The packets/statistics have been read without problems.</summary>
            Ok = 0,
            /// <summary>The timeout set with Open() has elapsed when trying to read packets.</summary>
            Timeout = 1
        }

        [Flags]
        public enum DataLinkKind
        {
            /// <summary>
            /// Ethernet data link kind.
            /// </summary>
            Ethernet,
            /// <summary>
            /// IPv4 data link kind.
            /// </summary>
            IpV4,
            /// <summary>
            /// Data Over Cable Service Interface Specification.
            /// </summary>
            Docsis
        }

        [Flags]
        public enum EthernetType : ushort
        {
            /// <summary>
            /// No Ethernet type
            /// </summary>
            None = 0,
            /// <summary>
            /// Internet Protocol, Version 4 (IPv4)
            /// </summary>
            IpV4 = 0x800,
            /// <summary>
            /// Address Resolution Protocol (ARP)
            /// </summary>
            Arp = 2054,
            /// <summary>
            /// Reverse Address Resolution Protocol (RARP)
            /// </summary>
            ReverseArp = 32821,
            /// <summary>
            /// AppleTalk (Ethertalk)
            /// </summary>
            AppleTalk = 32923,
            /// <summary>
            /// AppleTalk Address Resolution Protocol (AARP)
            /// </summary>
            AppleTalkArp = 33011,
            /// <summary>
            /// VLAN-tagged frame (IEEE 802.1Q)
            /// </summary>
            VLanTaggedFrame = 33024,
            /// <summary>
            /// Novell IPX (alt)
            /// </summary>
            NovellInternetworkPacketExchange = 33079,
            /// <summary>
            /// Novell
            /// </summary>
            Novell = 33080,
            /// <summary>
            /// Internet Protocol, Version 6 (IPv6)
            /// </summary>
            IpV6 = 34525,
            /// <summary>
            /// MAC Control
            /// </summary>
            MacControl = 34824,
            /// <summary>
            /// PPP, Point-to-Point Protocol
            /// </summary>
            PointToPointProtocol = 34827,
            /// <summary>
            /// CobraNet
            /// </summary>
            CobraNet = 34841,
            /// <summary>
            /// MPLS unicast
            /// </summary>
            MultiprotocolLabelSwitchingUnicast = 34887,
            /// <summary>
            /// MPLS multicast
            /// </summary>
            MultiprotocolLabelSwitchingMulticast = 34888,
            /// <summary>
            /// PPPoE Discovery Stage
            /// </summary>
            PointToPointProtocolOverEthernetDiscoveryStage = 34915,
            /// <summary>
            /// PPPoE Session Stage 
            /// </summary>
            PointToPointProtocolOverEthernetSessionStage = 34916,
            /// <summary>
            /// EAP over LAN (IEEE 802.1X)
            /// </summary>
            ExtensibleAuthenticationProtocolOverLan = 34958,
            /// <summary>
            /// HyperSCSI (SCSI over Ethernet)
            /// </summary>
            HyperScsi = 34970,
            /// <summary>
            /// ATA over Ethernet
            /// </summary>
            AtaOverEthernet = 34978,
            /// <summary>
            /// EtherCAT Protocol
            /// </summary>
            EtherCatProtocol = 34980,
            /// <summary>
            /// Provider Bridging (IEEE 802.1ad)
            /// </summary>
            ProviderBridging = 34984,
            /// <summary>
            /// AVB Transport Protocol (AVBTP)
            /// </summary>
            AvbTransportProtocol = 34997,
            /// <summary>
            /// SERCOS III
            /// </summary>
            SerialRealTimeCommunicationSystemIii = 35021,
            /// <summary>
            /// Circuit Emulation Services over Ethernet (MEF-8)
            /// </summary>
            CircuitEmulationServicesOverEthernet = 35032,
            /// <summary>
            /// HomePlug
            /// </summary>
            HomePlug = 35041,
            /// <summary>
            /// MAC security (IEEE 802.1AE)
            /// </summary>
            MacSecurity = 35045,
            /// <summary>
            /// Precision Time Protocol (IEEE 1588)
            /// </summary>
            PrecisionTimeProtocol = 35063,
            /// <summary>
            /// IEEE 802.1ag Connectivity Fault Management (CFM) Protocol / ITU-T Recommendation Y.1731 (OAM)
            /// </summary>
            ConnectivityFaultManagementOrOperationsAdministrationManagement = 35074,
            /// <summary>
            /// Fibre Channel over Ethernet
            /// </summary>
            FibreChannelOverEthernet = 35078,
            /// <summary>
            /// FCoE Initialization Protocol
            /// </summary>
            FibreChannelOverEthernetInitializationProtocol = 35092,
            /// <summary>
            /// Q-in-Q
            /// </summary>
            QInQ = 37120,
            /// <summary>
            /// Veritas Low Latency Transport (LLT)
            /// </summary>
            VeritasLowLatencyTransport = 51966
        }

        public sealed class LivePacketDevice
        {
            public DeviceAddress[] Addresses
            {
#if NETCOREAPP
                [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
                get;
            }

            public string Name
            {
#if NETCOREAPP
                [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
                get;
            }

            public string Description
            {
#if NETCOREAPP
                [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
                get;
            }

            public DeviceAttributes Attributes
            {
#if NETCOREAPP
                [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
                get;
            }

#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            internal LivePacketDevice(void* device)
            {
                pcap_if* d = (pcap_if*)device;
                this.Name = new string((sbyte*)d->name);
                this.Description = new string((sbyte*)d->description);
                this.Attributes = (DeviceAttributes)d->flags;
                {
                    List<DeviceAddress> addresses = new List<DeviceAddress>();
                    for (pcap_addr* a = d->addresses; a != null; a = a->next)
                    {
                        DeviceAddress address = new DeviceAddress(a);
                        addresses.Add(address);
                    }
                    this.Addresses = addresses.ToArray();
                }
            }

#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            public override string ToString()
            {
                return this.Name;
            }

#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            public LivePacketCommunicator Open(int snapshotLength, PacketDeviceOpenAttributes attributes, int readTimeout)
            {
                if (readTimeout < -1 || readTimeout == 0)
                {
                    throw new ArgumentOutOfRangeException(nameof(readTimeout));
                }
                else if (readTimeout == -1)
                {
                    readTimeout = 0;
                }
                if (snapshotLength < 1 || snapshotLength > SocketExtension.MTU)
                {
                    throw new ArgumentOutOfRangeException(nameof(snapshotLength));
                }
                byte* errbuf = stackalloc byte[PCAP_ERRBUF_SIZE];
                void* pcap;
                if (Environments.Platform == PlatformID.Win32NT)
                {
                    pcap = win32_pcap_open_live(this.Name, snapshotLength, (int)attributes, readTimeout, errbuf);
                }
                else
                {
                    pcap = linux_pcap_open_live(this.Name, snapshotLength, (int)attributes, readTimeout, errbuf);
                }
                if (pcap == null)
                {
                    throw new InvalidOperationException(string.Format(args: new object[2]
                    {
                        this.Name,
                        new string((sbyte*)errbuf)
                    },
                    provider: CultureInfo.InvariantCulture,
                    format: "Unable to open the adapter. Adapter name: {0}. Error: {1}"));
                }
                return new LivePacketCommunicator(this, pcap);
            }
        }

        public sealed class DeviceAddress
        {
            public IPAddress Destination
            {
#if NETCOREAPP
                [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
                get;
            }

            public IPAddress Broadcast
            {
#if NETCOREAPP
                [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
                get;
            }

            public IPAddress Netmask
            {
#if NETCOREAPP
                [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
                get;
            }

            public IPAddress Address
            {
#if NETCOREAPP
                [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
                get;
            }

#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            internal DeviceAddress(void* pcapAddress)
            {
                pcap_addr* addr = (pcap_addr*)pcapAddress;
                this.Address = ToAddress(addr->addr);
                this.Netmask = ToAddress(addr->netmask);
                this.Broadcast = ToAddress(addr->broadaddr);
                this.Destination = ToAddress(addr->dstaddr);
            }

#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            private static IPAddress ToAddress(sockaddr* address)
            {
                if (address == null)
                {
                    return IPAddress.Any;
                }
                AddressFamily af = (AddressFamily)address->sa_family;
                if (af == AddressFamily.InterNetwork)
                {
                    return new IPAddress(*(uint*)((byte*)address + 4));
                }
                else if (af == AddressFamily.InterNetworkV6)
                {
                    byte[] buf = new byte[16];
                    byte* src = (byte*)&((sockaddr_in6*)address)->sin6_addr_1;
                    for (int i = 0; i < buf.Length; i++)
                    {
                        buf[i] = src[i];
                    }
                    return new IPAddress(buf, ((sockaddr_in6*)address)->sin6_scope_id);
                }
                else
                {
                    return IPAddress.Any;
                }
            }

#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            public override string ToString()
            {
                return this.Address.ToString();
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static ReadOnlyCollection<LivePacketDevice> GetAllDevices()
        {
            pcap_if* alldevs;
            byte* errbuf = stackalloc byte[PCAP_ERRBUF_SIZE];
            int rc;
            PlatformID platform = Environments.Platform;
            if (platform == PlatformID.Win32NT)
            {
                rc = win32_pcap_findalldevs_ex(PCAP_SRC_IF_STRING, null, &alldevs, errbuf);
            }
            else
            {
                try
                {
                    rc = linux_pcap_findalldevs_ex(PCAP_SRC_IF_STRING, null, &alldevs, errbuf);
                }
                catch
                {
                    rc = linux_pcap_findalldevs(&alldevs, errbuf);
                }
            }
            if (rc < 0)
            {
                throw new InvalidOperationException(new string((sbyte*)errbuf));
            }
            List<LivePacketDevice> devices = new List<LivePacketDevice>();
            for (pcap_if* d = alldevs; d != null; d = d->next)
            {
                LivePacketDevice device = new LivePacketDevice(d);
                devices.Add(device);
            }
            if (platform == PlatformID.Win32NT)
            {
                win32_pcap_freealldevs(alldevs);
            }
            else
            {
                linux_pcap_freealldevs(alldevs);
            }
            return new ReadOnlyCollection<LivePacketDevice>(devices);
        }

        public sealed class Packet
        {
            public static readonly PhysicalAddress NullAddress = new PhysicalAddress(new byte[ETH_ALEN]);

            public const uint ETH_ALEN = 6;
            public const uint ETH_HLAN = 14;

            public EthernetType EtherType
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

            public DateTime DateTime
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

            public PhysicalAddress SouceAddress
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

            public PhysicalAddress DestinationAddress
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

            [StructLayout(LayoutKind.Sequential, Size = 14, Pack = 1)]
            private struct eth_hdr
            {
                public uint h_dest;
                public ushort h_dest_u2;
                public uint h_src;
                public ushort h_src_u2;
                public ushort h_proto;
            }

#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
            public static Packet Parse(BufferSegment packet, DateTime dateTime)
            {
                if (packet == null)
                {
                    return null;
                }
                if (packet.Length <= ETH_HLAN)
                {
                    return null;
                }
                fixed (byte* pinned = &packet.Buffer[packet.Offset])
                {
                    eth_hdr* ethhdr = (eth_hdr*)pinned;
                    return new Packet
                    {
                        SouceAddress = new PhysicalAddress(GetMacAddress(&ethhdr->h_src)),
                        DestinationAddress = new PhysicalAddress(GetMacAddress(&ethhdr->h_dest)),
                        DateTime = dateTime,
                        EtherType = (EthernetType)CheckSum.ntohs(ethhdr->h_proto),
                        Payload = new BufferSegment(packet.Buffer, packet.Offset + sizeof(eth_hdr), packet.Length - sizeof(eth_hdr)),
                    };
                }
            }

#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
            public static Packet Create(EthernetType etherType,
                PhysicalAddress sourceAddress,
                PhysicalAddress destinationAddres,
                BufferSegment payload)
            {
                if (sourceAddress == null || destinationAddres == null || payload == null)
                {
                    return null;
                }
                return new Packet
                {
                    EtherType = etherType,
                    DateTime = DateTime.Now,
                    SouceAddress = sourceAddress,
                    Payload = payload,
                    DestinationAddress = destinationAddres,
                };
            }

#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
            public BufferSegment ToArray()
            {
                BufferSegment payload = this.Payload;
                if (payload == null || payload.Length < 1)
                {
                    return null;
                }
                byte[] buffer = new byte[sizeof(eth_hdr) + payload.Length];
                fixed (byte* pinned = buffer)
                {
                    eth_hdr* ethhdr = (eth_hdr*)pinned;
                    ethhdr->h_proto = CheckSum.htons((ushort)this.EtherType);
                    Marshal.Copy(this.SouceAddress.GetAddressBytes(), 0, (IntPtr)(&ethhdr->h_src), (int)ETH_ALEN);
                    Marshal.Copy(this.DestinationAddress.GetAddressBytes(), 0, (IntPtr)(&ethhdr->h_dest), (int)ETH_ALEN);
                    Marshal.Copy(payload.Buffer, payload.Offset, (IntPtr)(pinned + sizeof(eth_hdr)), payload.Length);
                }
                return new BufferSegment(buffer, 0, buffer.Length);
            }

#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
            private static byte[] GetMacAddress(void* p)
            {
                byte[] r = new byte[ETH_ALEN];
                fixed (byte* d = r)
                {
                    *(uint*)d = *(uint*)p;
                    *(ushort*)(d + 4) = *(ushort*)((byte*)p + 4);
                }
                return r;
            }
        }

        public sealed class LivePacketCommunicator : IDisposable
        {
            [DebuggerBrowsable(DebuggerBrowsableState.Never)]
            private volatile int _disposed = 0;
            private readonly byte[] _buffer = new byte[SocketExtension.MTU];
            private readonly void* _handle = null;

            public IntPtr Handle
            {
#if NETCOREAPP
                [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
                get => (IntPtr)this._handle;
            }

            public LivePacketDevice Device
            {
#if NETCOREAPP
                [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
                get;
            }

            public DataLinkKind DataLink
            {
#if NETCOREAPP
                [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
                get
                {
                    if (Environments.Platform == PlatformID.Win32NT)
                    {
                        return (DataLinkKind)win32_pcap_datalink(this._handle);
                    }
                    else
                    {
                        return (DataLinkKind)linux_pcap_datalink(this._handle);
                    }
                }
#if NETCOREAPP
                [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
                set
                {
                    int rc;
                    if (Environments.Platform == PlatformID.Win32NT)
                    {
                        rc = win32_pcap_set_datalink(this._handle, (int)value);
                    }
                    else
                    {
                        rc = linux_pcap_set_datalink(this._handle, (int)value);
                    }
                    if (rc < 0)
                    {
                        throw new InvalidOperationException("Failed setting datalink " + value.ToString());
                    }
                }
            }

            public bool Blocking
            {
#if NETCOREAPP
                [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
                get
                {
                    if (Environments.Platform == PlatformID.Win32NT)
                    {
                        return win32_pcap_getnonblock(this._handle) < 1;
                    }
                    else
                    {
                        return linux_pcap_getnonblock(this._handle) < 1;
                    }
                }
#if NETCOREAPP
                [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
                set
                {
                    byte* errbuf = stackalloc byte[PCAP_ERRBUF_SIZE];
                    int rc;
                    if (Environments.Platform == PlatformID.Win32NT)
                    {
                        rc = win32_pcap_setnonblock(this._handle, value ? 0 : 1, errbuf);
                    }
                    else
                    {
                        rc = linux_pcap_setnonblock(this._handle, value ? 0 : 1, errbuf);
                    }
                    if (rc < 0)
                    {
                        throw new InvalidOperationException(new string((sbyte*)errbuf));
                    }
                }
            }

#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
            public LivePacketCommunicator(LivePacketDevice device, void* handle)
            {
                if (handle == null)
                {
                    throw new ArgumentNullException(nameof(handle));
                }
                this._handle = handle;
                this.Device = device ?? throw new ArgumentNullException(nameof(device));
            }

#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
            ~LivePacketCommunicator() => this.Dispose();

#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
            public void Dispose()
            {
                bool disposing = Interlocked.CompareExchange(ref this._disposed, 1, 0) == 0;
                if (disposing)
                {
                    if (Environments.Platform == PlatformID.Win32NT)
                    {
                        win32_pcap_close(this._handle);
                    }
                    else
                    {
                        linux_pcap_close(this._handle);
                    }
                }
                GC.SuppressFinalize(this);
            }

#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
            public void Break()
            {
                if (Environments.Platform == PlatformID.Win32NT)
                {
                    win32_pcap_breakloop(this._handle);
                }
                else
                {
                    linux_pcap_breakloop(this._handle);
                }
            }

#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
            public PacketCommunicatorReceiveResult ReceivePacket(out Packet packet)
            {
                packet = null;
                pcap_pkthdr* pkg_hdr;
                byte* pkg_data;
                int rc;
                if (Environments.Platform == PlatformID.Win32NT)
                {
                    rc = win32_pcap_next_ex(this._handle, &pkg_hdr, &pkg_data);
                }
                else
                {
                    rc = linux_pcap_next_ex(this._handle, &pkg_hdr, &pkg_data);
                }
                switch (rc + 2)
                {
                    case 0:
                        return PacketCommunicatorReceiveResult.Eof;
                    case 1:
                        throw new InvalidOperationException("Failed reading from device " + this.Handle);
                    case 2:
                        return PacketCommunicatorReceiveResult.Timeout;
                    case 3:
                        break;
                    default:
                        throw new InvalidOperationException("Result value " + rc.ToString(CultureInfo.InvariantCulture) + " is undefined");
                };
                byte[] buffer = this._buffer;
                if (pkg_hdr->caplen == 0)
                {
                    return PacketCommunicatorReceiveResult.Ok;
                }
                long caplen = pkg_hdr->caplen;
                if (caplen > buffer.Length)
                {
                    caplen = buffer.Length;
                }
                Marshal.Copy((IntPtr)pkg_data, buffer, 0, (int)caplen);
                packet = Packet.Parse(
                     new BufferSegment(buffer, 0, (int)caplen),
                     PcapTimestampToDateTime(&pkg_hdr->ts));
                return PacketCommunicatorReceiveResult.Ok;
            }

#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
            public bool SendPacket(Packet packet)
            {
                if (packet == null)
                {
                    return false;
                }
                BufferSegment messages = packet.ToArray();
                if (messages == null)
                {
                    return false;
                }
                if (messages.Length < 1)
                {
                    return false;
                }
                fixed (byte* p = &messages.Buffer[messages.Offset])
                {
                    if (Environments.Platform == PlatformID.Win32NT)
                    {
                        return win32_pcap_sendpacket(this._handle, p, messages.Length) == 0;
                    }
                    else
                    {
                        return linux_pcap_sendpacket(this._handle, p, messages.Length) == 0;
                    }
                }
            }

#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
            private unsafe static DateTime PcapTimestampToDateTime(timeval* pcapTimestamp)
            {
                DateTime dateTime;
                DateTime dateTime2 = dateTime = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
                TimeSpan t = TimeSpan.FromSeconds(*(int*)pcapTimestamp);
                TimeSpan t2 = TimeSpan.FromTicks((long)(*(int*)((byte*)pcapTimestamp + 4)) * 10L);
                TimeSpan value = t + t2;
                DateTime dateTime3 = dateTime = dateTime.Add(value);
                DateTime dateTime4 = dateTime = dateTime.ToLocalTime();
                return dateTime;
            }
        }

        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private LivePacketCommunicator _communicator = null;
        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private volatile bool _disposed = false;
        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private PhysicalAddress _srcMacAddress = null;
        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private PhysicalAddress _dstMacAddress = null;
        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private readonly Ping _ping = new Ping();
        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private readonly IPAddress _nextHopAddress = null;
        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private int _checkNextHopStart = 0;

        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        public readonly static PhysicalAddress BroadcastMacAddress =
            new PhysicalAddress(new byte[] { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff });
        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        public readonly static PhysicalAddress NoneMacAddress =
            new PhysicalAddress(new byte[Packet.ETH_HLAN]);

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public Ethernet(string interfaceAddress) : this(IPAddress.Parse(interfaceAddress))
        {

        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public Ethernet(IPAddress interfaceAddress)
        {
            this.InterfaceAddress = interfaceAddress ?? throw new ArgumentNullException(nameof(interfaceAddress));
            this.NetworkInterface = NetworkInterface.GetAllNetworkInterfaces().
                FirstOrDefault(i => i.GetIPProperties().UnicastAddresses.FirstOrDefault(a => IPFrame.Equals(a.Address, interfaceAddress)) != null);
            if (this.NetworkInterface == null)
            {
                throw new InvalidOperationException("Can't find the network interface");
            }
            else
            {
                var gatewayAddress = this.NetworkInterface.GetIPProperties().GatewayAddresses.
                    FirstOrDefault(i => i.Address.AddressFamily == AddressFamily.InterNetwork);
                if (gatewayAddress == null)
                {
                    throw new InvalidOperationException("Can't find the gateway address");
                }
                this._nextHopAddress = gatewayAddress.Address;
            }

            ReadOnlyCollection<LivePacketDevice> devices = GetAllDevices();
            LivePacketDevice device = devices.FirstOrDefault(i =>
                i.Addresses.FirstOrDefault(a => IPFrame.Equals(a.Address, interfaceAddress)) != null);
            if (device == null)
            {
                throw new InvalidOperationException("Unable to find any available Ethernet nic devices");
            }

            LivePacketCommunicator communicator = device.Open(SocketExtension.MTU,
                PacketDeviceOpenAttributes.Promiscuous | PacketDeviceOpenAttributes.MaximumResponsiveness, 1000);
            if (communicator == null)
            {
                throw new InvalidOperationException("Unable to open ethernet card packet communication layer");
            }

            if (communicator.DataLink != DataLinkKind.Ethernet && communicator.DataLink != DataLinkKind.IpV4)
            {
                throw new InvalidOperationException("This is not a valid ethernet card network character device");
            }
            else
            {
                communicator.Blocking = true;
            }

            this._communicator = communicator;
        }

        public event EventHandler<IPFrame> LanInput;
        public event EventHandler<IPFrame> WanInput;
        public event EventHandler<IPFrame> Sniffer;
        public event EventHandler<ArpFrame> ArpSniffer;

        public IPAddress InterfaceAddress
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            get;
        }

        public NetworkInterface NetworkInterface
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            get;
        }

        public bool Checksum
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            get;
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            set;
        } = true;

        public bool IsDisposed
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            get => this._disposed;
        }

        public bool Blocking
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            get
            {
                var p = this._communicator;
                if (p == null)
                {
                    return false;
                }
                return p.Blocking;
            }
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            set
            {
                var p = this._communicator;
                if (p != null)
                {
                    p.Blocking = value;
                }
            }
        }

        public bool IsReady
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            get
            {
                return this._srcMacAddress != null && this._dstMacAddress != null;
            }
        }

        public IPAddress NextHopAddress
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
            get => this._nextHopAddress;
        }

        public PhysicalAddress NextHopMacAddress
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
            get => this._dstMacAddress;
        }

        public PhysicalAddress LocalMacAddress
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
            get => this._srcMacAddress;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public virtual ulong Listen()
        {
            if (Interlocked.CompareExchange(ref this._checkNextHopStart, 1, 0) == 0)
            {
                Thread t = new Thread(() =>
                {
                    while (!this._disposed)
                    {
                        if (this.IsReady)
                        {
                            break;
                        }
                        try
                        {
                            this._ping.Send(this._nextHopAddress, 500);
                        }
                        catch (ObjectDisposedException)
                        {
                            break;
                        }
                        catch { }
                    }
                });
                t.IsBackground = true;
                t.Priority = ThreadPriority.Lowest;
                t.Start();
            }
            ulong events = 0;
            while (!this._disposed)
            {
                LivePacketCommunicator communicator = this._communicator;
                if (communicator == null)
                {
                    break;
                }
                PacketCommunicatorReceiveResult result = communicator.ReceivePacket(out Packet packet);
                switch (result)
                {
                    case PacketCommunicatorReceiveResult.Timeout:
                        continue;
                    case PacketCommunicatorReceiveResult.Ok:
                        if (packet == null)
                        {
                            continue;
                        }
                        if (packet.EtherType == EthernetType.IpV4)
                        {
                            IPFrame frame = IPv4Layer.ParseFrame(packet.Payload, this.Checksum);
                            if (frame == null)
                            {
                                continue;
                            }
                            else
                            {
                                bool lanToWan = IPFrame.Equals(frame.Source, this.InterfaceAddress);
                                bool wanToLan = IPFrame.Equals(frame.Destination, this.InterfaceAddress);
                                if (lanToWan && wanToLan)
                                {
                                    continue;
                                }
                                else
                                {
                                    events++;
                                    if (lanToWan)
                                    {
                                        bool unready = false;
                                        if (!this.IsReady)
                                        {
                                            unready = true;
                                        }
                                        if (unready)
                                        {
                                            bool ok = IPFrame.Equals(frame.Destination, this._nextHopAddress);
                                            if (ok)
                                            {
                                                this._srcMacAddress = packet.SouceAddress;
                                                this._dstMacAddress = packet.DestinationAddress;
                                                this.OnReady(EventArgs.Empty);
                                            }
                                        }
                                    }
                                    this.OnSniffer(frame);
                                }
                            }
                        }
                        else if (packet.EtherType == EthernetType.Arp)
                        {
                            ArpFrame frame = ArpFrame.ParseFrame(packet.Payload);
                            if (frame != null)
                            {
                                this.OnArpSniffer(frame);
                            }
                        }
                        continue;
                    default:
                        break;
                };
            }
            return events;
        }

        [Flags]
        public enum ArpOpCode
        {
            Request = 1,
            Reponse = 2,
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct arp_hdr
        {
            public ushort w_hw_type;
            public ushort w_proto_type;
            public byte u_hw_addr_len;
            public byte u_proto_addr_len;
            public ushort w_opcode;

            public uint src_mac;
            public ushort src_mac_;
            public uint src_addr;

            public uint dst_mac;
            public ushort dst_mac_;
            public uint dst_addr;
        }

        public sealed class ArpFrame : EventArgs
        {
            public ArpOpCode Code
            {
#if NETCOREAPP
                [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
                get;
#if NETCOREAPP
                [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
                set;
            } = ArpOpCode.Request;

            public PhysicalAddress SourceMac
            {
#if NETCOREAPP
                [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
                get;
#if NETCOREAPP
                [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
                set;
            }

            public IPAddress SourceIP
            {
#if NETCOREAPP
                [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
                get;
#if NETCOREAPP
                [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
                set;
            }

            public PhysicalAddress DestinationMac
            {
#if NETCOREAPP
                [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
                get;
#if NETCOREAPP
                [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
                set;
            }

            public IPAddress DestinationIP
            {
#if NETCOREAPP
                [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
                get;
#if NETCOREAPP
                [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
                set;
            }

#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            private static byte[] GetBuffer(void* p, int size)
            {
                byte[] buffer = new byte[size];
                Marshal.Copy((IntPtr)p, buffer, 0, size);
                return buffer;
            }

#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            public static ArpFrame ParseFrame(BufferSegment e)
            {
                if (e == null || e.Length < sizeof(arp_hdr))
                {
                    return null;
                }
                ArpFrame frame = null;
                e.UnsafeAddrOfPinnedArrayElement((p) =>
                {
                    arp_hdr* arphdr = (arp_hdr*)p;
                    if (arphdr->w_hw_type != CheckSum.htons(1))
                    {
                        return;
                    }
                    if (arphdr->w_proto_type != CheckSum.htons((ushort)EthernetType.IpV4))
                    {
                        return;
                    }
                    if (arphdr->u_hw_addr_len != Packet.ETH_ALEN)
                    {
                        return;
                    }
                    ArpOpCode opCode = (ArpOpCode)CheckSum.ntohs(arphdr->w_opcode);
                    if (opCode != ArpOpCode.Request && opCode != ArpOpCode.Reponse)
                    {
                        return;
                    }
                    frame = new ArpFrame()
                    {
                        Code = opCode,
                        DestinationIP = new IPAddress(GetBuffer(&arphdr->dst_addr, sizeof(uint))),
                        DestinationMac = new PhysicalAddress(GetBuffer(&arphdr->dst_mac, (int)Packet.ETH_ALEN)),
                        SourceIP = new IPAddress(GetBuffer(&arphdr->src_addr, sizeof(uint))),
                        SourceMac = new PhysicalAddress(GetBuffer(&arphdr->src_mac, (int)Packet.ETH_ALEN)),
                    };
                });
                return frame;
            }

#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            public Packet ToPacket()
            {
                ArpFrame frame = this;
                return ToPacket(frame.SourceMac, frame.SourceIP, frame.DestinationMac, frame.DestinationIP, frame.Code);
            }

#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            public static Packet ToPacket(PhysicalAddress srcMac, IPAddress srcIP, PhysicalAddress dstMac, IPAddress dstIP, ArpOpCode opCode)
            {
                if (srcMac == null || srcIP == null || dstIP == null || dstMac == null)
                {
                    return null;
                }
                if (srcIP.AddressFamily != AddressFamily.InterNetwork ||
                    dstIP.AddressFamily != AddressFamily.InterNetwork)
                {
                    return null;
                }
                int buffer_size = sizeof(arp_hdr);
                if (opCode == ArpOpCode.Request)
                {
                    buffer_size += 18;
                }
                byte[] buffer = new byte[buffer_size];
                fixed (byte* pinned = buffer)
                {
                    arp_hdr* arphdr = (arp_hdr*)pinned;
                    arphdr->w_hw_type = CheckSum.htons(1);
                    arphdr->w_proto_type = CheckSum.htons((ushort)EthernetType.IpV4);
                    arphdr->u_hw_addr_len = (byte)Packet.ETH_ALEN;
                    arphdr->u_proto_addr_len = sizeof(uint);
                    arphdr->w_opcode = CheckSum.htons((ushort)opCode);
                    arphdr->src_addr = BitConverter.ToUInt32(srcIP.GetAddressBytes(), 0);
                    arphdr->dst_addr = BitConverter.ToUInt32(dstIP.GetAddressBytes(), 0);
                    Marshal.Copy(srcMac.GetAddressBytes(), 0, (IntPtr)(&arphdr->src_mac), (int)Packet.ETH_ALEN);
                    Marshal.Copy(dstMac.GetAddressBytes(), 0, (IntPtr)(&arphdr->dst_mac), (int)Packet.ETH_ALEN);
                }
                return Packet.Create(EthernetType.Arp, srcMac, dstMac, new BufferSegment(buffer, 0, buffer.Length));
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public bool Output(IPFrame frame, PhysicalAddress source, PhysicalAddress destination)
        {
            if (frame == null || source == null || destination == null)
            {
                return false;
            }
            BufferSegment payload = IPv4Layer.ToArray(frame);
            if (payload == null)
            {
                return false;
            }
            Packet packet = Packet.Create(EthernetType.IpV4, source, destination, payload);
            if (packet == null)
            {
                return false;
            }
            return this.Output(packet);
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public virtual bool Output(Packet packet)
        {
            if (packet == null)
            {
                return false;
            }
            LivePacketCommunicator communicator = this._communicator;
            if (communicator == null)
            {
                return false;
            }
            return communicator.SendPacket(packet);
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public virtual bool Output(IPFrame frame)
        {
            if (frame == null)
            {
                return false;
            }
            if (IPFrame.Equals(frame.Source, this.InterfaceAddress))
            {
                return this.Output(frame, this._srcMacAddress, this._dstMacAddress);
            }
            else
            {
                return this.Output(frame, this._dstMacAddress, this._srcMacAddress);
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        protected virtual void OnReady(EventArgs e)
        {

        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        protected virtual void OnSniffer(IPFrame e)
        {
            var snifferEventHandler = this.Sniffer;
            if (snifferEventHandler != null)
            {
                snifferEventHandler.Invoke(this, e);
            }
            bool lanToWan = IPFrame.Equals(e.Source, this.InterfaceAddress);
            if (!lanToWan)
            {
                this.OnWanInput(e);
            }
            else
            {
                this.OnLanInput(e);
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        protected virtual void OnLanInput(IPFrame e)
        {
            this.LanInput?.Invoke(this, e);
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        protected virtual void OnWanInput(IPFrame e)
        {
            this.WanInput?.Invoke(this, e);
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        protected virtual void OnArpSniffer(ArpFrame e)
        {
            this.ArpSniffer?.Invoke(this, e);
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public virtual void Dispose()
        {
            if (!this._disposed)
            {
                LivePacketCommunicator communicator = this._communicator;
                if (communicator != null)
                {
                    communicator.Break();
                    communicator.Dispose();
                }
                this.LanInput = null;
                this.WanInput = null;
                this.Sniffer = null;
                this.ArpSniffer = null;
                this._ping.Dispose();
                this._disposed = true;
                this._communicator = null;
            }
            GC.SuppressFinalize(this);
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static bool Equals(PhysicalAddress x, PhysicalAddress y)
        {
            if (x == y)
            {
                return true;
            }
            byte[] xb = x.GetAddressBytes();
            byte[] yb = y.GetAddressBytes();
            if (xb == yb)
            {
                return true;
            }
            if (xb.Length != yb.Length)
            {
                return false;
            }
            for (int i = 0; i < xb.Length; i++)
            {
                if (xb[i] != yb[i])
                {
                    return false;
                }
            }
            return true;
        }
    }
}
