namespace VEthernet.Net.Routing
{
    using System;
    using System.Net;
    using System.Runtime.InteropServices;
    using VEthernet.Net.IP;

    public static class RouteTableManager
    {
        public enum MIB_IPFORWARD_TYPE : uint
        {
            /// <summary>
            /// Some other type not specified in RFC 1354.
            /// </summary>
            MIB_IPROUTE_TYPE_OTHER = 1,
            /// <summary>
            /// An invalid route. This value can result from a route added by an ICMP redirect.
            /// </summary>
            MIB_IPROUTE_TYPE_INVALID = 2,
            /// <summary>
            /// A local route where the next hop is the final destination (a local interface).
            /// </summary>
            MIB_IPROUTE_TYPE_DIRECT = 3,
            /// <summary>
            /// The remote route where the next hop is not the final destination (a remote destination).
            /// </summary>
            MIB_IPROUTE_TYPE_INDIRECT = 4
        }

        public enum MIB_IPPROTO : uint
        {
            /// <summary>
            /// Some other protocol not specified in RFC 1354.
            /// </summary>
            MIB_IPPROTO_OTHER = 1,
            /// <summary>
            /// A local interface.
            /// </summary>
            MIB_IPPROTO_LOCAL = 2,
            /// <summary>
            /// A static route. 
            /// This value is used to identify route information for IP routing
            /// set through network management such as the Dynamic Host Configuration
            /// Protocol (DCHP), the Simple Network Management Protocol (SNMP),
            /// or by calls to the CreateIpForwardEntry, DeleteIpForwardEntry,
            /// or SetIpForwardEntry functions.
            /// </summary>
            MIB_IPPROTO_NETMGMT = 3,
            /// <summary>
            /// The result of ICMP redirect.
            /// </summary>
            MIB_IPPROTO_ICMP = 4,
            /// <summary>
            /// The Exterior Gateway Protocol (EGP), a dynamic routing protocol.
            /// </summary>
            MIB_IPPROTO_EGP = 5,
            /// <summary>
            /// The Gateway-to-Gateway Protocol (GGP), a dynamic routing protocol.
            /// </summary>
            MIB_IPPROTO_GGP = 6,
            /// <summary>
            /// The Hellospeak protocol, a dynamic routing protocol. This is a
            /// historical entry no longer in use and was an early routing protocol
            /// used by the original ARPANET routers that ran special software
            /// called the Fuzzball routing protocol, sometimes called Hellospeak,
            /// as described in RFC 891 and RFC 1305. For more information,
            /// see http://www.ietf.org/rfc/rfc891.txt and http://www.ietf.org/rfc/rfc1305.txt.
            /// </summary>
            MIB_IPPROTO_HELLO = 7,
            /// <summary>
            /// The Berkeley Routing Information Protocol (RIP) or RIP-II, a dynamic routing protocol.
            /// </summary>
            MIB_IPPROTO_RIP = 8,
            /// <summary>
            /// The Intermediate System-to-Intermediate System (IS-IS) protocol,
            /// a dynamic routing protocol. The IS-IS protocol was developed for
            /// use in the Open Systems Interconnection (OSI) protocol suite.
            /// </summary>
            MIB_IPPROTO_IS_IS = 9,
            /// <summary>
            /// The End System-to-Intermediate System (ES-IS) protocol, a dynamic
            /// routing protocol. The ES-IS protocol was developed for use in the
            /// Open Systems Interconnection (OSI) protocol suite.
            /// </summary>
            MIB_IPPROTO_ES_IS = 10,
            /// <summary>
            /// The Cisco Interior Gateway Routing Protocol (IGRP), a dynamic routing protocol.
            /// </summary>
            MIB_IPPROTO_CISCO = 11,
            /// <summary>
            /// The Bolt, Beranek, and Newman (BBN) Interior Gateway Protocol
            /// (IGP) that used the Shortest Path First (SPF) algorithm. This
            /// was an early dynamic routing protocol.
            /// </summary>
            MIB_IPPROTO_BBN = 12,
            /// <summary>
            /// The Open Shortest Path First (OSPF) protocol, a dynamic routing protocol.
            /// </summary>
            MIB_IPPROTO_OSPF = 13,
            /// <summary>
            /// The Border Gateway Protocol (BGP), a dynamic routing protocol.
            /// </summary>
            MIB_IPPROTO_BGP = 14,
            /// <summary>
            /// A Windows specific entry added originally by a routing protocol, but which is now static.
            /// </summary>
            MIB_IPPROTO_NT_AUTOSTATIC = 10002,
            /// <summary>
            /// A Windows specific entry added as a static route from the routing user interface or a routing command.
            /// </summary>
            MIB_IPPROTO_NT_STATIC = 10006,
            /// <summary>
            /// A Windows specific entry added as a static route from the routing
            /// user interface or a routing command, except these routes do not cause Dial On Demand (DOD).
            /// </summary>
            MIB_IPPROTO_NT_STATIC_NON_DOD = 10007
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_IPFORWARDROW
        {
            public uint dwForwardDest;        //destination IP address.
            public uint dwForwardMask;        //Subnet mask
            public uint dwForwardPolicy;      //conditions for multi-path route. Unused, specify 0.
            public uint dwForwardNextHop;     //IP address of the next hop. Own address?
            public uint dwForwardIfIndex;     //index of interface
            public MIB_IPFORWARD_TYPE dwForwardType;        //route type
            public MIB_IPPROTO dwForwardProto;       //routing protocol.
            public uint dwForwardAge;         //age of route.
            public uint dwForwardNextHopAS;   //autonomous system number. 0 if not relevant
            public int dwForwardMetric1;     //-1 if not used (goes for all metrics)
            public int dwForwardMetric2;
            public int dwForwardMetric3;
            public int dwForwardMetric4;
            public int dwForwardMetric5;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_IPINTERFACE_ROW
        {
            public uint Family;
            public ulong InterfaceLuid;
            public uint InterfaceIndex;
            public uint MaxReassemblySize;
            public ulong InterfaceIdentifier;
            public uint MinRouterAdvertisementInterval;
            public uint MaxRouterAdvertisementInterval;
            public byte AdvertisingEnabled;
            public byte ForwardingEnabled;
            public byte WeakHostSend;
            public byte WeakHostReceive;
            public byte UseAutomaticMetric;
            public byte UseNeighborUnreachabilityDetection;
            public byte ManagedAddressConfigurationSupported;
            public byte OtherStatefulConfigurationSupported;
            public byte AdvertiseDefaultRoute;
            public uint RouterDiscoveryBehavior;
            public uint DadTransmits;
            public uint BaseReachableTime;
            public uint RetransmitTime;
            public uint PathMtuDiscoveryTimeout;
            public uint LinkLocalAddressBehavior;
            public uint LinkLocalAddressTimeout;
            public uint ZoneIndice0, ZoneIndice1, ZoneIndice2, ZoneIndice3, ZoneIndice4, ZoneIndice5, ZoneIndice6, ZoneIndice7,
             ZoneIndice8, ZoneIndice9, ZoneIndice10, ZoneIndice11, ZoneIndice12, ZoneIndice13, ZoneIndice14, ZoneIndice15;
            public uint SitePrefixLength;
            public uint Metric;
            public uint NlMtu;
            public byte Connected;
            public byte SupportsWakeUpPatterns;
            public byte SupportsNeighborDiscovery;
            public byte SupportsRouterDiscovery;
            public uint ReachableTime;
            public byte TransmitOffload;
            public byte ReceiveOffload;
            public byte DisableDefaultRoutes;
        }

        [StructLayout(LayoutKind.Sequential)]
        private unsafe struct MIB_IPFORWARDTABLE
        {
            /// <summary>
            /// number of route entriesin the table.
            /// </summary>
            public int dwNumEntries;
            public MIB_IPFORWARDROW table;
        }

        [DllImport("Iphlpapi.dll", SetLastError = false, ExactSpelling = true)]
        private static extern int CreateIpForwardEntry(ref MIB_IPFORWARDROW pRoute);

        [DllImport("Iphlpapi.dll", SetLastError = false, ExactSpelling = true)]
        private static extern int DeleteIpForwardEntry(ref MIB_IPFORWARDROW pRoute);

        [DllImport("Iphlpapi.dll", SetLastError = false, ExactSpelling = true)]
        private static extern int SetIpForwardEntry(ref MIB_IPFORWARDROW pRoute);

        [DllImport("Iphlpapi.dll", SetLastError = false, ExactSpelling = true)]
        private static extern int GetIpInterfaceEntry(ref MIB_IPINTERFACE_ROW row);

        [DllImport("Iphlpapi.dll", SetLastError = false, ExactSpelling = true)]
        private static extern int GetBestInterface(uint DestAddr, out uint BestIfIndex);

        [DllImport("Iphlpapi.dll", SetLastError = false, ExactSpelling = true)]
        private static extern int GetBestRoute(uint dwDestAddr, uint dwSourceAddr, out MIB_IPFORWARDROW pBestRoute);

        [DllImport("Iphlpapi.dll", SetLastError = false, ExactSpelling = true)]
        private unsafe static extern int GetIpForwardTable(MIB_IPFORWARDTABLE* pIpForwardTable, ref int pdwSize, bool bOrder);

        [DllImport("kernel32.dll", SetLastError = false, CharSet = CharSet.Ansi)]
        private extern static int FormatMessage(int flag, ref IntPtr source, int msgid, int langid, ref string buf, int size, ref IntPtr args);

        /// <summary>
        /// 获取错误信息
        /// </summary>
        /// <param name="errCode"></param>
        /// <returns></returns>
        public static string GetErrMsg(int errCode)
        {
            IntPtr tempptr = IntPtr.Zero;
            string msg = null;
            FormatMessage(0x1300, ref tempptr, errCode, 0, ref msg, 255, ref tempptr);
            return msg;
        }

        /// <summary>
        /// 获取路由表
        /// </summary>
        /// <param name="ipForwardTable"></param>
        /// <returns></returns>
        public unsafe static int GetIpForwardTable(out RouteInformation[] ipForwardTable)
        {
            int res = 0;
            int size = Marshal.SizeOf(typeof(MIB_IPFORWARDROW));
            MIB_IPFORWARDTABLE* table = (MIB_IPFORWARDTABLE*)Marshal.AllocHGlobal(size);

            res = GetIpForwardTable(table, ref size, true);
            if (res == 0x7A)
            {
                Marshal.FreeHGlobal((IntPtr)table);
                table = (MIB_IPFORWARDTABLE*)Marshal.AllocHGlobal((IntPtr)size);
                res = GetIpForwardTable(table, ref size, true);
            }

            if (res == 0)
            {
                ipForwardTable = new RouteInformation[(*table).dwNumEntries];
                for (int i = 0; i < ipForwardTable.Length; i++)
                {
                    ipForwardTable[i] = new RouteInformation((&(*table).table)[i]);
                }
            }
            else
            {
                ipForwardTable = null;
            }

            Marshal.FreeHGlobal((IntPtr)table);
            return res;
        }

        /// <summary>
        /// 获取基础路由
        /// </summary>
        /// <param name="destAddr"></param>
        /// <param name="sourceAddr"></param>
        /// <param name="bestRoute"></param>
        /// <returns></returns>
        public static int GetBestRoute(IPAddress destAddr, IPAddress sourceAddr, out RouteInformation bestRoute)
        {
            MIB_IPFORWARDROW pBestRoute;
            var res = GetBestRoute(IpToUint(destAddr), IpToUint(sourceAddr), out pBestRoute);
            bestRoute = new RouteInformation(pBestRoute);
            return res;
        }

        /// <summary>
        /// 获取基础接口
        /// </summary>
        /// <param name="destAddr"></param>
        /// <param name="bestIfIndex"></param>
        /// <returns></returns>
        public static int GetBestInterface(IPAddress destAddr, out uint bestIfIndex)
        {
            return GetBestInterface(IpToUint(destAddr), out bestIfIndex);
        }

        /// <summary>
        /// 获取IP接口信息
        /// </summary>
        /// <param name="interfaceIndex"></param>
        /// <param name="row"></param>
        /// <returns></returns>
        public static int GetIpInterfaceEntry(uint interfaceIndex, out MIB_IPINTERFACE_ROW row)
        {
            row = new MIB_IPINTERFACE_ROW();
            row.Family = 2;
            //row.InterfaceLuid = 0;
            row.InterfaceIndex = interfaceIndex;
            return GetIpInterfaceEntry(ref row);
        }

        /// <summary>
        /// 获取单条路由信息
        /// </summary>
        /// <param name="destAddr"></param>
        /// <param name="nextHop"></param>
        /// <param name="route"></param>
        /// <returns></returns>
        public unsafe static int GetIpForwardEntry(IPAddress destAddr, IPAddress nextHop, out RouteInformation route)
        {
            route = null;

            RouteInformation[] ipForwardTable;
            var res = GetIpForwardTable(out ipForwardTable);

            if (res == 0)
            {
                for (int i = 0; i < ipForwardTable.Length; i++)
                {
                    if (IPFrame.Equals(ipForwardTable[i].Destination, destAddr) &&
                        IPFrame.Equals(ipForwardTable[i].NextHop, nextHop))
                    {
                        route = ipForwardTable[i];
                        break;
                    }
                }
            }

            return res;
        }

        /// <summary>
        /// 获取单条路由信息
        /// </summary>
        /// <param name="destAddr"></param>
        /// <param name="route"></param>
        /// <returns></returns>
        public unsafe static int GetIpForwardEntry(IPAddress destAddr, out RouteInformation route)
        {
            route = null;

            RouteInformation[] ipForwardTable;
            var res = GetIpForwardTable(out ipForwardTable);

            if (res == 0)
            {
                for (int i = 0; i < ipForwardTable.Length; i++)
                {
                    if (IPFrame.Equals(ipForwardTable[i].Destination, destAddr))
                    {
                        route = ipForwardTable[i];
                        break;
                    }
                }
            }

            return res;
        }

        /// <summary>
        /// 创建路由
        /// </summary>
        /// <param name="route"></param>
        /// <returns></returns>
        public static int CreateIpForwardEntry(RouteInformation route)
        {
            if (route == null)
            {
                return ~0;
            }
            MIB_IPFORWARDROW mib = route.GetBaseStruct();
            return CreateIpForwardEntry(ref mib);
        }

        /// <summary>
        /// 创建路由
        /// </summary>
        /// <param name="dest"></param>
        /// <param name="mask"></param>
        /// <param name="nextHop"></param>
        /// <param name="ifIndex"></param>
        /// <param name="metric"></param>
        /// <returns></returns>
        public static int CreateIpForwardEntry(IPAddress dest, IPAddress mask, IPAddress nextHop, uint ifIndex, int metric = 1)
        {
            RouteInformation route = new RouteInformation()
            {
                Destination = dest,
                Mask = mask,
                NextHop = nextHop,
                IfIndex = ifIndex,
                Metric = metric,
                Policy = 0,
                Type = MIB_IPFORWARD_TYPE.MIB_IPROUTE_TYPE_DIRECT,
                Proto = MIB_IPPROTO.MIB_IPPROTO_NETMGMT,
                Age = 0,
                NextHopAS = 0
            };

            OperatingSystem os = Environment.OSVersion;
            if (os.Platform == PlatformID.Win32NT && os.Version.Major >= 6)
            {
                MIB_IPINTERFACE_ROW row;
                int res = GetIpInterfaceEntry(ifIndex, out row);
                if (res != 0)
                    return res;
                route.Metric = (int)row.Metric;
            }

            return CreateIpForwardEntry(route);
        }

        /// <summary>
        /// 创建路由
        /// </summary>
        /// <param name="dest"></param>
        /// <param name="mask"></param>
        /// <param name="nextHop"></param>
        /// <param name="metric"></param>
        /// <returns></returns>
        public static int CreateIpForwardEntry(IPAddress dest, IPAddress mask, IPAddress nextHop, int metric = 1)
        {
            uint bestIfIndex;
            int res = GetBestInterface(nextHop, out bestIfIndex);
            if (res != 0)
                return res;

            return CreateIpForwardEntry(dest, mask, nextHop, bestIfIndex, metric);
        }

        /// <summary>
        /// 创建路由
        /// </summary>
        /// <param name="dest"></param>
        /// <param name="nextHop"></param>
        /// <param name="metric"></param>
        /// <returns></returns>
        public static int CreateIpForwardEntry(IPAddress dest, IPAddress nextHop, int metric = 1)
        {
            return CreateIpForwardEntry(dest, IPAddress.Parse("255.255.255.255"), nextHop, metric);
        }

        /// <summary>
        /// [不推荐使用]修改路由
        /// 仅用于修改网关和跃点数
        /// </summary>
        /// <param name="route"></param>
        /// <returns></returns>
        public static int SetIpForwardEntry(RouteInformation route)
        {
            if (route == null)
            {
                return ~0;
            }
            MIB_IPFORWARDROW mib = route.GetBaseStruct();
            return SetIpForwardEntry(ref mib);
        }

        /// <summary>
        /// 删除路由
        /// </summary>
        /// <param name="route"></param>
        /// <returns></returns>
        public static int DeleteIpForwardEntry(RouteInformation route)
        {
            if (route == null)
            {
                return ~0;
            }
            MIB_IPFORWARDROW mib = route.GetBaseStruct();
            return DeleteIpForwardEntry(ref mib);
        }

        /// <summary>
        /// 删除路由
        /// </summary>
        /// <param name="destAddr"></param>
        /// <param name="nextHop"></param>
        /// <returns></returns>
        public static int DeleteIpForwardEntry(IPAddress destAddr, IPAddress nextHop)
        {
            RouteInformation route;
            int res = GetIpForwardEntry(destAddr, nextHop, out route);
            if (res != 0)
                return res;
            return DeleteIpForwardEntry(route);
        }

        /// <summary>
        /// 删除路由
        /// </summary>
        /// <param name="destAddr"></param>
        /// <returns></returns>
        public static int DeleteIpForwardEntry(IPAddress destAddr)
        {
            RouteInformation route;
            int res = GetIpForwardEntry(destAddr, out route);
            if (res != 0)
                return res;
            return DeleteIpForwardEntry(route);
        }

        /// <summary>
        /// IPAdderss转uint
        /// </summary>
        /// <param name="ipAddress"></param>
        /// <returns></returns>
        public static uint IpToUint(IPAddress ipAddress)
        {
            string[] startIP = ipAddress.ToString().Split('.');

            uint U = uint.Parse(startIP[3]) << 24;
            U += uint.Parse(startIP[2]) << 16;
            U += uint.Parse(startIP[1]) << 8;
            U += uint.Parse(startIP[0]);
            return U;
        }

        /// <summary>
        /// uint转IPAddress
        /// </summary>
        /// <param name="ip"></param>
        /// <returns></returns>
        public static IPAddress UintToIp(uint ip)
        {
            string ipStr = $"{ip & 0xff}.{(ip >> 8) & 0xff}.{(ip >> 16) & 0xff}.{(ip >> 24) & 0xff}";
            return IPAddress.Parse(ipStr);
        }
    }
}
