namespace VEthernet.Net.Tun
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.IO;
    using System.Linq;
    using System.Net;
    using System.Net.NetworkInformation;
    using System.Net.Sockets;
    using System.Reflection;
    using System.Runtime.InteropServices;
    using System.Text;
    using System.Threading;
    using VEthernet.Core;
    using VEthernet.Net.Auxiliary;
    using VEthernet.Net.IP;
    using VEthernet.Net.Routing;

#pragma warning disable IDE1006
    public unsafe sealed class Layer3Netif
    {
        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private static readonly Stopwatch _getAllNetworkInterfacesConcurrent = new Stopwatch();
        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private static NetworkInterface[] _cachedAllNetworkInterfaces = null;
        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private static string _preferredNetworkInterfaceId;

        public const int MTU = SocketExtension.MTU;

        public class AdapterInterface
        {
            public string Id { get; set; }

            public string Name { get; set; }

            public string Address { get; set; }

            public string Mask { get; set; }

            public string GatewayServer { get; set; }

            public string DhcpServer { get; set; }

            public string PrimaryWinsServer { get; set; }

            public string SecondaryWinsServer { get; set; }

            public string MacAddress { get; set; }

            public int IfIndex { get; set; }

            public int IfType { get; set; } // MIB_IF_TYPE

            public OperationalStatus Status { get; set; }
        };

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        private struct IP_ADAPTER_INFO
        {
            public IntPtr Next;
            public int ComboIndex;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_ADAPTER_NAME_LENGTH + 4)]
            public string AdapterName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_ADAPTER_DESCRIPTION_LENGTH + 4)]
            public string AdapterDescription;
            public uint AddressLength;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = MAX_ADAPTER_ADDRESS_LENGTH)]
            public byte[] Address;
            public int Index;
            public int Type;
            public uint DhcpEnabled;
            public IntPtr CurrentIpAddress;
            public IP_ADDR_STRING IpAddressList;
            public IP_ADDR_STRING GatewayList;
            public IP_ADDR_STRING DhcpServer;
            public bool HaveWins;
            public IP_ADDR_STRING PrimaryWinsServer;
            public IP_ADDR_STRING SecondaryWinsServer;
            public int LeaseObtained;
            public int LeaseExpires;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        private struct IP_ADDR_STRING
        {
            public IntPtr Next;
            public IP_ADDRESS_STRING IpAddress;
            public IP_ADDRESS_STRING IpMask;
            public int Context;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        private struct IP_ADDRESS_STRING
        {
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 16)]
            public string Address;
        }

        [DllImport("Iphlpapi.dll", SetLastError = false, CharSet = CharSet.Ansi)]
        private static extern int GetAdaptersInfo(IntPtr pAdapterInfo, ref long pBufOutLen);

        [DllImport("Iphlpapi.dll", SetLastError = false, CharSet = CharSet.Unicode)]
        private static extern int GetIfEntry(ref MIB_IFROW pIfRow);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct MIB_IFROW
        {
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_INTERFACE_NAME_LEN)]
            public string wszName;
            public uint dwIndex; // index of the interface
            public uint dwType; // type of interface
            public uint dwMtu; // max transmission unit 
            public uint dwSpeed; // speed of the interface 
            public uint dwPhysAddrLen; // length of physical address
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = MAXLEN_PHYSADDR)]
            public byte[] bPhysAddr; // physical address of adapter
            public uint dwAdminStatus; // administrative status
            public uint dwOperStatus; // operational status
            public uint dwLastChange; // last time operational status changed 
            public uint dwInOctets; // octets received
            public uint dwInUcastPkts; // unicast packets received 
            public uint dwInNUcastPkts; // non-unicast packets received 
            public uint dwInDiscards; // received packets discarded 
            public uint dwInErrors; // erroneous packets received 
            public uint dwInUnknownProtos; // unknown protocol packets received 
            public uint dwOutOctets; // octets sent 
            public uint dwOutUcastPkts; // unicast packets sent 
            public uint dwOutNUcastPkts; // non-unicast packets sent 
            public uint dwOutDiscards; // outgoing packets discarded 
            public uint dwOutErrors; // erroneous packets sent 
            public uint dwOutQLen; // output queue length 
            public uint dwDescrLen; // length of bDescr member 
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = MAXLEN_IFDESCR)]
            public byte[] bDescr; // interface description         
        }

        private const int MAX_INTERFACE_NAME_LEN = 256;
        private const int MAXLEN_PHYSADDR = 8;
        private const int MAXLEN_IFDESCR = 256;
        private const int MAX_ADAPTER_DESCRIPTION_LENGTH = 128;
        private const int ERROR_BUFFER_OVERFLOW = 111;
        private const int MAX_ADAPTER_NAME_LENGTH = 256;
        private const int MAX_ADAPTER_ADDRESS_LENGTH = 8;
        private const int MIB_IF_TYPE_OTHER = 1;
        private const int MIB_IF_TYPE_ETHERNET = 6;
        private const int MIB_IF_TYPE_TOKENRING = 9;
        private const int MIB_IF_TYPE_FDDI = 15;
        private const int MIB_IF_TYPE_PPP = 23;
        private const int MIB_IF_TYPE_LOOPBACK = 24;
        private const int MIB_IF_TYPE_SLIP = 28;
        private const int IF_OPER_STATUS_OPERATIONAL = 5;

        public static OperationalStatus GetOperationalStatus(int ifIndex)
        {
            MIB_IFROW m = new MIB_IFROW()
            {
                dwIndex = (uint)ifIndex,
            };
            int err = GetIfEntry(ref m);
            if (err == 0)
            {
                if (m.dwOperStatus == IF_OPER_STATUS_OPERATIONAL)
                {
                    return OperationalStatus.Up;
                }
                return OperationalStatus.Down;
            }
            return OperationalStatus.Unknown;
        }

        public static AdapterInterface[] GetAllAdapterInterfaces()
        {
            long structSize = Marshal.SizeOf(typeof(IP_ADAPTER_INFO));
            IntPtr pArray = Marshal.AllocHGlobal(new IntPtr(structSize));

            int ret = GetAdaptersInfo(pArray, ref structSize);
            if (ret == ERROR_BUFFER_OVERFLOW) // ERROR_BUFFER_OVERFLOW == 111
            {
                // Buffer was too small, reallocate the correct size for the buffer.
                pArray = Marshal.ReAllocHGlobal(pArray, new IntPtr(structSize));

                ret = GetAdaptersInfo(pArray, ref structSize);
            } // if

            string any = IPAddress.Any.ToString();
            List<AdapterInterface> interfaces = new List<AdapterInterface>();
            if (ret == 0)
            {
                // Call Succeeded
                IntPtr pEntry = pArray;
                do
                {
                    // Retrieve the adapter info from the memory address
                    IP_ADAPTER_INFO entry = (IP_ADAPTER_INFO)Marshal.PtrToStructure(pEntry, typeof(IP_ADAPTER_INFO));
                    AdapterInterface interfacex = new AdapterInterface()
                    {
                        Id = entry.AdapterName,
                        IfIndex = entry.Index,
                        Name = entry.AdapterDescription,
                        Address = entry.IpAddressList.IpAddress.Address,
                        Mask = entry.IpAddressList.IpMask.Address,
                        GatewayServer = entry.GatewayList.IpAddress.Address,
                        IfType = entry.Type,
                        Status = GetOperationalStatus(entry.Index),
                    };
                    interfaces.Add(interfacex);
                    if (entry.DhcpEnabled != 0)
                    {
                        interfacex.DhcpServer = entry.DhcpServer.IpAddress.Address;
                    }
                    if (entry.HaveWins)
                    {
                        interfacex.PrimaryWinsServer = entry.PrimaryWinsServer.IpAddress.Address;
                        interfacex.SecondaryWinsServer = entry.SecondaryWinsServer.IpAddress.Address;
                    }
                    if (string.IsNullOrEmpty(interfacex.Address)) interfacex.Address = any;
                    if (string.IsNullOrEmpty(interfacex.Mask)) interfacex.Mask = any;
                    if (string.IsNullOrEmpty(interfacex.GatewayServer)) interfacex.GatewayServer = any;
                    if (string.IsNullOrEmpty(interfacex.DhcpServer)) interfacex.DhcpServer = any;
                    if (string.IsNullOrEmpty(interfacex.PrimaryWinsServer)) interfacex.PrimaryWinsServer = any;
                    if (string.IsNullOrEmpty(interfacex.SecondaryWinsServer)) interfacex.SecondaryWinsServer = any;
                    interfacex.MacAddress = BitConverter.ToString(entry.Address, 0, (int)entry.AddressLength);
                    if (string.IsNullOrEmpty(interfacex.MacAddress))
                    {
                        interfacex.MacAddress = "00-00-00-00-00-00";
                    }
                    // Get next adapter (if any)
                    pEntry = entry.Next;
                }
                while (pEntry != IntPtr.Zero);
                Marshal.FreeHGlobal(pArray);
            }
            else
            {
                Marshal.FreeHGlobal(pArray);
            }
            return interfaces.ToArray();
        }

        public static IPAddress GetGatewayAddress(NetworkInterface ni)
        {
            if (ni == null)
            {
                return IPAddress.Any;
            }
            if (ni.OperationalStatus != OperationalStatus.Up)
            {
                return IPAddress.Any;
            }
            var gatewayAddresses = ni.GetIPProperties().GatewayAddresses;
            if (gatewayAddresses.Count < 1)
            {
                return IPAddress.Any;
            }
            foreach (var gatewayAddress in gatewayAddresses)
            {
                if (gatewayAddress.Address.AddressFamily != AddressFamily.InterNetwork)
                {
                    continue;
                }
                if (IPFrame.Any(gatewayAddress.Address) ||
                    IPFrame.Loopback(gatewayAddress.Address))
                {
                    continue;
                }
                return gatewayAddress.Address;
            }
            foreach (var gatewayAddress in gatewayAddresses)
            {
                if (gatewayAddress.Address.AddressFamily != AddressFamily.InterNetworkV6)
                {
                    continue;
                }
                if (IPFrame.Any(gatewayAddress.Address) ||
                    IPFrame.Loopback(gatewayAddress.Address))
                {
                    continue;
                }
                return gatewayAddress.Address;
            }
            return IPAddress.Any;
        }

        public static NetworkInterface GetPreferredNetworkInterfaceAddress(bool v4, out IPAddress gw)
        {
            NetworkInterface ni = GetPreferredNetworkInterfaceAddressImpl(false, v4, out gw);
            if (ni == null)
            {
                ni = GetPreferredNetworkInterfaceAddressImpl(true, v4, out gw);
            }
            if (ni != null && gw != null)
            {
                if (!IPFrame.Equals(gw, IPAddress.Any) &&
                    !IPFrame.Equals(gw, IPAddress.Broadcast) &&
                    !IPFrame.Equals(gw, IPAddress.None) &&
                    !IPFrame.Equals(gw, IPAddress.Loopback) &&
                    !IPFrame.Equals(gw, IPAddress.IPv6Any) &&
                    !IPFrame.Equals(gw, IPAddress.IPv6Loopback) &&
                    !IPFrame.Equals(gw, IPAddress.IPv6None))
                {
                    _preferredNetworkInterfaceId = ni.Id;
                    return ni;
                }
            }
            ni = GetAllNetworkInterfaces().FirstOrDefault(i => i.Id == _preferredNetworkInterfaceId);
            if (ni == null || ni.OperationalStatus == OperationalStatus.Down)
            {
                gw = null;
                return null;
            }
            gw = GetGatewayAddress(ni);
            if (!IPFrame.Equals(gw, IPAddress.Any) &&
                    !IPFrame.Equals(gw, IPAddress.Broadcast) &&
                    !IPFrame.Equals(gw, IPAddress.None) &&
                    !IPFrame.Equals(gw, IPAddress.Loopback) &&
                    !IPFrame.Equals(gw, IPAddress.IPv6Any) &&
                    !IPFrame.Equals(gw, IPAddress.IPv6Loopback) &&
                    !IPFrame.Equals(gw, IPAddress.IPv6None))
            {
                _preferredNetworkInterfaceId = ni.Id;
                return ni;
            }
            IPAddress address = GetNetworkInterfaceAddress(ni, out IPAddress mask);
            if (address == null || mask == null)
            {
                gw = null;
                return null;
            }
            if (v4)
            {
                if (address.AddressFamily != AddressFamily.InterNetwork)
                {
                    gw = null;
                    return null;
                }
            }
            int maskAddr = IPAddress.NetworkToHostOrder(BitConverter.ToInt32(mask.GetAddressBytes(), 0));
            if (uint.MaxValue == (uint)maskAddr)
            {
                gw = address;
            }
            else
            {
                int ipAddr = IPAddress.NetworkToHostOrder(BitConverter.ToInt32(address.GetAddressBytes(), 0));
                gw = new IPAddress(IPAddress.HostToNetworkOrder((ipAddr & maskAddr) + 1));
            }
            byte[] bytes = gw.GetAddressBytes();
            if (bytes == null || bytes.Length < 1)
            {
                gw = null;
                return null;
            }
            if (address.AddressFamily == AddressFamily.InterNetwork)
            {
                int ch = bytes[0];
                if (ch == 127)
                {
                    gw = null;
                    return null;
                }
            }
            _preferredNetworkInterfaceId = ni.Id;
            return ni;
        }

        private static NetworkInterface GetPreferredNetworkInterfaceAddressImpl(bool compatibleInvalidNetwork, bool onlyInterNetwork, out IPAddress gatewayAddresss)
        {
            gatewayAddresss = null;
            var interfaces = GetAllNetworkInterfaces();
            if (interfaces == null || interfaces.Length < 1)
            {
                return null;
            }
            var routes = Router.FindAllAnyAddress(out Router.Error error);
            if (error == Router.Error.Success && routes != null && routes.Length > 0)
            {
                var route = routes.FirstOrDefault(i => IPFrame.Equals(i.Destination, IPAddress.Any) && IPFrame.Equals(i.Mask, IPAddress.Any));
                if (route == null)
                {
                    route = routes.FirstOrDefault();
                }
                if (route != null)
                {
                    NetworkInterface interface_ = interfaces.FirstOrDefault(i =>
                        i.GetIPProperties().GatewayAddresses.FirstOrDefault(g => IPFrame.Equals(g.Address, route.NextHop)) != null);
                    if (interface_ != null)
                    {
                        interface_ = GetPreferredNetworkInterfaceAddressImpl(new[] { interface_ },
                            compatibleInvalidNetwork, onlyInterNetwork, ref gatewayAddresss);
                        if (interface_ != null)
                        {
                            gatewayAddresss = route.NextHop;
                            return interface_;
                        }
                    }
                }
            }
            return GetPreferredNetworkInterfaceAddressImpl(interfaces, compatibleInvalidNetwork, onlyInterNetwork, ref gatewayAddresss); ;
        }

        private static NetworkInterface GetPreferredNetworkInterfaceAddressImpl(NetworkInterface[] interfaces,
            bool compatibleInvalidNetwork, bool onlyInterNetwork, ref IPAddress gatewayAddresss)
        {
            interfaces = interfaces?.Where(ni =>
            {
                if (ni == null)
                {
                    return false;
                }
                if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback)
                {
                    return false;
                }
                if (ni.OperationalStatus != OperationalStatus.Up)
                {
                    return false;
                }
                string description = ni.Description.ToLower();
                if (description.Contains("vmware") ||
                    description.Contains("virtual") || /* VirtualBox, Virtual Port */
                    description.Contains("virtio") ||
                    description.Contains("tap") || /* tap-windows */
                    description.Contains("tun") ||
                    description.Contains("vpn") ||
                    description.Contains("vnic") ||
                    description.Contains("pcap") ||
                    description.Contains("liebao") ||
                    description.Contains("microsoft loopback") ||
                    description.Contains("microsoft km-test") ||
                    description.Contains("microsoft wi-fi direct") ||
                    description.Contains("wan miniport(pptp)") ||
                    description.Contains("wan miniport(l2tp)") ||
                    description.Contains("wan miniport(sstp)") ||
                    description.Contains("wan miniport(ikev2)") ||
                    description.Contains("wan miniport(ipsec)") ||
                    description.Contains("teredo tunneling pseudo-interface"))
                {
                    return false;
                }
                return true;
            }).ToArray();
            if (interfaces == null || interfaces.Length < 1)
            {
                return null;
            }
            int invalidIPAddr = BitConverter.ToInt32(IPAddress.Parse("169.254.0.0").GetAddressBytes(), 0);
            int invalidIPMask = BitConverter.ToInt32(IPAddress.Parse("255.255.0.0").GetAddressBytes(), 0);
            foreach (var ni in interfaces)
            {
                IPAddress address = GetGatewayAddress(ni);
                if (address == null)
                {
                    continue;
                }
                if (onlyInterNetwork)
                {
                    if (address.AddressFamily != AddressFamily.InterNetwork)
                    {
                        continue;
                    }
                }
                if (!compatibleInvalidNetwork)
                {
                    if (address.AddressFamily == AddressFamily.InterNetwork)
                    {
                        int ipAddr = BitConverter.ToInt32(address.GetAddressBytes(), 0);
                        ipAddr &= invalidIPMask;
                        if (ipAddr == invalidIPAddr)
                        {
                            continue;
                        }
                    }
                }
                if (!IPFrame.Equals(address, IPAddress.Any) &&
                    !IPFrame.Equals(address, IPAddress.Broadcast) &&
                    !IPFrame.Equals(address, IPAddress.None) &&
                    !IPFrame.Equals(address, IPAddress.Loopback) &&
                    !IPFrame.Equals(address, IPAddress.IPv6Any) &&
                    !IPFrame.Equals(address, IPAddress.IPv6Loopback) &&
                    !IPFrame.Equals(address, IPAddress.IPv6None))
                {
                    gatewayAddresss = address;
                    return ni;
                }
            }
            foreach (var ni in interfaces)
            {
                IPAddress address = GetNetworkInterfaceAddress(ni, out IPAddress mask);
                if (address == null || mask == null)
                {
                    continue;
                }
                if (onlyInterNetwork)
                {
                    if (address.AddressFamily != AddressFamily.InterNetwork)
                    {
                        continue;
                    }
                }
                if (!compatibleInvalidNetwork)
                {
                    if (address.AddressFamily == AddressFamily.InterNetwork)
                    {
                        int ipAddr = BitConverter.ToInt32(address.GetAddressBytes(), 0);
                        ipAddr &= invalidIPMask;
                        if (ipAddr == invalidIPAddr)
                        {
                            continue;
                        }
                    }
                }
                if (!IPFrame.Equals(address, IPAddress.Any) &&
                    !IPFrame.Equals(address, IPAddress.Broadcast) &&
                    !IPFrame.Equals(address, IPAddress.None) &&
                    !IPFrame.Equals(address, IPAddress.Loopback) &&
                    !IPFrame.Equals(address, IPAddress.IPv6Any) &&
                    !IPFrame.Equals(address, IPAddress.IPv6Loopback) &&
                    !IPFrame.Equals(address, IPAddress.IPv6None) &&
                    !IPFrame.Equals(mask, IPAddress.Any) &&
                    !IPFrame.Equals(mask, IPAddress.Loopback) &&
                    !IPFrame.Equals(mask, IPAddress.IPv6Any) &&
                    !IPFrame.Equals(mask, IPAddress.IPv6Loopback) &&
                    !IPFrame.Equals(mask, IPAddress.IPv6None))
                {
                    int maskAddr = IPAddress.NetworkToHostOrder(BitConverter.ToInt32(mask.GetAddressBytes(), 0));
                    if (uint.MaxValue == (uint)maskAddr)
                    {
                        gatewayAddresss = address;
                    }
                    else
                    {
                        int ipAddr = IPAddress.NetworkToHostOrder(BitConverter.ToInt32(address.GetAddressBytes(), 0));
                        gatewayAddresss = new IPAddress(IPAddress.HostToNetworkOrder((ipAddr & maskAddr) + 1));
                    }
                    return ni;
                }
            }
            return null;
        }

        public static IPAddress GetNetworkInterfaceAddress(NetworkInterface ni) =>
            GetNetworkInterfaceAddress(ni, out IPAddress mask);

        public static IPAddress GetNetworkInterfaceAddress(NetworkInterface ni, out IPAddress mask)
        {
            mask = IPAddress.Any;
            if (ni == null)
            {
                return IPAddress.Any;
            }
            UnicastIPAddressInformationCollection addressInformationCollection = ni.GetIPProperties().UnicastAddresses;
            UnicastIPAddressInformation addressInformation = addressInformationCollection.FirstOrDefault(i =>
            {
                IPAddress address = i.Address;
                if (address.AddressFamily != AddressFamily.InterNetwork)
                {
                    return false;
                }
                if (IPFrame.Equals(address, IPAddress.Any))
                {
                    return false;
                }
                return true;
            });
            if (addressInformation == null)
            {
                addressInformation = addressInformationCollection.FirstOrDefault(i =>
                {
                    IPAddress address = i.Address;
                    if (address.AddressFamily != AddressFamily.InterNetworkV6)
                    {
                        return false;
                    }
                    if (IPFrame.Equals(address, IPAddress.IPv6Any))
                    {
                        return false;
                    }
                    return true;
                });
            }
            if (addressInformation == null)
            {
                return IPAddress.Any;
            }
            else
            {
                mask = addressInformation.IPv4Mask;
            }
            return addressInformation.Address;
        }

        public static NetworkInterface[] GetAllNetworkInterfaces()
        {
            NetworkInterface[] interfaces = null;
            lock (_getAllNetworkInterfacesConcurrent)
            {
                if (_cachedAllNetworkInterfaces == null ||
                        !_getAllNetworkInterfacesConcurrent.IsRunning ||
                        _getAllNetworkInterfacesConcurrent.ElapsedMilliseconds >= 1000)
                {
                    lock (_getAllNetworkInterfacesConcurrent)
                    {
                        _getAllNetworkInterfacesConcurrent.Reset();
                        _getAllNetworkInterfacesConcurrent.Start();
                    }
                    _cachedAllNetworkInterfaces = NetworkInterface.GetAllNetworkInterfaces();
                }
                interfaces = _cachedAllNetworkInterfaces;
            }
            return interfaces;
        }

        private class NativeNetif
        {
            private static UIntPtr HKEY_LOCAL_MACHINE = new UIntPtr(0x80000002u);
            private static UIntPtr HKEY_CURRENT_USER = new UIntPtr(0x80000001u);
            private static UIntPtr NULL = UIntPtr.Zero;
            public const int ERROR_SUCCESS = 0;
            private const int KEY_ALL_ACCESS = 983103;
            private const int MAX_PATH = 260;
            private const uint REG_NONE = 0;
            private const int REG_SZ = 1;
            private const int RRF_RT_REG_SZ = 0x00000002;
            private const int FILE_FLAG_OVERLAPPED = 0x40000000;

            [DllImport("kernel32.dll", SetLastError = false, CallingConvention = CallingConvention.StdCall)]
            public static extern bool ReadFile(IntPtr hFile,
                byte[] aSegementArray,
                int nNumberOfBytesToRead,
                ref int lpReserved,
                ref OVERLAPPED lpOverlapped); // System.Threading.NativeOverlapped

            [DllImport("kernel32.dll", SetLastError = false, CallingConvention = CallingConvention.StdCall)]
            public static extern bool GetOverlappedResult(
                IntPtr hFile,
                OVERLAPPED* lpOverlapped,
                ref int lpNumberOfBytesTransferred,
                bool bWait);

            [DllImport("kernel32.dll", SetLastError = false, CharSet = CharSet.Ansi)]
            public static extern IntPtr CreateEvent(IntPtr lpEventAttributes,
                bool bManualReset,
                bool bInitialState,
                string lpName);

            [DllImport("kernel32.dll", SetLastError = false)]
            public static extern int WaitForSingleObject(IntPtr hObject, int dwTimeout);

            [DllImport("advapi32.dll", CharSet = CharSet.Ansi)]
            private static extern int RegOpenKeyEx(
                    UIntPtr hKey,
                    string subKey,
                    int ulOptions,
                    int samDesired,
                    out UIntPtr hkResult);

            [DllImport("advapi32.dll", SetLastError = false, CharSet = CharSet.Ansi)]
            private extern static int RegEnumKey(UIntPtr hkey,
                    uint index,
                    byte[] lpName,
                    uint lpcbName);

            [DllImport("advapi32.dll", SetLastError = false, CharSet = CharSet.Ansi)]
            private extern static int RegOpenKey(UIntPtr hkey,
                string lpSubKey,
                out UIntPtr phkResult);

            [DllImport("advapi32.dll", SetLastError = false, CharSet = CharSet.Ansi)]
            private extern static int RegCloseKey(UIntPtr hkey);

            [DllImport("advapi32.dll", SetLastError = false, CharSet = CharSet.Ansi)]
            private static extern int RegQueryValueEx(
                UIntPtr hKey,
                string lpValueName,
                int lpReserved,
                out uint lpType,
                byte[] lpData,
                ref int lpcbData);

            [DllImport("msvcrt.dll", CallingConvention = CallingConvention.Cdecl, SetLastError = false, ExactSpelling = true)]
            public static extern void* memset(void* dest, int c, int byteCount);

            [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = false)]
            private static extern IntPtr CreateFile(
                        string filename,
                        [MarshalAs(UnmanagedType.U4)] FileAccess access,
                        [MarshalAs(UnmanagedType.U4)] FileShare share,
                        IntPtr securityAttributes, // optional SECURITY_ATTRIBUTES struct or IntPtr.Zero
                        [MarshalAs(UnmanagedType.U4)] FileMode creationDisposition,
                        [MarshalAs(UnmanagedType.U4)] FileAttributes flagsAndAttributes,
                        IntPtr templateFile);

            [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = false)]
            private static extern IntPtr CreateFile(
                        string filename,
                        int access,
                        int share,
                        IntPtr securityAttributes, // optional SECURITY_ATTRIBUTES struct or IntPtr.Zero
                        int creationDisposition,
                        int flagsAndAttributes,
                        IntPtr templateFile);

            [StructLayout(LayoutKind.Explicit, Pack = 1)]
            public struct OVERLAPPED
            {
                [FieldOffset(0)]
                public uint Internal;

                [FieldOffset(4)]
                public uint InternalHigh;

                [FieldOffset(8)]
                public uint Offset;

                [FieldOffset(12)]
                public uint OffsetHigh;

                [FieldOffset(8)]
                public IntPtr Pointer;

                [FieldOffset(16)]
                public IntPtr hEvent;
            }

            [DllImport("kernel32.dll", SetLastError = false, ExactSpelling = true)]
            public static extern bool DeviceIoControl(
                IntPtr hDevice,
                uint dwIoControlCode,
                byte[] lpInBuffer,
                uint nInBufferSize,
                byte[] lpOutBuffer,
                uint nOutBufferSize,
                ref uint lpBytesReturned,
                ref OVERLAPPED lpOverlapped);

            [DllImport("kernel32.dll", SetLastError = false, ExactSpelling = true)]
            public static extern bool DeviceIoControl(
                IntPtr hDevice,
                uint dwIoControlCode,
                IntPtr lpInBuffer,
                uint nInBufferSize,
                IntPtr lpOutBuffer,
                uint nOutBufferSize,
                ref uint lpBytesReturned,
                ref OVERLAPPED lpOverlapped);

            public static ICollection<string> FindAllComponentId()
            {
                string szOwnerKeyPath = "SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}";
                ICollection<string> oDevComponentSet = new HashSet<string>();
                if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, szOwnerKeyPath, 0, KEY_ALL_ACCESS, out UIntPtr hOwnerKey) == ERROR_SUCCESS)
                {
                    byte[] szClassName = new byte[MAX_PATH];
                    uint dwIndex = 0;
                    byte[] data = new byte[MAX_PATH];
                    while (RegEnumKey(hOwnerKey, dwIndex++, szClassName, MAX_PATH) == ERROR_SUCCESS)
                    {
                        uint dwRegType = REG_NONE;
                        int dwSize = data.Length;
                        UIntPtr hSubKey = NULL;
                        string szSubKeyPath = szOwnerKeyPath + "\\" + Encoding.Default.GetString(szClassName);
                        if (RegOpenKey(HKEY_LOCAL_MACHINE, szSubKeyPath, out hSubKey) != ERROR_SUCCESS)
                        {
                            continue;
                        }
                        if (RegQueryValueEx(hSubKey, "ComponentId", 0, out dwRegType, data, ref dwSize) == ERROR_SUCCESS && dwRegType == REG_SZ)
                        {
                            if (dwSize < 3)
                            {
                                continue;
                            }
                            string szData = Encoding.Default.GetString(data, 0, 3).TrimEnd();
                            if ("tap" == szData)
                            {
                                dwSize = data.Length;
                                dwRegType = 0;
                                if (RegQueryValueEx(hSubKey, "NetCfgInstanceId", 0, out dwRegType, data, ref dwSize) == ERROR_SUCCESS && dwRegType == REG_SZ)
                                {
                                    string szDevComponentId = dwSize < 1 ? string.Empty : Encoding.Default.GetString(data, 0, dwSize - 1).TrimEnd();
                                    if (!string.IsNullOrEmpty(szDevComponentId))
                                    {
                                        oDevComponentSet.Add(szDevComponentId);
                                    }
                                }
                            }
                        }
                        RegCloseKey(hSubKey);
                    }
                    RegCloseKey(hOwnerKey);
                }
                return oDevComponentSet;
            }

            private const int GENERIC_READ = unchecked((int)(0x80000000));
            private const int GENERIC_WRITE = (0x40000000);
            private const int FILE_SHARE_READ = 0x00000001;
            private const int FILE_SHARE_WRITE = 0x00000002;
            private const int OPEN_EXISTING = 3;
            private const int FILE_ATTRIBUTE_SYSTEM = 0x00000004;

            public static IntPtr OpenDrive(string drive)
            {
                IntPtr handle = CreateFile(drive,
                    GENERIC_READ | GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    IntPtr.Zero,
                    OPEN_EXISTING,
                    FILE_FLAG_OVERLAPPED | FILE_ATTRIBUTE_SYSTEM,
                    IntPtr.Zero);
                if (handle == IntPtr.Zero || handle == (IntPtr)~0)
                {
                    handle = CreateFile(drive,
                            FileAccess.ReadWrite,
                            FileShare.ReadWrite,
                            IntPtr.Zero,
                            FileMode.Open,
                            FileAttributes.System | (FileAttributes)FILE_FLAG_OVERLAPPED,
                            IntPtr.Zero);
                }
                if (handle == (IntPtr)~0)
                {
                    handle = IntPtr.Zero;
                }
                return handle;
            }

            [DllImport("kernel32.dll", SetLastError = false)]
            public extern static void CloseHandle(IntPtr handle);

            [DllImport("kernel32.dll", SetLastError = false)]
            public static extern bool WriteFile(IntPtr fFile,
                byte* lpBuffer,
                int nNumberOfBytesToWrite,
                out int lpNumberOfBytesWritten,
                OVERLAPPED* lpOverlapped);
        }

        public static ICollection<string> FindAllComponentId()
        {
            ICollection<string> s = NativeNetif.FindAllComponentId();
            return s;
        }

        public static IntPtr OpenTunDev(string componentId)
        {
            string devName = $"\\\\.\\Global\\{componentId}.tap";
            return NativeNetif.OpenDrive(devName);
        }

        public static bool CloseTunDev(IntPtr handle)
        {
            if (handle != IntPtr.Zero)
            {
                try
                {
                    NativeNetif.CloseHandle(handle);
                    return true;
                }
                catch
                {
                    return false;
                }
            }
            return false;
        }

        public static bool DeviceIoControl(IntPtr tap, uint commands, byte[] contents)
        {
            IntPtr hEvent = NativeNetif.CreateEvent(IntPtr.Zero, false, false, null);
            try
            {
                NativeNetif.OVERLAPPED overlapped = new NativeNetif.OVERLAPPED();
                overlapped.hEvent = hEvent;

                uint dw = 0;
                uint content_size = 0;
                if (contents == null)
                {
                    return NativeNetif.DeviceIoControl(tap, commands,
                          contents, 0, contents, 0, ref dw, ref overlapped);
                }
                else
                {
                    content_size = (uint)contents.Length;
                    return NativeNetif.DeviceIoControl(tap, commands,
                         contents, content_size, contents, content_size, ref dw, ref overlapped);
                }
            }
            finally
            {
                if (hEvent != IntPtr.Zero)
                {
                    NativeNetif.CloseHandle(hEvent);
                }
            }
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct IpNetifInfo
        {
            public uint address;
            public uint gateway;
            public uint subnetmask;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct DnsNetifInfo
        {
            public ushort reserved;
            public uint dns1;
            public uint dns2;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct DhcpNetifInfo
        {
            public uint gateway;
            public uint ip;
            public uint netmask;
        }

        private const uint METHOD_BUFFERED = 0;
        private const uint FILE_DEVICE_UNKNOWN = 0x00000022;
        private const uint FILE_ANY_ACCESS = 0;

        private static uint CTL_CODE(uint DeviceType, uint Function, uint Method, uint Access)
        {
            return ((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method);
        }

        private static uint TAP_WIN_CONTROL_CODE(uint request, uint method)
        {
            return CTL_CODE(FILE_DEVICE_UNKNOWN, request, method, FILE_ANY_ACCESS);
        }

        public static readonly uint TAP_WIN_IOCTL_GET_MAC = TAP_WIN_CONTROL_CODE(1, METHOD_BUFFERED);
        public static readonly uint TAP_WIN_IOCTL_GET_VERSION = TAP_WIN_CONTROL_CODE(2, METHOD_BUFFERED);
        public static readonly uint TAP_WIN_IOCTL_GET_MTU = TAP_WIN_CONTROL_CODE(3, METHOD_BUFFERED);
        public static readonly uint TAP_WIN_IOCTL_GET_INFO = TAP_WIN_CONTROL_CODE(4, METHOD_BUFFERED);
        public static readonly uint TAP_WIN_IOCTL_CONFIG_POINT_TO_POINT = TAP_WIN_CONTROL_CODE(5, METHOD_BUFFERED);
        public static readonly uint TAP_WIN_IOCTL_SET_MEDIA_STATUS = TAP_WIN_CONTROL_CODE(6, METHOD_BUFFERED);
        public static readonly uint TAP_WIN_IOCTL_CONFIG_DHCP_MASQ = TAP_WIN_CONTROL_CODE(7, METHOD_BUFFERED);
        public static readonly uint TAP_WIN_IOCTL_GET_LOG_LINE = TAP_WIN_CONTROL_CODE(8, METHOD_BUFFERED);
        public static readonly uint TAP_WIN_IOCTL_CONFIG_DHCP_SET_OPT = TAP_WIN_CONTROL_CODE(9, METHOD_BUFFERED);
        public static readonly uint TAP_WIN_IOCTL_CONFIG_TUN = TAP_WIN_CONTROL_CODE(10, METHOD_BUFFERED);

        public static void SetNetifAddress(int index, IPAddress address, IPAddress mask)
        {
            string commands = $"netsh interface ip set address {index} static {address} {mask} ";
            Environments.System(commands);
        }

        public static int GetAdapterIndex(NetworkInterface ni)
        {
            if (ni == null)
            {
                return ~0;
            }
            Type type = ni.GetType();
            if (type == null)
            {
                return ~0;
            }
            FieldInfo fi = type.GetField("_index", BindingFlags.Instance | BindingFlags.NonPublic);
            if (fi == null)
            {
                fi = type.GetField("index", BindingFlags.Instance | BindingFlags.NonPublic);
            }
            if (fi == null)
            {
                return ~0;
            }
            return Convert.ToInt32(fi.GetValue(ni) ?? ~0);
        }

        public static NetworkInterface GetNetworkInterface(int index)
        {
            if (index == ~0)
            {
                return null;
            }
            foreach (var mbi2 in GetAllNetworkInterfaces())
            {
                int ifIndex = GetAdapterIndex(mbi2);
                if (ifIndex == index)
                {
                    return mbi2;
                }
            }
            return null;
        }

        public static int GetAdapterIndex(string componentId)
        {
            if (string.IsNullOrEmpty(componentId))
            {
                return ~0;
            }
            foreach (var mbi2 in GetAllNetworkInterfaces())
            {
                if (mbi2.Id == componentId)
                {
                    return GetAdapterIndex(mbi2);
                }
            }
            return ~0;
        }

        public static string GetAdapterName(string componentId)
        {
            if (string.IsNullOrEmpty(componentId))
            {
                return string.Empty;
            }
            foreach (var mbi2 in GetAllNetworkInterfaces())
            {
                if (mbi2.Id == componentId)
                {
                    return mbi2.Name;
                }
            }
            return string.Empty;
        }

        public static bool ChangeAdapterName(string name, string newName)
        {
            if (string.IsNullOrEmpty(name))
            {
                return false;
            }
            newName = newName ?? string.Empty;
            return Environments.ExecuteCommands($"netsh interface set interface name=\"{name}\" newname=\"{newName}\"");
        }

        private static string GetTapInstallPath(ref string path)
        {
            if (string.IsNullOrEmpty(path))
            {
                path = ".\\";
            }
            path = Path.GetFullPath(path);
            if (path[path.Length - 1] != '\\')
            {
                path += "\\";
            }
            return Path.GetFullPath(path + "tapinstall.exe");
        }

        public static bool RemoveAllTapWindows(string path)
        {
            string componentId = FindAllComponentId().FirstOrDefault();
            if (string.IsNullOrEmpty(componentId))
            {
                return true;
            }
            string installPath = GetTapInstallPath(ref path);
            if (!File.Exists(installPath))
            {
                return false;
            }
            string commandsText = $"\"{installPath}\" remove tap0901";
            if (!Environments.ExecuteCommands(commandsText))
            {
                return false;
            }
            componentId = FindAllComponentId().FirstOrDefault();
            if (string.IsNullOrEmpty(componentId))
            {
                return true;
            }
            return false;
        }

        public static bool InstallTapWindows(string path, string declareTapName)
        {
            string componentId = FindAllComponentId().FirstOrDefault();
            if (!string.IsNullOrEmpty(componentId))
            {
                return false;
            }
            string installPath = GetTapInstallPath(ref path);
            if (!File.Exists(installPath))
            {
                return false;
            }
            string driverPath = Path.GetFullPath(path + "OemVista.inf");
            if (!File.Exists(installPath)) // tapinstall.exe remove tap0901
            {
                return false;
            }
            else
            {
                string commandsText = $"\"{installPath}\" install \"{driverPath}\" tap0901";
                if (!Environments.ExecuteCommands(commandsText))
                {
                    return false;
                }
                else
                {
                    Thread.Sleep(1000);
                }
            }
            componentId = FindAllComponentId().FirstOrDefault();
            if (string.IsNullOrEmpty(componentId))
            {
                return false;
            }
            string adapterName = GetAdapterName(componentId);
            if (string.IsNullOrEmpty(adapterName))
            {
                return false;
            }
            else
            {
                ChangeAdapterName(adapterName, declareTapName);
            }
            return true;
        }
    }
#pragma warning restore IDE1006
}