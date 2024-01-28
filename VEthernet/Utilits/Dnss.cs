namespace VEthernet.Utilits
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Management;
    using System.Net;
    using System.Net.NetworkInformation;
    using System.Net.Sockets;
#if NETCOREAPP
    using System.Runtime.CompilerServices;
#endif
    using System.Runtime.InteropServices;
    using System.Threading;
    using VEthernet.Core;
    using VEthernet.Net.Auxiliary;
    using VEthernet.Net.Routing;
    using VEthernet.Net.Tools;
    using VEthernet.Net.Tun;

    public static class Dnss
    {
        public const int Port = SocketExtension.DnsPort;

        [DllImport("Dnsapi.dll", SetLastError = false, ExactSpelling = true)]
        private static extern bool DnsFlushResolverCache();

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static bool Flush()
        {
            if (Environments.Platform != PlatformID.Win32NT)
            {
                return false;
            }
            if (!DnsFlushResolverCache())
            {
                return Environments.ExecuteCommands("ipconfig /flushdns");
            }
            return false;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static bool SetAddresses(params IPAddress[] addresses)
        {
            if (addresses == null || addresses.Length < 1)
            {
                return false;
            }
            bool success = false;
            Layer3Netif.GetAllNetworkInterfaces().FirstOrDefault(ni =>
            {
                if (ni == null || ni.OperationalStatus != OperationalStatus.Up)
                {
                    return false;
                }
                int dwIndex = Layer3Netif.GetAdapterIndex(ni);
                success |= SetAddresses(dwIndex, addresses);
                return false;
            });
            return success;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static bool SetAddresses(int ifIndex, params IPAddress[] addresses)
        {
            if (addresses == null || addresses.Length < 1)
            {
                return false;
            }
            string[] servers = addresses.Select(i => i.ToString()).ToArray();
            if (QueryNetworkInterface(ifIndex, managementObject =>
            {
                using (ManagementBaseObject arguments = managementObject.GetMethodParameters("SetDNSServerSearchOrder"))
                {
                    try
                    {
                        arguments["DNSServerSearchOrder"] = servers;
                    }
                    catch
                    {
                        return false;
                    }
                    try
                    {
                        using (ManagementBaseObject results = managementObject.InvokeMethod("SetDNSServerSearchOrder", arguments, null))
                        {
                            if (results == null)
                            {
                                return false;
                            }
                            try
                            {
                                object returnValue = results["ReturnValue"];
                                if (returnValue == null)
                                {
                                    return false;
                                }

                                string returnValueString = Convert.ToString(returnValue);
                                return returnValueString == "0";
                            }
                            catch
                            {
                                return false;
                            }
                        }
                    }
                    catch
                    {
                        return false;
                    }
                }
            }))
            {
                return true;
            }
            return Environments.ExecuteCommands($"netsh interface ip set dns {ifIndex} static {addresses}");
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static bool ConfigureInterface(int ifIndex, IPAddress ip, IPAddress gw, IPAddress mask)
        {
            if (ip == null || gw == null || mask == null)
            {
                return false;
            }
            return QueryNetworkInterface(ifIndex, managementObject =>
            {
                using (ManagementBaseObject arguments = managementObject.GetMethodParameters("EnableStatic"))
                {
                    try
                    {
                        arguments["IPAddress"] = new string[] { ip.ToString() };
                    }
                    catch
                    {
                        return false;
                    }
                    try
                    {
                        arguments["SubnetMask"] = new string[] { mask.ToString() };
                    }
                    catch
                    {
                        return false;
                    }
                    using (ManagementBaseObject results = managementObject.InvokeMethod("EnableStatic", arguments, null))
                    {
                        if (results == null)
                        {
                            return false;
                        }
                        try
                        {
                            object returnValue = results["ReturnValue"];
                            if (returnValue == null)
                            {
                                return false;
                            }

                            string returnValueString = Convert.ToString(returnValue);
                            if (returnValueString != "0")
                            {
                                return true;
                            }
                        }
                        catch
                        {
                            return false;
                        }
                    }
                }
                using (ManagementBaseObject arguments = managementObject.GetMethodParameters("SetGateways"))
                {
                    try
                    {
                        arguments["DefaultIPGateway"] = new string[] { gw.ToString() };
                    }
                    catch
                    {
                        return false;
                    }
                    using (ManagementBaseObject results = managementObject.InvokeMethod("SetGateways", arguments, null))
                    {
                        if (results == null)
                        {
                            return false;
                        }
                        try
                        {
                            object returnValue = results["ReturnValue"];
                            if (returnValue == null)
                            {
                                return false;
                            }

                            string returnValueString = Convert.ToString(returnValue);
                            return returnValueString == "0";
                        }
                        catch
                        {
                            return false;
                        }
                    }
                }
            });
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static bool EnableDHCP(int ifIndex, bool dhcpDNS)
        {
            return QueryNetworkInterface(ifIndex, managementObject =>
            {
                if (dhcpDNS)
                {
                    try
                    {
                        managementObject.InvokeMethod("SetDNSServerSearchOrder", null);
                    }
                    catch
                    {
                        return false;
                    }
                }
                try
                {
                    managementObject.InvokeMethod("EnableDHCP", null);
                    return true;
                }
                catch
                {
                    return false;
                }
            });
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        private static bool QueryNetworkInterface(int ifIndex, Func<ManagementObject, bool> handler)
        {
            bool success = false;
            try
            {
                using (ManagementObjectSearcher managementObjectSearcher =
                    new ManagementObjectSearcher($"SELECT * FROM Win32_NetworkAdapterConfiguration WHERE InterfaceIndex={ifIndex}"))
                {
                    try
                    {
                        using (ManagementObjectCollection managementObjectCollection = managementObjectSearcher.Get())
                        {
                            try
                            {
                                foreach (ManagementObject managementObject in managementObjectCollection)
                                {
                                    if (managementObject == null)
                                    {
                                        continue;
                                    }
                                    using (managementObject)
                                    {
                                        try
                                        {
                                            success |= handler(managementObject);
                                        }
                                        catch
                                        {
                                            continue;
                                        }
                                    }
                                }

                            }
                            catch { }
                        }
                    }
                    catch { }
                }
            }
            catch { }
            return success;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static IEnumerable<IPAddressRange> ToAddressRangeResources(string s)
            => ToAddressRangeResources(s, false);

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static IEnumerable<IPAddressRange> ToAddressRangeResources(string s, bool v6)
        {
            HashSet<IPAddressRange> addresses = new HashSet<IPAddressRange>();
            if (string.IsNullOrEmpty(s))
            {
                return addresses;
            }
            string[] lines = s.Split('\n');
            foreach (string line in lines)
            {
                string str = line;
                if (string.IsNullOrEmpty(str))
                {
                    continue;
                }
                int index = str.IndexOf('#');
                if (index > -1)
                {
                    if (index < 1)
                    {
                        continue;
                    }
                    str = str.Substring(0, index);
                }
                str = str.Trim();
                if (!IPAddressRange.TryParse(str, out IPAddressRange addressRange))
                {
                    continue;
                }
                if (!v6)
                {
                    IPAddress addr = addressRange.Begin;
                    if (addr == null || addr.AddressFamily != AddressFamily.InterNetwork)
                    {
                        continue;
                    }
                }
                addresses.Add(addressRange);
            }
            return addresses;
        }
    }
}
