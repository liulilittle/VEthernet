namespace VEthernet.Net.Dns
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Net;
    using System.Net.Sockets;
    using System.Threading;
#if NETCOREAPP
    using System.Runtime.CompilerServices;
#endif
    using VEthernet.Net.Auxiliary;
    using VEthernet.Net.IP;

    public static class Dns2
    {
        public static IPEndPoint[] DefaultServers { get; set; } = new IPEndPoint[] // 默认的解析服务器群组
        {
            new IPEndPoint(IPAddress.Parse("8.8.8.8"), SocketExtension.DnsPort), // Google(Cloudflare)
            new IPEndPoint(IPAddress.Parse("8.8.4.4"), SocketExtension.DnsPort), // Google
        };

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static IPAddress[] GetValidAddresses(IEnumerable<IPAddress> addresses)
        {
            List<IPAddress> list = new List<IPAddress>();
            if (addresses == null)
            {
                return list.ToArray();
            }
            HashSet<IPAddress> set = new HashSet<IPAddress>();
            foreach (IPAddress address in addresses)
            {
                if (IsValidAddress(address))
                {
                    if (set.Add(address))
                    {
                        list.Add(address);
                    }
                }
            }
            return list.ToArray();
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static bool IsValidAddress(IPAddress address)
        {
            if (address == null)
            {
                return false;
            }
            if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
            {
                return !(IPFrame.Equals(address, IPAddress.IPv6Any) ||
                    IPFrame.Equals(address, IPAddress.IPv6None));
            }
            else if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            {
                byte[] addressBytes = address.GetAddressBytes();
                unsafe
                {
                    if (addressBytes.Length != sizeof(uint))
                    {
                        return false;
                    }
                }
                if (addressBytes[0] > 223)
                {
                    return false;
                }
                unsafe
                {
                    fixed (byte* p = addressBytes)
                    {
                        return *(uint*)p != 0;
                    }
                }
            }
            else
            {
                return false;
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static bool GetHostAddressAsync(string hostNameOrAddress, Action<IPAddress> callback) =>
            GetHostAddressAsync(false, hostNameOrAddress, callback);

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static bool GetHostAddressesAsync(string hostNameOrAddress, Action<IPAddress[]> callback) =>
            GetHostAddressesAsync(false, hostNameOrAddress, callback);

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static bool GetHostAddressAsync(bool synchronous, string hostNameOrAddress, Action<IPAddress> callback)
        {
            if (callback == null)
            {
                return false;
            }
            return GetHostAddressesAsync(synchronous, hostNameOrAddress, (addresses) =>
            {
                if (addresses == null || addresses.Length < 1)
                {
                    callback(null);
                }
                else
                {
                    IPAddress address = addresses.FirstOrDefault(i => i.AddressFamily == AddressFamily.InterNetwork);
                    if (address == null)
                    {
                        address = addresses.FirstOrDefault(i => i.AddressFamily == AddressFamily.InterNetworkV6);
                    }
                    callback(address);
                }
            });
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static bool GetHostAddressesAsync(bool synchronous, string hostNameOrAddress, Action<IPAddress[]> callback)
        {
            if (callback == null || string.IsNullOrEmpty(hostNameOrAddress))
            {
                return false;
            }
            hostNameOrAddress = hostNameOrAddress.TrimStart().TrimEnd();
            if (string.IsNullOrEmpty(hostNameOrAddress))
            {
                return false;
            }
            if (IPAddress.TryParse(hostNameOrAddress, out IPAddress address))
            {
                callback(new IPAddress[] { address });
                return true;
            }
            if (synchronous)
            {
                IPAddress[] addresses = null;
                try
                {
                    addresses = Dns.GetHostAddresses(hostNameOrAddress);
                }
                catch { }
                callback(addresses);
                return address != null;
            }
            else
            {
                try
                {
                    return Dns.BeginGetHostAddresses(hostNameOrAddress, (ar) =>
                    {
                        IPAddress[] addresses = null;
                        try
                        {
                            addresses = Dns.EndGetHostAddresses(ar);
                        }
                        catch { }
                        callback(addresses);
                    }, null) != null;
                }
                catch
                {
                    return false;
                }
            }
        }
    }
}
