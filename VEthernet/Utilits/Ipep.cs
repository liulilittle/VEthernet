namespace VEthernet.Utilits
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Net;
    using System.Net.Sockets;
#if NETCOREAPP
    using System.Runtime.CompilerServices;
#endif

    public static class Ipep
    {
#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static string ToAddresses(IPAddress[] addresses)
        {
            if (addresses == null || addresses.Length < 1)
            {
                return string.Empty;
            }
            string s = string.Empty;
            for (int i = 0, l = addresses.Length - 1; i <= l; i++)
            {
                s += addresses[i].ToString();
                if (i < l)
                {
                    s += "; ";
                }
            }
            return s;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static string[] ToAddresses2(IEnumerable<IPAddress> addresses)
        {
            List<string> list = new List<string>();
            if (addresses == null)
            {
                return list.ToArray();
            }
            foreach (IPAddress address in addresses)
            {
                if (address == null)
                {
                    continue;
                }
                list.Add(address.ToString());
            }
            return list.ToArray();
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static IPAddress[] ToAddresses2(IEnumerable<string> addresses)
        {
            List<IPAddress> list = new List<IPAddress>();
            if (addresses == null)
            {
                return list.ToArray();
            }
            HashSet<IPAddress> set = new HashSet<IPAddress>();
            foreach (string i in addresses)
            {
                if (string.IsNullOrEmpty(i))
                {
                    continue;
                }
                string s = i.
                    Replace(',', ';').
                    Replace(' ', ';').
                    Replace('|', ';').
                    Replace('-', ';').
                    Replace(':', ';').
                    Replace('*', ';');
                if (string.IsNullOrEmpty(s))
                {
                    continue;
                }
                if (IPAddress.TryParse(s, out IPAddress address))
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
        public static IPAddress[] ToAddresses(string addresses)
        {
            List<IPAddress> list = new List<IPAddress>();
            if (string.IsNullOrEmpty(addresses))
            {
                return list.ToArray();
            }
            HashSet<IPAddress> set = new HashSet<IPAddress>();
            addresses = addresses.
                Replace(',', ';').
                Replace(' ', ';').
                Replace('|', ';').
                Replace('-', ';').
                Replace(':', ';').
                Replace('*', ';');
            foreach (string i in addresses.Split(';'))
            {
                if (string.IsNullOrEmpty(i))
                {
                    continue;
                }
                if (IPAddress.TryParse(i, out IPAddress address))
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
        public static string ToIpepAddress(IPEndPoint ep)
        {
            if (ep == null)
            {
                return "0.0.0.0:0";
            }
            return $"{ep.Address}:{ep.Port}";
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static IPEndPoint GetEndPoint(string ipepAddress)
        {
            FromIpepAddress(ipepAddress, out string host, out int port);
            return GetEndPoint(host, port);
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static bool FromIpepAddress(string ipepAddress, out string host, out int port)
        {
            host = "0.0.0.0";
            port = 0;
            if (string.IsNullOrEmpty(ipepAddress))
            {
                return false;
            }
            else
            {
                ipepAddress = ipepAddress.Trim();
                if (string.IsNullOrEmpty(ipepAddress))
                {
                    return false;
                }
            }
            int i = ipepAddress.LastIndexOf(":");
            if (i >= 0)
            {
                string s = ipepAddress.Substring(i + 1);
                if (!int.TryParse(s, out port))
                {
                    port = 0;
                }
                host = ipepAddress.Substring(0, i);
            }
            else
            {
                host = ipepAddress;
            }
            return true;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static IPEndPoint GetEndPoint(string host, int port)
        {
            if (port < IPEndPoint.MinPort || port > IPEndPoint.MaxPort)
            {
                port = IPEndPoint.MinPort;
            }
            if (string.IsNullOrEmpty(host))
            {
                return new IPEndPoint(IPAddress.Loopback, port);
            }
            if (IPAddress.TryParse(host, out IPAddress address))
            {
                return new IPEndPoint(address, port);
            }
            try
            {
                IPAddress[] addresses = Dns.GetHostAddresses(host);
                if (addresses == null || addresses.Length < 1)
                {
                    return new IPEndPoint(IPAddress.Any, port);
                }
                IPAddress result = addresses.FirstOrDefault(i => i.AddressFamily == AddressFamily.InterNetwork);
                if (result != null)
                {
                    return new IPEndPoint(result, port);
                }
                return new IPEndPoint(addresses[0], port);
            }
            catch
            {
                return new IPEndPoint(IPAddress.Any, port);
            }
        }
    }
}
