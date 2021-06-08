namespace tun2socks
{
    using System;
    using System.Net;

    public class NetworkAddress
    {
        ~NetworkAddress()
        {
            this.Host = null;
            this.Tag = null;
        }
        /// <summary>
        /// 主机号
        /// </summary>
        public object Host { get; set; }
        /// <summary>
        /// 端口
        /// </summary>
        public int Port { get; set; }
        /// <summary>
        /// 地址类型：IPv4：0x01、域名：0x03、IPv6：0x04
        /// </summary>
        public byte Type { get; set; }
        /// <summary>
        /// 用户数据报
        /// </summary>
        public bool Udp { get; set; }

        public object Tag { get; set; }

        public static bool Equals(NetworkAddress x, NetworkAddress y)
        {
            if (x == null || y == null)
            {
                return false;
            }
            if (x.Type == y.Type && x.Port == y.Port)
            {
                if (x.Type == 0x01 || x.Type == 0x04)
                {
                    byte[] x1 = (byte[])x.Host;
                    byte[] y1 = (byte[])y.Host;
                    if (x1.Length != y1.Length)
                    {
                        return false;
                    }
                    for (int i = 0; i < x1.Length; i++)
                    {
                        if (x1[i] != y1[i])
                        {
                            return false;
                        }
                    }
                    return true;
                }
                else
                {
                    string x1 = (string)x.Host;
                    string y1 = (string)y.Host;
                    if (x1 != y1)
                    {
                        return false;
                    }
                }
                return true;
            }
            return false;
        }

        public IPEndPoint EndPoint
        {
            get
            {
                if (this.Host != null && this.Host is IPEndPoint)
                {
                    return (IPEndPoint)this.Host;
                }
                IPAddress ip = null;
                if (this.Type == 0x01 || this.Type == 0x04)
                {
                    ip = new IPAddress((byte[])Host);
                }
                else if (this.Type == 0x03)
                {
                    string hostname = (Host ?? string.Empty).ToString();
                    try
                    {
#if DNS_ACCESS_OPTIMIZATION
                        ip = Dns2.Resolve(hostname);
#else
                        IPAddress[] s = Dns.GetHostAddresses(hostname);
                        if (s.Length > 0)
                        {
                            ip = s[0];
                        }
#endif
                    }
                    catch (Exception)
                    {
                        return null;
                    }
                }
                else
                {
                    return null;
                }
                return new IPEndPoint(ip, this.Port);
            }
        }
    }
}
