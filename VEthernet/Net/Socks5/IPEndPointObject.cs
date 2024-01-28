namespace VEthernet.Net.Socks5
{
    using System;
    using System.Collections.Generic;
    using System.Net;
    using System.Net.NetworkInformation;
    using System.Text;
    using Network = System.Net;
    using Sockets = System.Net.Sockets;

    public class IPEndPointObject : EndPoint // wrapper
    {
        private readonly byte[] m_addressTextBytes;

        public IPAddress Address { get; }

        public int Port { get; }

        public string AddressString { get; }

        public byte[] GetAddressStringBytes()
        {
            return m_addressTextBytes;
        }

        public byte[] AddressBytes { get; }

        public override Sockets.AddressFamily AddressFamily
        {
            get
            {
                return Address.AddressFamily;
            }
        }

        public override string ToString()
        {
            return string.Format("{0}:{1}", AddressString, Port);
        }

        public IPEndPointObject(EndPoint ep) : this((Network.IPEndPoint)ep)
        {

        }

        public IPEndPointObject(Network.IPEndPoint ep) : this(ep.Address, ep.Port)
        {

        }

        public IPEndPointObject(IPAddress address, int port)
        {
            Address = address ?? throw new ArgumentNullException();
            Port = port;
            AddressString = address.ToString();
            m_addressTextBytes = Encoding.Default.GetBytes(AddressString);
            AddressBytes = address.GetAddressBytes();
        }

        public static IPAddress[] IPActiveAddress
        {
            get
            {
                List<IPAddress> ipaddrs = new List<IPAddress>();
                foreach (NetworkInterface mib2i in NetworkInterface.GetAllNetworkInterfaces())
                {
                    IPInterfaceProperties ipiprop = mib2i.GetIPProperties();
                    UnicastIPAddressInformationCollection uaddrs = ipiprop.UnicastAddresses;
                    if (uaddrs.Count > 0 && ipiprop.DhcpServerAddresses.Count > 0)
                    {
                        foreach (UnicastIPAddressInformation uaddr in uaddrs)
                        {
                            if (uaddr.Address.AddressFamily != Sockets.AddressFamily.InterNetworkV6)
                            {
                                if (!ipaddrs.Contains(uaddr.Address))
                                    ipaddrs.Add(uaddr.Address);
                            }
                        }
                    }
                }
                return ipaddrs.ToArray();
            }
        }
    }
}
