namespace VEthernet.Net.Tun
{
    using System.Net;
    using VEthernet.Core;
    using VEthernet.Net.IP;

    public class NetifConfiguration
    {
        public IPAddress Address { get; set; }

        public IPAddress SubnetMask { get; set; }

        public IPAddress DnsAddress1 { get; set; }

        public IPAddress DnsAddress2 { get; set; }

        public IPAddress GatewayAddress { get; set; }

        public NetifConfiguration()
        {
            this.Address = IPAddress.Parse("10.0.0.1");
            this.SubnetMask = IPAddress.Parse("255.255.255.0");
            this.DnsAddress1 = IPAddress.Parse("8.8.8.8");
            this.DnsAddress2 = IPAddress.Parse("8.8.4.4");
            this.GatewayAddress = IPAddress.Parse("10.0.0.0");
        }
    }
}
