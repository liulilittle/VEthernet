/*
 * Description: Quick implementation of a no-tech difficulty tun2socks samples
 * Author     ：Copyright (C) 2017~2021 SupersocksR ORG. All rights reserved
 * DateTime   ：2021-06-02
 * Related    ：Ppp 2/3 layer VEthernet [Mini-Version] (Ppp Windows)
 * Statement1 : Product implementations based on this technology do not allow closed sources and must declare the use of VEthernet
 * Statement2 : If you borrow code to implement the same class or other, you must declare that you borrow VEthernet
 * Statement3 : Do not allow the statement, VEthernet technology independent research and development
 */
namespace tun2socks
{
    using System;
    using System.Diagnostics;
    using System.Linq;
    using System.Net;
    using System.Net.NetworkInformation;
    using System.Net.Sockets;
    using System.Security;
    using VEthernet.Core;
    using VEthernet.Net.Auxiliary;
    using VEthernet.Net.IP;
    using VEthernet.Net.Routing;
    using VEthernet.Net.Tun;
    using VEthernet.Utilits;
    using WebProxy = VEthernet.Net.Internet.WebProxy;

    public static class Program
    {
        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        public static readonly string ApplicationName = "VEthernet (tun2socks{0})";

        [SecurityCritical]
        [SecuritySafeCritical]
        private static bool DeploymentTapWindows()
        {
            string componentId = Layer3Netif.FindAllComponentId().FirstOrDefault();
            if (!string.IsNullOrEmpty(componentId))
            {
                return true;
            }
            else
            {
                Console.WriteLine("Installing the VEthernet Windows Virtual Network Card TAP device driver.");
            }
            if (Layer3Netif.InstallTapWindows(AppDomain.CurrentDomain.BaseDirectory + "\\Driver", "VEthernet"))
            {
                Console.WriteLine("Installed the VEthernet Virtual Network Card TAP device driver to computer.");
                return true;
            }
            else
            {
                Console.WriteLine("Unable to install Virtual Network Card TAP device driver to computer.");
                return false;
            }
        }

        [SecurityCritical]
        [SecuritySafeCritical]
        static Program()
        {
            // Adjust the application system scheduling priority, reference to the source code implementation:
            // https://blog.csdn.net/liulilittle/article/details/121021222
            Priority.AdjustToHighestPriority();
            SocketExtension.PeriodGCCollect = 10000;
        }

        [SecurityCritical]
        [SecuritySafeCritical]
        private static void RepiarDefaultGateway()
        {
            NetworkInterface ni = Layer3Netif.GetPreferredNetworkInterfaceAddress(true, out IPAddress gwAddress);
            if (ni != null)
            {
                IPAddress ipAddress = Layer3Netif.GetNetworkInterfaceAddress(ni, out IPAddress ipMask);
                if (Router.FindAllAnyAddress(out Router.Error error).
                    FirstOrDefault(r => IPFrame.Equals(r.NextHop, gwAddress)) == null)
                {
                    Router.Create(IPAddress.Any, IPAddress.Any, gwAddress, 1);
                }
            }
        }

        [SecurityCritical]
        [SecuritySafeCritical]
        private static bool ToBoolean(string s, bool defaultValue)
        {
            if (string.IsNullOrEmpty(s))
            {
                return defaultValue;
            }
            s = s.ToLower().Trim();
            return s == "y" || s == "yes" || s == "true" || s == "1";
        }

        [MTAThread]
        private static void Main(string[] args)
        {
            Console.Title = string.Format(Program.ApplicationName, string.Empty);
            Console.TreatControlCAsInput = true;
            if (args.Length <= 0)
            {
                Console.WriteLine($"usage: {Process.GetCurrentProcess().MainModule.FileName} --product-mode=[yes|no] --proxyserver=192.168.0.21 --proxyport=1080 --proxyuser=[sa] --proxypassword=[admin] --bypass-iplist=./ip.txt");
                Console.ReadKey(false);
                return;
            }
            if (!Fw.IsAdministrator())
            {
                Console.WriteLine("Please run this program under administrator's privilege.");
                Console.ReadKey(false);
                return;
            }
            else if (!DeploymentTapWindows())
            {
                Console.ReadKey(false);
                return;
            }
            else
            {
                // If the system physical hosting Ethernet card is not correctly configured with a default gateway address (0.0.0.0),
                // tun2socks attempts to calculate the general default gateway address and configure it to the system to
                RepiarDefaultGateway(); // restore the connection to the Internet network.

                WebProxy.Direct(); // Disable system proxy settings.

                // Add or modify tun2socks private/public network firewall rules.
                Fw.NetFirewallAddAllApplication(Program.ApplicationName, Process.GetCurrentProcess().MainModule.FileName);
            }

            // Obtain the valid proxyserver address from the command line interface parameter.
            string proxyserver = Environments.GetCommandArgumentString(args, "--proxyserver") ?? string.Empty;
            if (!IPAddress.TryParse(proxyserver, out IPAddress proxyserverAddress) ||
                proxyserver == null ||
                proxyserverAddress.AddressFamily != AddressFamily.InterNetwork ||
                IPFrame.Equals(IPAddress.Any, proxyserverAddress) ||
                IPFrame.Equals(IPAddress.Broadcast, proxyserverAddress) ||
                IPFrame.Equals(IPAddress.None, proxyserverAddress))
            {
                // Query the dns-server to obtain the IPv4 address of the proxy server.
                try
                {
                    proxyserverAddress = Dns.GetHostAddresses(proxyserver).FirstOrDefault(p =>
                        p.AddressFamily == AddressFamily.InterNetwork &&
                            !IPFrame.Equals(IPAddress.Any, p) &&
                            !IPFrame.Equals(IPAddress.Broadcast, p) &&
                            !IPFrame.Equals(IPAddress.None, p));
                }
                catch (Exception)
                {
                    proxyserverAddress = null;
                }
                if (proxyserverAddress == null)
                {
                    Console.WriteLine("Please use a valid socks5 agent server \"IPv4 or domain\" address.");
                    Console.ReadKey(false);
                    return;
                }
            }

            IPEndPoint serverEP = new IPEndPoint(proxyserverAddress, (int)Environments.GetCommandArgumentInt64(args, "--proxyport").GetValueOrDefault());
            using (Socks5Ethernet ethernet = new Socks5Ethernet(serverEP,
                ToBoolean(Environments.GetCommandArgumentString(args, "--product-mode"), true),
                Environments.GetCommandArgumentString(args, "--proxyuser"),
                Environments.GetCommandArgumentString(args, "--proxypassword"),
                Environments.GetCommandArgumentString(args, "--bypass-iplist"), null))
            {
                Console.Title = string.Format(Program.ApplicationName, $"@{serverEP}");
                Console.WriteLine("Application started. Press Ctrl+C to shut down.");
                ethernet.Listen();
                while (!ethernet.IsDisposed)
                {
                    ConsoleKeyInfo cki = Console.ReadKey(false);
                    if (cki.Key == ConsoleKey.C && cki.Modifiers == ConsoleModifiers.Control
                        || cki.Key == ConsoleKey.Escape)
                    {
                        break;
                    }
                }
                Console.WriteLine("Application is shutting down...");
            }
        }
    }
}
