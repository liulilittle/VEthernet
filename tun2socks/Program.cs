/*
 * Description: Quick implementation of a no-tech difficulty tun2socks samples
 * Author     ：Copyright (C) 2017~2021 SupersocksR ORG. All rights reserved
 * DateTime   ：2021-06-02
 * Related    ：VEthernet 2/3 layer VEthernet [mini-version]
 * Statement1 : Product implementations based on this technology do not allow closed sources and must declare the use of VEthernet
 * Statement2 : If you borrow code to implement the same class or other, you must declare that you borrow VEthernet
 * Statement3 : Do not allow the statement, VEthernet technology independent research and development
 */
namespace tun2socks
{
    using System;
    using System.Diagnostics;
    using System.IO;
    using System.Linq;
    using System.Net;
    using System.Security;
    using VEthernet.Core;
    using VEthernet.Net.Auxiliary;
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
                Console.WriteLine("Installing the VEthernet Windows Virtual Network Card TAP device driver");
            }
            if (Layer3Netif.InstallTapWindows(AppDomain.CurrentDomain.BaseDirectory + "\\Driver", "VEthernet"))
            {
                Console.WriteLine("Installed the VEthernet Virtual Network Card TAP device driver to computer");
                return true;
            }
            else
            {
                Console.WriteLine("Unable to install Virtual Network Card TAP device driver to computer");
                return false;
            }
        }

        [SecurityCritical]
        [SecuritySafeCritical]
        static Program() => SocketExtension.PeriodGCCollect = 10000;

        [MTAThread]
        private static void Main(string[] args)
        {
            Console.Title = string.Format(Program.ApplicationName, string.Empty);
            Console.TreatControlCAsInput = true;
            if (args.Length <= 0)
            {
                Console.WriteLine($"usage: {Process.GetCurrentProcess().MainModule.FileName} --proxyserver=192.168.0.21 --proxyport=1080 --bypass-iplist=./ip.txt");
                Console.ReadKey(false);
                return;
            }
            if (!Fw.IsAdministrator())
            {
                Console.WriteLine("Please run this program under administrator's privilege");
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
                WebProxy.Direct();
                Fw.NetFirewallAddAllApplication(Program.ApplicationName, Process.GetCurrentProcess().MainModule.FileName);
            }
            IPAddress.TryParse(Environments.GetCommandArgumentString(args, "--proxyserver") ?? string.Empty,
                out IPAddress proxyserver);
            IPEndPoint serverEP = new IPEndPoint(proxyserver, (int)Environments.GetCommandArgumentInt64(args, "--proxyport").GetValueOrDefault());
            using (Socks5Ethernet ethernet = new Socks5Ethernet(serverEP, 
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
