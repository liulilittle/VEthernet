namespace VEthernet.Net.Routing
{
    using System;
    using System.Collections.Generic;
    using System.Net;
    using global::VEthernet.Net.Tools;
    using VEthernet.Net.IP;

    public static class Router
    {
        public enum Error
        {
            Success,
            ObjectAlreadyExists,
            NetworkInterfaceNotExists,
            OperationsAreNotSupported,
            PermissionsNotEnough,
            ArgumentOutRangeException,
        }

        private const int ERROR_SUCCESS = 0;
        private const int ERROR_ACCESS_DENIED = 5;
        private const int ERROR_INVALID_PARAMETER = 87;
        private const int ERROR_NOT_FOUND = 1168;
        private const int ERROR_NOT_SUPPORTED = 50;
        private const int ERROR_OBJECT_ALREADY_EXISTS = 5010;

        private static Error ConvertError(int error)
        {
            switch (error)
            {
                case ERROR_SUCCESS:
                    return Error.Success;
                case ERROR_OBJECT_ALREADY_EXISTS:
                    return Error.ObjectAlreadyExists;
                case ERROR_NOT_FOUND:
                    return Error.NetworkInterfaceNotExists;
                case ERROR_NOT_SUPPORTED:
                    return Error.OperationsAreNotSupported;
                case ERROR_ACCESS_DENIED:
                    return Error.PermissionsNotEnough;
                default:
                    return Error.ArgumentOutRangeException;
            };
        }

        public static RouteInformation Find(IPAddress destination, IPAddress gateway, out Error error)
        {
            error = Error.ArgumentOutRangeException;
            if (destination == null)
            {
                destination = IPAddress.Any;
            }
            if (gateway == null)
            {
                gateway = IPAddress.Any;
            }
            int errno = RouteTableManager.GetIpForwardEntry(destination, gateway, out RouteInformation route);
            error = ConvertError(errno);
            return route;
        }

        public static RouteInformation Find(IPAddress destination, out Error error)
        {
            error = Error.ArgumentOutRangeException;
            if (destination == null)
            {
                destination = IPAddress.Any;
            }
            int errno = RouteTableManager.GetIpForwardEntry(destination, out RouteInformation route);
            error = ConvertError(errno);
            return route;
        }

        public static Error Set(RouteInformation route)
        {
            if (route == null)
            {
                return Error.ArgumentOutRangeException;
            }
            int errno = RouteTableManager.SetIpForwardEntry(route);
            return ConvertError(errno);
        }

        public static RouteInformation[] FindAll(out Error error)
        {
            int errno = RouteTableManager.GetIpForwardTable(out RouteInformation[] routes);
            error = ConvertError(errno);
            if (routes == null)
            {
                routes = new RouteInformation[0];
            }
            return routes;
        }

        public static int Flush(out Error error)
        {
            return Delete(FindAll(out error));
        }

        public static int Create(IEnumerable<RouteInformation> routes)
        {
            int events = 0;
            if (routes == null)
            {
                return events;
            }
            foreach (RouteInformation route in routes)
            {
                if (route == null)
                {
                    continue;
                }
                int errno = RouteTableManager.CreateIpForwardEntry(route);
                if (errno == ERROR_SUCCESS)
                {
                    events++;
                }
            }
            return events;
        }

        public static int Delete(IEnumerable<RouteInformation> routes)
        {
            int events = 0;
            if (routes == null)
            {
                return events;
            }
            foreach (RouteInformation route in routes)
            {
                if (route == null)
                {
                    continue;
                }
                int errno = RouteTableManager.DeleteIpForwardEntry(route);
                if (errno == ERROR_SUCCESS)
                {
                    events++;
                }
            }
            return events;
        }

        public static RouteInformation[] FindAllAnyAddress(out Error error)
        {
            RouteInformation[] routes = FindAll(out error);
            if (routes == null)
            {
                routes = new RouteInformation[0];
            }
            if (routes.Length < 1)
            {
                return routes;
            }
            List<RouteInformation> caches = new List<RouteInformation>();
            IPAddress cirdMiddleMask = IPAddress.Parse("128.0.0.0"); // 0.0.0.0/1
            foreach (RouteInformation route in routes) 
            {
                /* 
                 * +------------------------------------------------------+
                 * + 本子程序仅查找通用规则的以太网卡驱动配置的系统全局路由    +
                 * + 为不保存整个路由表并且清空系统路由表而设计               +
                 * + 仅查找全局路由信息保存并且从内核中移除路由               +
                 * +------------------------------------------------------+
                 *  VPN：PPTP / L2TP / OpenVPN / SoftEther / SkylakeNAT
                 *  IIF：Realtek / Intel / Ralink / Broadcom / Marvell..... 
                 */
                if (route == null) 
                {
                    continue;
                }
                // 0.0.0.0 MASK 0.0.0.0（以太网卡设备驱动在配置有效的下个跳数[指网关]时为缺省网卡所有IP从此接口出站）
                if (IPFrame.Equals(route.Destination, IPAddress.Any) && IPFrame.Equals(route.Mask, IPAddress.Any))
                {
                    caches.Add(route);
                    continue;
                }
                // 128.0.0.0 MASK 0.0.0.0（多用于点对点虚拟网卡链路-VPN）
                if (IPFrame.Equals(route.Mask, cirdMiddleMask) && IPFrame.Equals(route.Destination, IPAddress.Any))
                {
                    caches.Add(route);
                    continue;
                }
                // 0.0.0.0 MASK 128.0.0.0（多用于点多点虚拟网卡链路-VPN）
                if (IPFrame.Equals(route.Mask, cirdMiddleMask) && IPFrame.Equals(route.Destination, cirdMiddleMask))
                {
                    caches.Add(route);
                    continue;
                }
            }
            return caches.ToArray();
        }

        public static Error DeleteFast(IPAddress destination, IPAddress mask, IPAddress gateway, int metric)
        {
            if (destination == null)
            {
                destination = IPAddress.Any;
            }
            if (mask == null)
            {
                mask = IPAddress.Any;
            }
            if (gateway == null)
            {
                gateway = IPAddress.Any;
            }
            int err = RouteTableManager.GetBestInterface(destination, out uint ifIndex);
            if (err != 0)
            {
                return ConvertError(err);
            }
            err = RouteTableManager.DeleteIpForwardEntry(new RouteInformation()
            {
                Destination = destination,
                Mask = mask,
                NextHop = gateway,
                IfIndex = ifIndex,
                Metric = metric,
                Policy = 0,
                Type = RouteTableManager.MIB_IPFORWARD_TYPE.MIB_IPROUTE_TYPE_DIRECT,
                Proto = RouteTableManager.MIB_IPPROTO.MIB_IPPROTO_NETMGMT,
                Age = 0,
                NextHopAS = 0
            });
            return ConvertError(err);
        }

        public static Error Create(IPAddress destination, IPAddress gateway, int metric)
        {
            if (destination == null)
            {
                destination = IPAddress.Any;
            }
            if (gateway == null)
            {
                gateway = IPAddress.Any;
            }
            int error = RouteTableManager.CreateIpForwardEntry(destination, gateway, metric);
            return ConvertError(error);
        }

        public static Error Create(IPAddress destination, IPAddress mask, IPAddress gateway, int metric)
        {
            if (destination == null)
            {
                destination = IPAddress.Any;
            }
            if (mask == null)
            {
                mask = IPAddress.Any;
            }
            if (gateway == null)
            {
                gateway = IPAddress.Any;
            }
            int error = RouteTableManager.CreateIpForwardEntry(destination, mask, gateway, metric);
            return ConvertError(error);
        }

        public static Error Create(IPAddress destination, IPAddress mask, IPAddress gateway, int ifIndex, int metric)
        {
            if (destination == null)
            {
                destination = IPAddress.Any;
            }
            if (mask == null)
            {
                mask = IPAddress.Any;
            }
            if (gateway == null)
            {
                gateway = IPAddress.Any;
            }
            int error = RouteTableManager.CreateIpForwardEntry(destination, mask, gateway, (uint)ifIndex, metric);
            return ConvertError(error);
        }

        public static Error Delete(IPAddress destination)
        {
            if (destination == null)
            {
                destination = IPAddress.Any;
            }
            int error = RouteTableManager.DeleteIpForwardEntry(destination);
            return ConvertError(error);
        }

        public static Error Delete(IPAddress destination, IPAddress gateway)
        {
            if (destination == null)
            {
                destination = IPAddress.Any;
            }
            if (gateway == null)
            {
                gateway = IPAddress.Any;
            }
            int error = RouteTableManager.DeleteIpForwardEntry(destination, gateway);
            return ConvertError(error);
        }

        public static int DeleteFast(IEnumerable<IPAddressRange> addresses, IPAddress gateway)
        {
            return AddDeleteFast(true, addresses, gateway);
        }

        public static int AddFast(IEnumerable<IPAddressRange> addresses, IPAddress gateway)
        {
            return AddDeleteFast(false, addresses, gateway);
        }

        private static int AddDeleteFast(bool deleted, IEnumerable<IPAddressRange> addresses, IPAddress gateway)
        {
            if (gateway == null)
            {
                gateway = IPAddress.Any;
            }
            int events = 0;
            if (addresses == null)
            {
                return events;
            }
            foreach (IPAddressRange i in addresses)
            {
                IPAddress destination = i.Begin;
                IPAddress mask = IPAddress.Any;
                try
                {
                    int crid = i.GetPrefixLength();
                    mask = IPAddressRange.SubnetMaskAddress(crid);
                }
                catch { }
                do
                {
                    Router.Error error = Router.Error.OperationsAreNotSupported;
                    if (deleted)
                    {
                        error = Router.DeleteFast(destination, mask, gateway, 1);
                    }
                    else
                    {
                        error = Router.Create(destination, mask, gateway, 1);
                    }
                    if (error == Router.Error.ObjectAlreadyExists || error == Router.Error.Success)
                    {
                        events++;
                    }
                } while (false);
            }
            return events;
        }

        public static Error DeleteAll(IPAddress gateway)
        {
            return DeleteAll(gateway, null);
        }

        public static Error DeleteAll(IPAddress gateway, Func<RouteInformation, bool> predicate)
        {
            RouteInformation[] routes = FindAll(out Error error);
            if (error != Error.Success)
            {
                return error;
            }

            if (gateway == null)
            {
                gateway = IPAddress.Any;
            }

            foreach (RouteInformation route in routes)
            {
                if (route == null)
                {
                    continue;
                }

                if (!IPFrame.Equals(route.NextHop, gateway))
                {
                    continue;
                }

                if (predicate == null || predicate(route))
                {
                    RouteTableManager.DeleteIpForwardEntry(route);
                }
            }
            return Error.Success;
        }
    }
}
