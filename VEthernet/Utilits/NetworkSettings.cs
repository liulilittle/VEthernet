namespace VEthernet.Utilits
{
    using System.Management;
    using System.Text.RegularExpressions;
    /// <summary>
    /// 网络设置类，设置网络的各种参数（DNS、网关、子网掩码、IP）
    /// </summary>
    public static class NetworkSettings
    {
        /// <summary>
        /// 设置DNS
        /// </summary>
        /// <param name="dns"></param>
        public static void SetDNS(string[] dns)
        {
            SetIPAddress(null, null, null, dns);
        }
        /// <summary>
        /// 设置网关
        /// </summary>
        /// <param name="getway"></param>
        public static void SetGetWay(string getway)
        {
            SetIPAddress(null, null, new string[] { getway }, null);
        }
        /// <summary>
        /// 设置网关
        /// </summary>
        /// <param name="getway"></param>
        public static void SetGetWay(string[] getway)
        {
            SetIPAddress(null, null, getway, null);
        }
        /// <summary>
        /// 设置IP地址和掩码
        /// </summary>
        /// <param name="ip"></param>
        /// <param name="submask"></param>
        public static void SetIPAddress(string ip, string submask)
        {
            SetIPAddress(new string[] { ip }, new string[] { submask }, null, null);
        }
        /// <summary>
        /// 设置IP地址，掩码和网关
        /// </summary>
        /// <param name="ip"></param>
        /// <param name="submask"></param>
        /// <param name="getway"></param>
        public static void SetIPAddress(string ip, string submask, string getway)
        {
            SetIPAddress(new string[] { ip }, new string[] { submask }, new string[] { getway }, null);
        }
        /// <summary>
        /// 设置IP地址，掩码，网关和DNS
        /// </summary>
        /// <param name="ip"></param>
        /// <param name="submask"></param>
        /// <param name="getway"></param>
        /// <param name="dns"></param>
        public static void SetIPAddress(string[] ip, string[] submask, string[] getway, string[] dns)
        {
            ManagementClass wmi = new ManagementClass("Win32_NetworkAdapterConfiguration");
            ManagementObjectCollection moc = wmi.GetInstances();
            ManagementBaseObject inPar = null;
            ManagementBaseObject outPar = null;
            foreach (ManagementObject mo in moc)
            {
                // 如果没有启用IP设置的网络设备则跳过
                if (!(bool)mo["IPEnabled"])
                {
                    continue;
                }

                // 设置IP地址和掩码
                if (ip != null && submask != null)
                {
                    inPar = mo.GetMethodParameters("EnableStatic");
                    inPar["IPAddress"] = ip;
                    inPar["SubnetMask"] = submask;
                    outPar = mo.InvokeMethod("EnableStatic", inPar, null);
                }

                // 设置网关地址
                if (getway != null)
                {
                    inPar = mo.GetMethodParameters("SetGateways");
                    inPar["DefaultIPGateway"] = getway;
                    outPar = mo.InvokeMethod("SetGateways", inPar, null);
                }

                // 设置DNS地址
                if (dns != null)
                {
                    inPar = mo.GetMethodParameters("SetDNSServerSearchOrder");
                    inPar["DNSServerSearchOrder"] = dns;
                    outPar = mo.InvokeMethod("SetDNSServerSearchOrder", inPar, null);
                }
            }
        }
        /// <summary>
        /// 启用DHCP服务器
        /// </summary>
        public static void EnableDHCP()
        {
            ManagementClass wmi = new ManagementClass("Win32_NetworkAdapterConfiguration");
            ManagementObjectCollection moc = wmi.GetInstances();
            foreach (ManagementObject mo in moc)
            {
                // 如果没有启用IP设置的网络设备则跳过
                if (!(bool)mo["IPEnabled"])
                {
                    continue;
                }

                // 重置DNS为空
                mo.InvokeMethod("SetDNSServerSearchOrder", null);

                // 开启DHCP
                mo.InvokeMethod("EnableDHCP", null);
            }
        }
        /// <summary>
        /// 判断是否符合IP地址格式
        /// </summary>
        /// <param name="ip"></param>
        /// <returns></returns>
        public static bool IsIPAddress(string ip)
        {
            // 将完整的IP以“.”为界限分组
            string[] arr = ip.Split('.');

            // 判断IP是否为四组数组成
            if (arr.Length != 4)
            {
                return false;
            }

            // 正则表达式，1~3位整数
            string pattern = @"\d{1,3}";
            for (int i = 0; i < arr.Length; i++)
            {
                string d = arr[i];


                // 判断IP开头是否为0
                if (i == 0 && d == "0")
                {
                    return false;
                }

                //判断IP是否是由1~3位数组成
                if (!Regex.IsMatch(d, pattern))
                {
                    return false;
                }

                if (d != "0")
                {
                    // 判断IP的每组数是否全为0
                    d = d.TrimStart('0');
                    if (d == "")
                    {
                        return false;
                    }

                    // 判断IP每组数是否大于255
                    if (int.Parse(d) > 255)
                    {
                        return false;
                    }
                }
            }
            return true;
        }
    }
}
