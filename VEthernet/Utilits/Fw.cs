namespace VEthernet.Utilits
{
    using System;
    using System.IO;
#if NETCOREAPP
    using System.Runtime.CompilerServices;
#endif
    using System.Runtime.InteropServices;
    using System.Security.Principal;

    public static class Fw
    {
#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static bool IsAdministrator()
        {
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static void NetFirewallAddAllApplication(string name, string executablePath)
        {
            if (!Fw.NetFirewallAddApplication(name, executablePath))
            {
                for (int c = 0; c < 3; c++)
                {
                    bool ok = Fw.NetFirewallAddApplication(name, executablePath, 1)
                        & Fw.NetFirewallAddApplication(name, executablePath, 2);
                    if (ok)
                    {
                        break;
                    }
                }
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static bool NetFirewallAddApplication(string name, string executablePath, int netFwType)
        {
            if (string.IsNullOrEmpty(name) || string.IsNullOrEmpty(executablePath))
            {
                return false;
            }
            if (!File.Exists(executablePath))
            {
                return false;
            }
            dynamic netFwMgr = null;
            dynamic netFwProfile = null;
            dynamic netFwApp = null;
            try
            {
                netFwMgr = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwMgr"));
                netFwProfile = netFwMgr.LocalPolicy.GetProfileByType(netFwType);
                netFwApp = Activator.
                    CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwAuthorizedApplication"));

                // 在例外列表里，程序显示的名称
                netFwApp.Name = name;

                // 程序的路径及文件名
                netFwApp.ProcessImageFileName = executablePath;

                // 是否启用该规则
                netFwApp.Enabled = true;

                // 加入到防火墙的管理策略
                netFwProfile.AuthorizedApplications.Add(netFwApp);
                return true;
            }
            catch
            {
                return false;
            }
            finally
            {
                object[] comObjects = { netFwMgr, netFwProfile, netFwApp };
                foreach (object comObject in comObjects)
                {
                    if (comObject == null)
                    {
                        continue;
                    }
                    IDisposable disposable = comObject as IDisposable;
                    if (disposable != null)
                    {
                        disposable.Dispose();
                    }
                    Marshal.ReleaseComObject(comObject);
                    Marshal.FinalReleaseComObject(comObject);
                }
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static bool NetFirewallAddApplication(string name, string executablePath)
        {
            dynamic rule = null;
            dynamic policy = null;
            dynamic rules = null;
            try
            {
                policy = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));
                rules = policy.Rules;
                foreach (dynamic i in rules)
                {
                    if (i.Name == name)
                    {
                        if (i.ApplicationName == executablePath)
                        {
                            rules.Remove(name);
                        }
                    }
                }
                rule = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule"));
                rule.Name = name;
                rule.Description = name;
                rule.ApplicationName = executablePath;
                rule.Direction = 1;
                rule.Action = 1;
                rule.Enabled = true;
                rules.Add(rule);
                return true;
            }
            catch
            {
                return false;
            }
            finally
            {
                object[] comObjects = { rule, rules, policy };
                foreach (object comObject in comObjects)
                {
                    if (comObject == null)
                    {
                        continue;
                    }
                    IDisposable disposable = comObject as IDisposable;
                    if (disposable != null)
                    {
                        disposable.Dispose();
                    }
                    Marshal.ReleaseComObject(comObject);
                    Marshal.FinalReleaseComObject(comObject);
                }
            }
        }
    }
}
