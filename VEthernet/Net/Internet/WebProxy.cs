namespace VEthernet.Net.Internet
{
    using System;
    using System.Text.RegularExpressions;
    using Microsoft.Win32;

    public static class WebProxy
    {
        private static bool RegistrySetValue(RegistryKey registry, string key, object value)
        {
            if (registry != null && !string.IsNullOrEmpty(key))
            {
                try
                {
                    registry.SetValue(key, value);
                    return true;
                }
                catch { }
            }
            return false;
        }

        private static T RegistryGetValue<T>(RegistryKey registry, string key)
        {
            object obj = null;
            if (registry != null && !string.IsNullOrEmpty(key))
            {
                try
                {
                    obj = registry.GetValue(key, null);
                }
                catch { }
            }
            if (obj != null)
            {
                return (T)obj;
            }
            return default(T);
        }

        private static bool SetProxy(string server, string pac, bool enabled)
        {
            try
            {
                using (RegistryKey registry = Properties.Configuration)
                {
                    if (registry == null)
                    {
                        return false;
                    }
                    try
                    {
                        RegistrySetValue(registry, "ProxyServer", server);
                        RegistrySetValue(registry, "ProxyEnable", (enabled ? 1 : 0));
                        RegistrySetValue(registry, "AutoConfigURL", pac);
                        Properties.Proxy(server);
                        RegistrySetValue(registry, "ProxyOverride", "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;172.32.*;192.168.*;<local>");
                        Properties.Update();
                        if (!Regex.IsMatch(RegistryGetValue<string>(registry, "ProxyServer") ?? string.Empty, server))
                        {
                            RegistrySetValue(registry, "ProxyServer", server);
                            RegistrySetValue(registry, "ProxyEnable", (enabled ? 1 : 0));
                            RegistrySetValue(registry, "AutoConfigURL", pac);
                            Properties.Proxy(server);
                            RegistrySetValue(registry, "ProxyOverride", "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;172.32.*;192.168.*;<local>");
                            Properties.OpenControlWindow();
                        }
                        return true;
                    }
                    catch
                    {
                        return false;
                    }
                }
            }
            catch
            {
                return false;
            }
        }

        public static bool Global(string server)
        {
            if (string.IsNullOrEmpty(server))
            {
                return false;
            }
            return SetProxy(server, string.Empty, true);
        }

        public static bool Pac(string url)
        {
            if (string.IsNullOrEmpty(url))
            {
                return false;
            }
            return SetProxy(string.Empty, url, true);
        }

        public static bool Direct()
        {
            return SetProxy(string.Empty, string.Empty, false);
        }
    }
}
