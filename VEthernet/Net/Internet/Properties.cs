namespace VEthernet.Net.Internet
{
    using System;
    using System.Diagnostics;
    using System.Net;
    using System.Runtime.InteropServices;
    using Microsoft.Win32;
    using VEthernet.Core;

    public unsafe static class Properties
    {
        private const string EXPERIMENTALQUICPROTOCOL_POLICIES_CHROME = @"Software\Policies\Google\Chrome";
        private const string EXPERIMENTALQUICPROTOCOL_POLICIES_EDGE = @"Software\Policies\Microsoft\Edge";

        private static class NativeMethods
        {
            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
            public struct INTERNET_PROXY_INFO
            {
                public int dwAccessType;
                public void* proxy;
                public void* proxyBypass;
            };

            [DllImport("wininet.dll", CharSet = CharSet.Ansi, SetLastError = false)]
            public static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);

            [DllImport("kernel32.dll", SetLastError = false, ExactSpelling = true)]
            public static extern void* RtlZeroMemory(void* src, int size);

            [DllImport("ntdll.dll", SetLastError = false, ExactSpelling = true)]
            public static extern void RtlGetNtVersionNumbers(out uint dwMajor, out uint dwMinor, out uint dwBuildNumber);

            [DllImport("shell32.dll", CharSet = CharSet.Unicode, SetLastError = false)]
            public static extern int ShellExecute(IntPtr hWnd, string operation, string filename, string parameters, string directory, int showcmd);

            public const int INTERNET_OPTION_SETTINGS_CHANGED = 39; // 修改设置完成
            public const int INTERNET_OPTION_REFRESH = 37; // 刷新网路设置
            public const int INTERNET_OPTION_PROXY = 38; // 代理服务器设置
            public const int INTERNET_OPTION_PROXY_SETTINGS_CHANGED = 95;

            public const int INTERNET_OPEN_TYPE_PROXY = 3;
        }

        public static RegistryKey Configuration
        {
            get
            {
                try
                {
                    return Registry.CurrentUser.OpenSubKey(
                        @"Software\Microsoft\Windows\CurrentVersion\Internet Settings", true);
                }
                catch
                {
                    return null;
                }
            }
        }

        public static bool Proxy(string server)
        {
            NativeMethods.INTERNET_PROXY_INFO* ipi = (NativeMethods.INTERNET_PROXY_INFO*)Marshal.AllocHGlobal(sizeof(NativeMethods.INTERNET_PROXY_INFO));
            ipi->dwAccessType = NativeMethods.INTERNET_OPEN_TYPE_PROXY;
            ipi->proxy = (void*)Marshal.StringToHGlobalAuto(server ?? string.Empty);
            ipi->proxyBypass = (void*)Marshal.StringToHGlobalAuto("local");
            bool retval = NativeMethods.InternetSetOption(IntPtr.Zero, NativeMethods.INTERNET_OPTION_PROXY, (IntPtr)ipi, sizeof(NativeMethods.INTERNET_PROXY_INFO));
            Marshal.FreeHGlobal((IntPtr)ipi->proxy);
            Marshal.FreeHGlobal((IntPtr)ipi->proxyBypass);
            Marshal.FreeHGlobal((IntPtr)ipi);
            return retval;
        }

        public static bool Update()
        {
            NativeMethods.INTERNET_PROXY_INFO* ipi = (NativeMethods.INTERNET_PROXY_INFO*)Marshal.AllocHGlobal(sizeof(NativeMethods.INTERNET_PROXY_INFO));
            NativeMethods.RtlZeroMemory(ipi, sizeof(NativeMethods.INTERNET_PROXY_INFO));
            bool retval =
                NativeMethods.InternetSetOption(IntPtr.Zero, NativeMethods.INTERNET_OPTION_PROXY_SETTINGS_CHANGED, IntPtr.Zero, 0) &&
                NativeMethods.InternetSetOption(IntPtr.Zero, NativeMethods.INTERNET_OPTION_SETTINGS_CHANGED, (IntPtr)ipi, sizeof(NativeMethods.INTERNET_PROXY_INFO)) &&
                NativeMethods.InternetSetOption(IntPtr.Zero, NativeMethods.INTERNET_OPTION_REFRESH, IntPtr.Zero, 0);
            Marshal.FreeHGlobal((IntPtr)ipi);
            return retval;
        }

        public static bool OpenControlWindow() => OpenControlWindow(0);

        public static bool OpenProxySettingsWindow()
        {
            NativeMethods.RtlGetNtVersionNumbers(out uint dwMajor, out uint dwMinor, out uint dwBuildNumber);
            if (dwMajor >= 10) // How-to: Quickly open control panel applets with ms-settings
            {                  // https://ss64.com/nt/syntax-settings.html
                if (NativeMethods.ShellExecute(IntPtr.Zero, "open", "ms-settings:network-proxy", null, null, 1) != 0)
                {
                    return true;
                }
            }
            return OpenControlWindow(4);
        }

        public unsafe static bool PacketIsQUIC(IPEndPoint destinationEP, BufferSegment messages)
        {
            if (destinationEP == null || messages == null || messages.Length < 1)
            {
                return false;
            }
            if (destinationEP.Port != 443 && destinationEP.Port != 80)
            {
                return false;
            }
            try
            {
                fixed (byte* pinned = messages.Buffer)  // QUIC IETF
                {
                    byte* p = pinned + messages.Offset;
                    byte* l = p + messages.Length;
                    byte kf = *p++;
                    int F_Header_Form = Extension.GetBitValueAt(kf, 7);
                    int F_Fixed_Bit = Extension.GetBitValueAt(kf, 6);
                    int F_Packet_Type_Bit = Extension.GetBitValueAt(kf, 5) << 1 | Extension.GetBitValueAt(kf, 4);
                    if (F_Header_Form != 0x01 || F_Fixed_Bit != 0x01)
                    {
                        return false;
                    }
                    if (F_Packet_Type_Bit == 0x00) // Initial(0)
                    {
                        int F_Reserved_Bit = Extension.GetBitValueAt(kf, 3) << 1 | Extension.GetBitValueAt(kf, 3);
                        int F_Packet_Number_Length_Bit = Extension.GetBitValueAt(kf, 1) << 1 | Extension.GetBitValueAt(kf, 0);
                        if (F_Packet_Number_Length_Bit == 0x00 && F_Reserved_Bit == 0x00)
                        {
                            return false;
                        }
                    }
                    else if (F_Packet_Type_Bit != 0x02) // Handshake(2)
                    {
                        return false;
                    }
                    p += 0x04;
                    if (p > l)
                    {
                        return false;
                    }
                    uint Version = CheckSum.ntohl(((uint*)p)[-1]);
                    if (Version != 0x01) // Version
                    {
                        return false;
                    }
                    int Destination_Connection_ID_Length = *p++;
                    p += Destination_Connection_ID_Length;
                    if (p > l || Destination_Connection_ID_Length < 0x01)
                    {
                        return false;
                    }
                    int Source_Connection_ID_Length = *p++;
                    p += Source_Connection_ID_Length;
                    if (p > l)
                    {
                        return false;
                    }
                    if (F_Packet_Type_Bit == 0x00) // Initial(0)
                    {
                        int Token_Length = *p++;
                        p += Token_Length;
                        if (p > l || Token_Length < 0x01)
                        {
                            return false;
                        }
                    }
                    int Packet_Length = CheckSum.ntohs(*(ushort*)p) & 0x3FFF;
                    p += 0x02;
                    if (p > l || Packet_Length < 0x01)
                    {
                        return false;
                    }
                    p += Packet_Length;
                    return p == l;
                }
            }
            catch
            {
                return false;
            }
        }

        private static bool IsSupportExperimentalQuicProtocol(string key)
        {
            object v = GetValue(Registry.CurrentUser, key, "QuicAllowed");
            if (v == null)
            {
                return true;
            }
            try
            {
                int n = Convert.ToInt32(v);
                return n != 0;
            }
            catch
            {
                return true;
            }
        }

        public static object GetValue(RegistryKey root, string section, string key)
        {
            if (root == null || string.IsNullOrEmpty(key) || string.IsNullOrEmpty(section))
            {
                return null;
            }
            RegistryKey rk = null;
            try
            {
                rk = root.OpenSubKey(section, false);
                if (rk == null)
                {
                    return null;
                }
                using (rk)
                {
                    try
                    {
                        return rk.GetValue(key);
                    }
                    catch
                    {
                        return null;
                    }
                }
            }
            catch
            {
                return null;
            }
        }

        public static bool SetSupportExperimentalQuicProtocol(string key, bool value)
        {
            return SetValue(Registry.CurrentUser, key, "QuicAllowed", value ? 1 : 0);
        }

        public static bool SetValue<T>(RegistryKey root, string section, string key, T value)
        {
            if (root == null || string.IsNullOrEmpty(key) || string.IsNullOrEmpty(section))
            {
                return false;
            }
            RegistryKey rk = null;
            try
            {
                rk = root.CreateSubKey(section,
                    RegistryKeyPermissionCheck.ReadWriteSubTree, RegistryOptions.Volatile);
            }
            catch
            {
                try
                {
                    rk = root.OpenSubKey(section);
                }
                catch { }
            }
            if (rk == null)
            {
                return false;
            }
            try
            {
                using (rk)
                {
                    try
                    {
                        rk.SetValue(key, value);
                        return true;
                    }
                    catch { }
                }
            }
            catch { }
            return false;
        }

        public static bool SupportExperimentalQuicProtocol
        {
            get
            {
                return
                    IsSupportExperimentalQuicProtocol(EXPERIMENTALQUICPROTOCOL_POLICIES_EDGE) ||
                    IsSupportExperimentalQuicProtocol(EXPERIMENTALQUICPROTOCOL_POLICIES_CHROME);
            }
            set
            {
                SetSupportExperimentalQuicProtocol(EXPERIMENTALQUICPROTOCOL_POLICIES_EDGE, value);
                SetSupportExperimentalQuicProtocol(EXPERIMENTALQUICPROTOCOL_POLICIES_CHROME, value);
            }
        }

        public static bool OpenControlWindow(int TabIndex)
        {
            // control.exe inetcpl.cpl
            try
            {
                string cmd = "shell32,Control_RunDLL inetcpl.cpl";
                if (TabIndex > 0)
                {
                    cmd += ",," + TabIndex;
                }
                Process process = Process.Start("rundll32", cmd);
                if (process != null)
                {
                    process.Dispose();
                }
                return true;
            }
            catch
            {
                return false;
            }
        }
    }
}
