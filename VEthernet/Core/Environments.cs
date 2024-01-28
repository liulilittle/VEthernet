namespace VEthernet.Core
{
    using System;
    using System.Diagnostics;
    using System.Linq;
    using System.Runtime.InteropServices;
    using System.Threading;
#if NETCOREAPP
    using System.Runtime.CompilerServices;
#endif

    public static class Environments
    {
        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private static readonly PlatformID _platformID = Environment.OSVersion.Platform;

        public static PlatformID Platform
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            get => _platformID;
        }

        public static bool TreatControlCAsInput
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            get
            {
                try
                {
                    return Console.TreatControlCAsInput;
                }
                catch
                {
                    return false;
                }
            }
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            set
            {
                try
                {
                    Console.TreatControlCAsInput = value;
                }
                catch { }
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static ConsoleKeyInfo ReadKey()
        {
            try
            {
                return Console.ReadKey();
            }
            catch
            {
                try
                {
                    Thread.Sleep(200);
                }
                catch { }
                return new ConsoleKeyInfo('\x0', (ConsoleKey)(0), false, false, false);
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static ConsoleKeyInfo ReadKey(bool intercept)
        {
            try
            {
                return Console.ReadKey(intercept);
            }
            catch
            {
                try
                {
                    Thread.Sleep(200);
                }
                catch { }
                return new ConsoleKeyInfo('\x0', (ConsoleKey)(0), false, false, false);
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static bool Write(this string s, params object[] args)
        {
            try
            {
                if (args == null || args.Length < 1)
                {
                    Console.Write(s);
                }
                else
                {
                    Console.Write(s, args);
                }
                return true;
            }
            catch
            {
                return false;
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static bool WriteLine(this string s, params object[] args)
        {
            try
            {
                if (args == null || args.Length < 1)
                {
                    Console.WriteLine(s);
                }
                else
                {
                    Console.WriteLine(s, args);
                }
                return true;
            }
            catch
            {
                return false;
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static string GetCommandArgumentString(this string[] args, string key)
        {
            if (args == null || args.Length < 1)
                return null;
            for (int i = 0; i < args.Length; i++)
            {
                string s = (args[i] ?? string.Empty).TrimStart().TrimEnd();
                int j = s.IndexOf('=');
                if (j < 0)
                {
                    if (key != s)
                        continue;
                    return s;
                }
                string p = s.Substring(0, j);
                if (string.IsNullOrEmpty(p))
                    continue;
                if (p != key)
                    continue;
                return s.Substring(j + 1).TrimStart().TrimEnd();
            }
            return null;
        }

        public enum CtrlTypes
        {
            CTRL_C_EVENT = 0,
            CTRL_BREAK_EVENT,
            CTRL_CLOSE_EVENT,
            CTRL_LOGOFF_EVENT = 5,
            CTRL_SHUTDOWN_EVENT
        }

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool HandlerRoutine(CtrlTypes CtrlType);

        [DllImport("kernel32.dll", SetLastError = false, ExactSpelling = true)]
        private static extern bool SetConsoleCtrlHandler([MarshalAs(UnmanagedType.FunctionPtr)] HandlerRoutine Handler, bool Add);

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static T Pinned<T>(T obj)
        {
            GCHandle.Alloc(obj);
            return (T)obj;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static void SetConsoleCtrlHandler(HandlerRoutine routine)
        {
            if (routine == null)
            {
                throw new ArgumentNullException(nameof(routine));
            }
            SetConsoleCtrlHandler(routine, true);
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static string[] GetCommandLineArgs()
        {
            string[] s = Environment.GetCommandLineArgs();
            if (s == null || s.Length < 1)
            {
                return new string[0];
            }
            return s.Skip(1).ToArray();
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static long? GetCommandArgumentInt64(this string[] args, string key)
        {
            string s = args.GetCommandArgumentString(key);
            if (string.IsNullOrEmpty(s))
                return null;
            if (!long.TryParse(s, out long r))
                return null;
            return r;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static ulong? GetCommandArgumentUInt64(this string[] args, string key)
        {
            string s = args.GetCommandArgumentString(key);
            if (string.IsNullOrEmpty(s))
                return null;
            if (!ulong.TryParse(s, out ulong r))
                return null;
            return r;
        }

        [DllImport("msvcrt.dll", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl, EntryPoint = "system", ExactSpelling = true)]
        public static extern void System(string command);

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static string Echo(string exec, string args)
        {
            var si = new ProcessStartInfo()
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                FileName = exec,
                Arguments = args,
                RedirectStandardOutput = true,
                RedirectStandardInput = true,
                RedirectStandardError = true,
            };
            try
            {
                using (var po = Process.Start(si))
                {
                    try
                    {
                        return po.StandardOutput.ReadLine();
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

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static bool ExecuteCommands(params string[] commands)
        {
            return ExecuteCommands(true, commands);
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static bool ExecuteCommands(bool waitForExit, params string[] commands)
        {
            if (commands == null)
            {
                return false;
            }
            for (int i = 0; i < commands.Length; i++)
            {
                string arguments = commands[i];
                if (string.IsNullOrEmpty(arguments))
                {
                    continue;
                }
                string fileName = string.Empty;
                if (arguments[0] == '\"')
                {
                    if (arguments.Length <= 2)
                    {
                        continue;
                    }
                    int j = arguments.IndexOf('\"', 1);
                    if (j < 0)
                    {
                        continue;
                    }
                    else
                    {
                        fileName = arguments.Substring(1, j - 1);
                        arguments = arguments.Substring(j + 1).TrimStart();
                    }
                }
                else
                {
                    int j = arguments.IndexOf(' ');
                    if (j < 0)
                    {
                        fileName = arguments;
                    }
                    else
                    {
                        fileName = arguments.Substring(0, j);
                        arguments = arguments.Substring(j + 1);
                    }
                }
                var si = new ProcessStartInfo()
                {
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    FileName = fileName,
                    Arguments = arguments,
                };
                try
                {
                    using (var po = Process.Start(si))
                    {
                        try
                        {
                            if (waitForExit)
                            {
                                po.WaitForExit();
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
            return false;
        }
    }
}
