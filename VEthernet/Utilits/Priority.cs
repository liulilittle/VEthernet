namespace VEthernet.Utilits
{
    using System;
    using System.Diagnostics;
    using System.IO;
    using System.Runtime.InteropServices;
    using System.Text;
    using VEthernet.Core;

    public static unsafe class Priority
    {
        [DllImport("libc", EntryPoint = "getpid", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        private static extern int getpid();

        [DllImport("libc", EntryPoint = "setpriority", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        private static extern int setpriority(int which, int who, int prio);

        [DllImport("libc", EntryPoint = "sched_get_priority_max", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        private static extern int sched_get_priority_max(int policy);

        [DllImport("libc", EntryPoint = "sched_setscheduler", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        private static extern int sched_setscheduler(int __pid, int __policy, sched_param* __param);

        [DllImport("kernel32.dll", EntryPoint = "SetPriorityClass", CallingConvention = CallingConvention.StdCall, ExactSpelling = true)]
        private static extern bool SetPriorityClass(IntPtr hProcess, uint dwPriorityClass);

        private const uint HIGH_PRIORITY_CLASS = 128;
        private const int PRIO_PROCESS = 0;
        private const int SCHED_FIFO = 1;
        private const int SCHED_RR = 2;

        /* The official definition.  */
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct sched_param
        {
            public int sched_priority;
        };

        public static void AdjustToHighestPriority()
        {
            if (Environments.Platform == PlatformID.Win32NT)
            {
                IntPtr hProcess = Process.GetCurrentProcess().Handle;
                SetPriorityClass(hProcess, HIGH_PRIORITY_CLASS);
            }
            else
            {
                PreventOOM();

                /* Processo pai deve ter prioridade maior que os filhos. */
                setpriority(PRIO_PROCESS, 0, -20);

                /* ps -eo state,uid,pid,ppid,rtprio,time,comm */
                sched_param param_;
                param_.sched_priority = sched_get_priority_max(SCHED_FIFO); // SCHED_RR
                sched_setscheduler(getpid(), SCHED_RR, &param_);
            }
        }

        private static bool PreventOOM()
        {
            int pid = getpid();
            string path = $"/proc/{pid}/oom_adj";
            try
            {
                File.WriteAllText(path, "-17", Encoding.ASCII);
                return true;
            }
            catch
            {
                return false;
            }
        }
    }
}
