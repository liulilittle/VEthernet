namespace VEthernet.Net
{
    using System;
    using System.Collections.Concurrent;
    using System.Collections.Generic;
    using System.Net;
    using System.Runtime.InteropServices;
    using System.Security;
    using System.Threading;
    using VEthernet.Core;
    using VEthernet.Net.IP;
    using VEthernet.Net.LwIP;
    using VEthernet.Net.Tun;
    using Timer = VEthernet.Threading.Timer;

    public unsafe class Tap : IDisposable
    {
        [DllImport("libtcpip.dll", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        private static extern void* libtcpip_loop_stream(void* handle, void* buff, int length, int state, [MarshalAs(UnmanagedType.FunctionPtr)] LIBTCPIP_LOOP_STREAM_CALLBACK callback);

        [DllImport("libtcpip.dll", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        private static extern void libtcpip_stop_stream(void* handle);

        [DllImport("libtcpip.dll", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        private static extern bool libtcpip_write_stream(void* handle, void* buffer, int length);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl, SetLastError = false)]
        [SuppressUnmanagedCodeSecurity]
        private delegate void LIBTCPIP_LOOP_STREAM_CALLBACK(int state, int length);

        private readonly int _kid = 0;
        private GCHandle _gch;
        private bool _disposed = false;
        private void* _stream = null;

        private static int _gkid = 0;
        private static GCHandle _gccb;
        private static LIBTCPIP_LOOP_STREAM_CALLBACK _pccb = null;
        private static readonly ConcurrentDictionary<long, Tap> _taps = new ConcurrentDictionary<long, Tap>();

        public IntPtr Handle { get; }

        public string Id { get; }

        public int Index { get; }

        public string Name { get; }

        public bool ValidateChecksum { get; set; }

        public byte[] Buffer { get; } = new byte[IPv4Layer.MTU];

        public virtual IPAddress LocalAddress => Netstack.LocalAddress;

        public virtual IPAddress NetworkMask => Netstack.NetworkMask;

        public virtual IPAddress GatewayAddress => Netstack.GatewayAddress;

        static Tap()
        {
            _pccb = (state, length) =>
            {
                _taps.TryGetValue(state, out Tap tap);
                if (tap != null)
                {
                    tap.Loopback(length);
                }
            };
            _gccb = GCHandle.Alloc(_pccb);
        }

        public Tap(string componentId)
        {
            this.Handle = Layer3Netif.OpenTunDev(componentId);
            if (IntPtr.Zero == this.Handle)
            {
                throw new SystemException("Unable to open netif specifying componentId");
            }
            for (; ; )
            {
                _kid = Interlocked.Increment(ref _gkid);
                if (_kid == 0)
                {
                    continue;
                }
                if (_taps.TryAdd(_kid, this))
                {
                    break;
                }
            }
            this._gch = GCHandle.Alloc(this.Buffer, GCHandleType.Pinned);
            this.Id = componentId;
            this.Index = Layer3Netif.GetAdapterIndex(componentId);
            this.Name = Layer3Netif.GetAdapterName(componentId);
        }

        ~Tap() => this.Dispose();

        public event EventHandler<IPFrame> Input = default(EventHandler<IPFrame>);

        public static ICollection<string> FindAllComponentId() => Layer3Netif.FindAllComponentId();

        private void Loopback(int length)
        {
            if (length < 0)
            {
                this.Dispose();
                return;
            }
            if (length > 0)
            {
                IPFrame frame = IPv4Layer.ParseFrame(new BufferSegment(this.Buffer, 0, length), this.ValidateChecksum);
                if (frame != null)
                {
                    this.OnInput(frame);
                }
            }
        }

        public virtual bool Output(BufferSegment packet)
        {
            if (this._disposed)
            {
                return false;
            }
            if (packet == null || packet.Length < 1 || packet.Offset < 0)
            {
                return false;
            }
            byte[] buffer = packet.Buffer;
            if ((packet.Length + packet.Offset) > buffer.Length)
            {
                return false;
            }
            fixed (byte* buff = &buffer[packet.Offset])
            {
                return libtcpip_write_stream(this._stream, buff, packet.Length);
            }
        }

        protected virtual void OnInput(IPFrame packet)
        {
            var events = this.Input;
            if (events != null)
            {
                events(this, packet);
            }
        }

        public virtual bool Listen()
        {
            Exception exception = null;
            GCHandle[] pinneds = null;
            do
            {
                if (this._disposed)
                {
                    exception = new ObjectDisposedException($"Managed or unmanaged resources held by the TAP device have been released");
                    return false;
                }
                byte[] dhcp = { 10, 0, 0, 0, 10, 0, 0, 1, 255, 255, 0, 0, 0, 1, 81, 128 };
                byte[] ip = { 10, 0, 0, 1, 10, 0, 0, 0, 255, 255, 0, 0 };
                byte[] dns = { 6, 8, 8, 8, 8, 8, 4, 4, 4, 4 };
                byte[] status = { 1, 0, 0, 0 };
                pinneds = new GCHandle[]
                {
                    GCHandle.Alloc(dhcp, GCHandleType.Pinned),
                    GCHandle.Alloc(ip, GCHandleType.Pinned),
                    GCHandle.Alloc(dns, GCHandleType.Pinned),
                    GCHandle.Alloc(status, GCHandleType.Pinned),
                };
                if (!Layer3Netif.DeviceIoControl(this.Handle, Layer3Netif.TAP_WIN_IOCTL_SET_MEDIA_STATUS, status)) // netif-up
                {
                    exception = new SystemException("Unable to pull up the TAP Ethernet network card");
                    break;
                }
                else
                {
                    Environments.ExecuteCommands($"netsh interface ip set address {this.Index} static {this.LocalAddress} {this.NetworkMask}");
                }
                if (!Layer3Netif.DeviceIoControl(this.Handle, Layer3Netif.TAP_WIN_IOCTL_CONFIG_DHCP_MASQ, dhcp)) // DHCP
                {
                    exception = new SystemException("Unable to configure TAP Ethernet device DHCP-MASQ");
                    break;
                }
                if (!Layer3Netif.DeviceIoControl(this.Handle, Layer3Netif.TAP_WIN_IOCTL_CONFIG_DHCP_SET_OPT, dns)) // DNS
                {
                    exception = new SystemException("Unable to configure TAP Ethernet device DHCP-SET-OPT");
                    break;
                }
                if (!Layer3Netif.DeviceIoControl(this.Handle, Layer3Netif.TAP_WIN_IOCTL_CONFIG_TUN, ip))// IP mode 1
                {
                    exception = new SystemException("Unable to configure TAP Ethernet device ip and gateway set");
                    break;
                }
            } while (false);
            if (pinneds != null)
            {
                foreach (GCHandle pinned in pinneds)
                {
                    if (pinned.IsAllocated)
                    {
                        pinned.Free();
                    }
                }
            }
            if (exception != null)
            {
                throw exception;
            }
            else
            {
                byte[] buffer = this.Buffer;
                fixed (byte* buff = buffer)
                {
                    void* stream_ = libtcpip_loop_stream(this.Handle.ToPointer(), buff, buffer.Length, _kid, _pccb);
                    if (stream_ == null)
                    {
                        throw new InvalidOperationException("Unable to open TAP-driver loopback.");
                    }
                    this._stream = stream_;
                }
                return true;
            }
        }

        public virtual void Dispose()
        {
            _taps.TryRemove(_kid, out Tap _);
            this._disposed = true;
            this.Input = null;
            ReleaseGC(this._gch);
            libtcpip_stop_stream(this._stream);
            Layer3Netif.CloseTunDev(this.Handle);
            GC.SuppressFinalize(this);
        }

        private static bool ReleaseGC(GCHandle gch)
        {
            if (!gch.IsAllocated)
            {
                return false;
            }
            Timer gc = new Timer(1000);
            gc.Tick += (_, __) =>
            {
                using (gc)
                {
                    try
                    {
                        if (gch.IsAllocated)
                        {
                            gch.Free();
                        }
                    }
                    catch { }
                }
            };
            gc.Start();
            return true;
        }
    }
}
