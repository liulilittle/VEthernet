namespace VEthernet.Net.Web
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.IO;
    using System.Net;
    using System.Net.Sockets;
    using System.Text;
    using System.Text.RegularExpressions;
    using System.Threading;
#if NETCOREAPP
    using System.Runtime.CompilerServices;
#endif
    using global::VEthernet.Core;
    using global::VEthernet.Net;
    using global::VEthernet.Net.Auxiliary;
    using global::VEthernet.Net.IP;
    using global::VEthernet.Utilits;

    public class HttpTunnel : IDisposable
    {
        private int _disposed = 0;
        private Socket _socket = null;
        private Socket _server = null;
        private byte[] _socketbuffer = null;
        private byte[] _serverbuffer = null;
        private AsyncCallback _socketRecvAc = null;
        private AsyncCallback _serverRecvAc = null;
        private BufferSegment _cached = null;
        private MemoryStream _responsestream = new MemoryStream();
        private MemoryStream _requeststream = new MemoryStream();
        private readonly Stopwatch _agingsw = new Stopwatch();
        public readonly static HashSet<string> ProtocolMethods = new HashSet<string>()
        {
            "CONNECT",
            "GET",
            "POST",
            "DELETE",
            "HEAD",
            "PUT",
            "OPTIONS",
            "PATCH",
            "TRACE",
        };
        private static Dictionary<string, string> _proxyHeaderToAgentHeader = new Dictionary<string, string>()
        {
            { "PROXY-CONNECTION", string.Empty },
            { "PROXY-AUTHORIZATION", string.Empty },
            { "CONNECTION", string.Empty },
        };

        public HttpListener Listener
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
            get;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public HttpTunnel(HttpListener listener, Socket socket)
        {
            this.Listener = listener ?? throw new ArgumentNullException(nameof(listener));
            this._socket = socket ?? throw new ArgumentNullException(nameof(socket));
            this._socketbuffer = new byte[this.MSS];
            this.ActiveTunnel();
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        ~HttpTunnel() => this.Dispose();

        public bool IsDisposed
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            get => Interlocked.CompareExchange(ref this._disposed, 0, 0) != 0;
        }

        public bool AnonymousMode
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            get;
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            private set;
        }

        public virtual int MSS
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
            get => SocketExtension.MSS;
        }

        public bool IsPortAging
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            get
            {
                if (this.IsDisposed)
                {
                    return true;
                }
                long maxInactivityTime = this.Listener.MaxInactivityTime;
                if (maxInactivityTime < 1000)
                {
                    maxInactivityTime = 1000;
                }
                long milliseconds = this._agingsw.ElapsedMilliseconds;
                return milliseconds >= maxInactivityTime;
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        protected virtual void ActiveTunnel()
        {
            if (Interlocked.CompareExchange(ref this._disposed, 0, 0) == 0)
            {
                this._agingsw.Restart();
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public virtual bool ConnectAsync()
        {
            Socket socket = null;
            byte[] buffer = null;
            if (this.IsDisposed)
            {
                return false;
            }
            socket = this._socket;
            if (socket == null)
            {
                return false;
            }
            buffer = this._socketbuffer;
            if (buffer == null)
            {
                return false;
            }

            void recvloop(IAsyncResult ar)
            {
                if (ar == null)
                {
                    if (!SocketExtension.BeginReceive(socket, buffer, 0, buffer.Length, recvloop))
                    {
                        this.Dispose();
                    }
                }
                else
                {
                    int len = SocketExtension.EndReceive(socket, ar);
                    if (len < 1)
                    {
                        this.Dispose();
                    }
                    else
                    {
                        MemoryStream stream = this._requeststream;
                        try
                        {
                            stream.Write(buffer, 0, len);
                            {
                                byte[] reqBuf = stream.GetBuffer();
                                int reqBufsz = Convert.ToInt32(stream.Position);
                                {
                                    int err = this.ProcessConnectPacket(reqBuf, 0, reqBufsz);
                                    if (err > 0)
                                    {
                                        this.Dispose();
                                    }
                                    else if (err < 0)
                                    {
                                        recvloop(null);
                                    }
                                    else
                                    {
                                        using (stream)
                                        {
                                            this._requeststream = null;
                                        }
                                    }
                                }
                            }
                        }
                        catch
                        {
                            this.Dispose();
                        }
                    }
                }
            }

            recvloop(null);
            return true;
        }

        public sealed class ProtocolRoot
        {
            public string RawProtocol
            {
#if NETCOREAPP
                [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
                get;
#if NETCOREAPP
                [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
                set;
            }

            public string Protocol
            {
#if NETCOREAPP
                [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
                get;
#if NETCOREAPP
                [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
                set;
            }

            public string RawUri
            {
#if NETCOREAPP
                [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
                get;
#if NETCOREAPP
                [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
                set;
            }

            public string Method
            {
#if NETCOREAPP
                [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
                get;
#if NETCOREAPP
                [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
                set;
            }

            public string Host
            {
#if NETCOREAPP
                [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
                get;
#if NETCOREAPP
                [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
                set;
            }

            public string Version
            {
#if NETCOREAPP
                [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
                get;
#if NETCOREAPP
                [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
                set;
            }

            public bool TunnelMode
            {
#if NETCOREAPP
                [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
                get;
#if NETCOREAPP
                [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
                set;
            }

            public IDictionary<string, string> Headers
            {
#if NETCOREAPP
                [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
                get;
#if NETCOREAPP
                [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
                set;
            }

#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            public override string ToString()
            {
                return GetProtocolHeaders(this);
            }

#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            public bool GetHost(out string host, out int port) => GetHost(this.Host, this.Protocol, out host, out port);

#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            public static bool GetHost(string s, string protocol, out string host, out int port)
            {
                host = string.Empty;
                port = protocol == "HTTPS" ? 443 : 80;
                if (string.IsNullOrEmpty(s))
                {
                    return false;
                }
                int j = s.LastIndexOf(':');
                if (j >= 0)
                {
                    int.TryParse(s.Substring(j + 1), out int portNew);
                    if (portNew > IPEndPoint.MinPort && portNew <= IPEndPoint.MaxPort)
                    {
                        port = portNew;
                    }
                    s = s.Substring(0, j);
                    if (string.IsNullOrEmpty(s))
                    {
                        return false;
                    }
                }
                host = s;
                return true;
            }

#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            public IPEndPoint GetHostEndPoint()
            {
                if (!this.GetHost(out string domain, out int port))
                {
                    return new IPEndPoint(IPAddress.Any, 0);
                }
                return Ipep.GetEndPoint(domain, port);
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        protected virtual byte[] GetBuffer(bool local)
        {
            if (this.IsDisposed)
            {
                this._serverbuffer = null;
                this._socketbuffer = null;
                return null;
            }
            return local ? this._socketbuffer : this._serverbuffer;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        protected virtual Socket GetSocket(bool local)
        {
            if (this.IsDisposed)
            {
                this._socket = null;
                this._server = null;
                return null;
            }
            return local ? this._socket : this._server;
        }

        private sealed class ResponseProtocolRoot
        {
            public string Desc
            {
#if NETCOREAPP
                [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
                get;
#if NETCOREAPP
                [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
                set;
            }

            public string Code
            {
#if NETCOREAPP
                [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
                get;
#if NETCOREAPP
                [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
                set;
            }

            public string Version
            {
#if NETCOREAPP
                [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
                get;
#if NETCOREAPP
                [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
                set;
            }

            public string Protocol
            {
#if NETCOREAPP
                [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
                get;
#if NETCOREAPP
                [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
                set;
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
        private static ResponseProtocolRoot GetProtocolByResponseFirstLine(string protocolFirstLine)
        {
            if (string.IsNullOrEmpty(protocolFirstLine))
            {
                return null;
            }
            string version = null;
            string code = null;
            string desc = null;
            do
            {
                int l = 0;
                int i = protocolFirstLine.IndexOf(" ");
                if (i < 0)
                {
                    return null;
                }
                version = protocolFirstLine.Substring(l, (i++ - l)).TrimStart().TrimEnd();
                if (string.IsNullOrEmpty(version))
                {
                    return null;
                }
                else
                {
                    l = i;
                    do
                    {
                        int j = version.IndexOf('/');
                        if (j < 0)
                        {
                            return null;
                        }
                        string sv = version.Substring(0, j);
                        if (string.IsNullOrEmpty(sv))
                        {
                            return null;
                        }
                        sv = sv.ToUpper();
                        if (sv != "HTTP")
                        {
                            return null;
                        }
                    } while (false);
                }
                if (i >= protocolFirstLine.Length)
                {
                    return null;
                }
                i = protocolFirstLine.IndexOf(" ", i);
                if (i < 0)
                {
                    return null;
                }
                code = protocolFirstLine.Substring(l, (i++ - l)).TrimStart().TrimEnd();
                if (string.IsNullOrEmpty(code))
                {
                    return null;
                }
                else
                {
                    l = i;
                    if (!int.TryParse(code, out int coden))
                    {
                        return null;
                    }
                }
                desc = string.Empty;
                if (i < protocolFirstLine.Length)
                {
                    desc = protocolFirstLine.Substring(i).TrimStart().TrimEnd();
                }
            } while (false);
            return new ResponseProtocolRoot { Version = version, Protocol = "HTTP", Desc = desc, Code = code };
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
        private static ProtocolRoot GetProtocolRootByRequestFirstLine(string protocolFirstLine)
        {
            if (string.IsNullOrEmpty(protocolFirstLine))
            {
                return null;
            }
            string[] segments = protocolFirstLine.Split(' ');
            if (segments.Length < 3)
            {
                return null;
            }
            else
            {
                for (int i = 0; i < 3; i++)
                {
                    segments[i] = segments[i].TrimStart().TrimEnd();
                }
            }
            string method = segments[0].ToUpper();
            if (!ProtocolMethods.Contains(method))
            {
                return null;
            }
            if (string.IsNullOrEmpty(segments[2]))
            {
                return null;
            }
            else
            {
                string version = segments[2];
                int i = version.IndexOf('/');
                if (i < 0)
                {
                    return null;
                }
                string sv = version.Substring(0, i);
                if (string.IsNullOrEmpty(sv))
                {
                    return null;
                }
                sv = sv.ToUpper();
                if (sv != "HTTP")
                {
                    return null;
                }
            }
            string host = string.Empty;
            string rawUri = string.Empty;
            string type = "HTTP";
            if (string.IsNullOrEmpty(segments[1]))
            {
                return null;
            }
            else
            {
                Match m = Regex.Match(segments[1], @"^(http|https)://(.*?)(/.*?)$", RegexOptions.IgnoreCase);
                if (m.Success)
                {
                    for (int i = 1; i <= 3; i++)
                    {
                        if (string.IsNullOrEmpty(m.Groups[i].Value))
                        {
                            return null;
                        }
                    }
                    string p1 = m.Groups[1].Value.ToUpper();
                    if (p1 != "HTTP")
                    {
                        return null;
                    }
                    string p2 = m.Groups[2].Value;
                    {
                        int j = p2.LastIndexOf(':');
                        if (j < 0)
                        {
                            p2 += ":80";
                        }
                    }
                    host = p2;
                    type = p1;
                    rawUri = m.Groups[3].Value;
                }
                else
                {
                    string p1 = segments[1];
                    int j = p1.LastIndexOf(':');
                    if (j < 0)
                    {
                        p1 += ":80";
                    }
                    host = p1;
                }
            }
            return new ProtocolRoot() { Method = method, TunnelMode = "CONNECT" == method, Host = host, RawUri = rawUri, Version = segments[2].ToUpper(), Protocol = type };
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
        private static bool ReadProtocolHeaders(IDictionary<string, string> protocolHeaders, string[] protocolLines)
        {
            if (protocolLines == null || protocolLines.Length < 1)
            {
                return false;
            }
            for (int i = 1; i < protocolLines.Length; i++)
            {
                string protocolLine = protocolLines[i];
                if (string.IsNullOrEmpty(protocolLine))
                {
                    continue;
                }
                int j = protocolLine.IndexOf(": ");
                if (j < 0)
                {
                    return false;
                }
                string key = protocolLine.Substring(0, j);
                if (string.IsNullOrEmpty(key))
                {
                    return false;
                }
                string keyUpper = key.ToUpper();
                if (_proxyHeaderToAgentHeader.
                    TryGetValue(keyUpper, out string keyNew))
                {
                    if (string.IsNullOrEmpty(keyNew))
                    {
                        continue;
                    }
                    key = keyNew;
                }
                string value = protocolLine.Substring(j + 2);
                if (string.IsNullOrEmpty(value))
                {
                    continue;
                }
                protocolHeaders[key] = value;
            }
            return true;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
        public static ProtocolRoot GetProtocolRoot(string protocolText)
        {
            if (string.IsNullOrEmpty(protocolText))
            {
                return null;
            }
            try
            {
                string[] protocolLines = protocolText.Split('\r', '\n');
                if (protocolLines.Length < 1)
                {
                    return null;
                }
                ProtocolRoot protocol = GetProtocolRootByRequestFirstLine(protocolLines[0]);
                if (protocol == null)
                {
                    return null;
                }
                else
                {
                    protocol.RawProtocol = protocolText;
                }
                IDictionary<string, string> protocolHeaders = protocol.Headers;
                if (protocolHeaders == null)
                {
                    protocolHeaders = new Dictionary<string, string>();
                    protocol.Headers = protocolHeaders;
                }
                if (!ReadProtocolHeaders(protocolHeaders, protocolLines))
                {
                    return null;
                }
                return protocol;
            }
            catch
            {
                return null;
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
        public static string GetProtocolHeaders(ProtocolRoot protocolRoot)
        {
            if (protocolRoot == null)
            {
                return string.Empty;
            }
            if (protocolRoot.TunnelMode)
            {
                string protocol = $"{protocolRoot.Method} {protocolRoot.Host} {protocolRoot.Version}\r\n";
                protocol += GetProtocolHeaders(protocolRoot.Headers);
                return protocol;
            }
            else
            {
                string protocol = $"{protocolRoot.Method} {protocolRoot.RawUri} {protocolRoot.Version}\r\n";
                protocol += GetProtocolHeaders(protocolRoot.Headers);
                return protocol;
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
        public static string GetProtocolHeaders(IDictionary<string, string> protocolHeaders)
        {
            if (protocolHeaders == null || protocolHeaders.Count < 1)
            {
                return "\r\n";
            }
            string protocolText = string.Empty;
            foreach (var kv in protocolHeaders)
            {
                protocolText += $"{kv.Key}: {kv.Value}\r\n";
            }
            protocolText += "\r\n";
            return protocolText;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
        private static bool ReadHeadersText(byte[] buffer, int offset, int length, out int headersEndSeek)
        {
            headersEndSeek = ~0;
            if (buffer == null || offset < 0 || length < 1 || (offset + length) > buffer.Length)
            {
                return false;
            }
            byte[] pattern = { (byte)'\r', (byte)'\n', (byte)'\r', (byte)'\n' };
            int i = ~0;
            unsafe
            {
                int[] next = new int[pattern.Length];
                fixed (byte* p1 = &buffer[offset])
                {
                    fixed (byte* p2 = pattern)
                    {
                        i = Extension.IndexOf(ref next, p1, length, p2, pattern.Length);
                    }
                }
            }
            if (i < 0)
            {
                return false;
            }
            else
            {
                i = i + pattern.Length;
                headersEndSeek = i;
            }
            return headersEndSeek >= 0;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
        private static int ReadPacket(byte[] buffer, int offset, int length,
            out ProtocolRoot protocolRoot, out BufferSegment overflowBuffer)
        {
            protocolRoot = null;
            overflowBuffer = null;
            if (!ReadHeadersText(buffer, offset, length, out int headersEndSeek))
            {
                return -1;
            }
            int overflowSize = length - headersEndSeek;
            if (overflowSize < 0)
            {
                return 1;
            }
            string protocolText = Encoding.UTF8.GetString(buffer, offset, headersEndSeek);
            if (string.IsNullOrEmpty(protocolText))
            {
                return 1;
            }
            protocolRoot = GetProtocolRoot(protocolText);
            if (protocolRoot == null)
            {
                return 1;
            }
            if (overflowSize > 0)
            {
                overflowBuffer = new BufferSegment(buffer, offset + headersEndSeek, overflowSize).ToArray();
            }
            return 0;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
        private int ProcessConnectPacket(byte[] buffer, int offset, int length)
        {
            if (this.IsDisposed)
            {
                return 1;
            }
            int success = ReadPacket(buffer, offset, length, out ProtocolRoot protocolRoot, out BufferSegment overflowBuffer);
            if (success != 0)
            {
                return success;
            }
            this._cached = overflowBuffer;
            this.AnonymousMode = protocolRoot.TunnelMode;
            return this.ProcessRequest(protocolRoot) ? 0 : 1;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
        protected virtual bool ProcessRequest(ProtocolRoot protocol)
        {
            if (protocol == null)
            {
                return false;
            }
            IPEndPoint hostEP = protocol.GetHostEndPoint();
            if (hostEP == null || hostEP.Port == 0 || IPFrame.Equals(IPAddress.Any, hostEP.Address))
            {
                return false;
            }
            if (this.IsDisposed)
            {
                return false;
            }
            try
            {
                this._server = new NetworkSocket(AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp);
                this._server.SetFastOpen(); 
                this._server.IPv6Only(false);
                this._server.SetTypeOfService();
                return this._server.BeginConnect(hostEP, (ar) =>
                {
                    bool noerror = false;
                    try
                    {
                        Socket server = null;
                        do
                        {
                            if (this.IsDisposed)
                            {
                                break;
                            }
                            server = this._server;
                            if (server == null)
                            {
                                break;
                            }
                            server.EndConnect(ar);
                            noerror = server.Connected;
                        } while (false);
                    }
                    catch { }
                    if (noerror)
                    {
                        noerror = this.ProcessEstablished(protocol);
                    }
                    if (!noerror)
                    {
                        this.Dispose();
                    }
                }, null) != null;
            }
            catch
            {
                this.Dispose();
                return false;
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
        private bool CompleteEstablished(ProtocolRoot protocol)
        {
            if (protocol == null)
            {
                return false;
            }
            if (protocol.TunnelMode) // HTTP/1.1 200 Connection established
            {
                byte[] response = Encoding.UTF8.GetBytes($"{protocol.Version} 200 Connection established\r\n\r\n");
                if (!this.SendToClient(response, 0, response.Length, null))
                {
                    return false;
                }
                this._cached = null;
            }
            else
            {
                byte[] headers = Encoding.UTF8.GetBytes(protocol.ToString());
                if (!this.SendToServer(headers, 0, headers.Length, null))
                {
                    return false;
                }
                BufferSegment cached = this._cached;
                if (cached != null)
                {
                    this._cached = default(BufferSegment);
                    if (!this.SendToServer(cached.Buffer,
                        cached.Offset, cached.Length, null))
                    {
                        return false;
                    }
                }
            }
            return true;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
        protected virtual bool ProcessEstablished(ProtocolRoot protocol)
        {
            if (this.IsDisposed)
            {
                return false;
            }
            bool ok = this.CompleteEstablished(protocol) && this.PullListener(PullFlags.All);
            if (ok)
            {
                this.ActiveTunnel();
            }
            return ok;
        }

        [Flags]
        protected enum PullFlags
        {
            Client = 1,
            Server = 2,
            All = Client | Server,
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
        protected virtual bool PullListener(PullFlags flags)
        {
            if (this.IsDisposed)
            {
                return false;
            }
            if (0 != (flags & PullFlags.Server))
            {
                if (this._serverbuffer == null)
                {
                    this._serverbuffer = new byte[this.MSS];
                }
                if (this._serverRecvAc == null)
                {
                    this._serverRecvAc = this.ProcessRecvServer;
                }
                this.ProcessRecvServer(null);
            }
            if (0 != (flags & PullFlags.Client))
            {
                if (this._socketRecvAc == null)
                {
                    this._socketRecvAc = this.ProcessRecvSocket;
                }
                this.ProcessRecvSocket(null);
            }
            return true;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
        private void ProcessRecvServer(IAsyncResult ar)
         {
             if (this.IsDisposed)
             {
                 return;
             }
             Socket socket = this._server;
             if (socket == null)
             {
                 return;
             }
             byte[] buffer = this._serverbuffer;
             if (buffer == null)
             {
                 return;
             }
             AsyncCallback ac = this._serverRecvAc;
             if (ac == null)
             {
                 return;
             }
             if (ar == null)
             {
                 if (!SocketExtension.BeginReceive(socket, buffer, 0, buffer.Length, ac))
                 {
                     this.Dispose();
                 }
             }
             else
             {
                 int len = SocketExtension.EndReceive(socket, ar);
                 if (len < 1)
                 {
                     this.Dispose();
                 }
                 else if (!this.ProcessInput(false, buffer, 0, len, null))
                 {
                     this.Dispose();
                 }
                 else
                 {
                     this.RepullListener(false);
                 }
             }
         }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
        private void ProcessRecvSocket(IAsyncResult ar)
        {
            if (this.IsDisposed)
            {
                return;
            }
            Socket socket = this._socket;
            if (socket == null)
            {
                return;
            }
            byte[] buffer = this._socketbuffer;
            if (buffer == null)
            {
                return;
            }
            AsyncCallback ac = this._socketRecvAc;
            if (ac == null)
            {
                return;
            }
            if (ar == null)
            {
                if (!SocketExtension.BeginReceive(socket, buffer, 0, buffer.Length, ac))
                {
                    this.Dispose();
                }
            }
            else
            {
                int len = SocketExtension.EndReceive(socket, ar);
                if (len < 1)
                {
                    this.Dispose();
                }
                else if (!this.ProcessInput(true, buffer, 0, len, null))
                {
                    this.Dispose();
                }
                else
                {
                    this.RepullListener(true);
                }
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
        protected virtual bool ProcessResponse(byte[] buffer, int offset, int length)
        {
            string[] protocolLines = Encoding.ASCII.GetString(buffer, offset, length).Split('\r', '\n');
            if (protocolLines == null || protocolLines.Length < 1)
            {
                return false;
            }
            ResponseProtocolRoot protocolRoot = GetProtocolByResponseFirstLine(protocolLines[0]);
            if (protocolRoot == null)
            {
                return false;
            }
            IDictionary<string, string> headers = new Dictionary<string, string>();
            if (!ReadProtocolHeaders(headers, protocolLines))
            {
                return false;
            }
            bool location = false;
            if (headers != null)
            {
                location = headers.TryGetValue("Location", out string s);
                if (!location)
                {
                    foreach (var key in headers.Keys)
                    {
                        var kx = key.ToLower();
                        if (kx == "LOCATION")
                        {
                            location = true;
                            break;
                        }
                    }
                }
            }
            return !location;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
        protected virtual bool ProcessInput(bool directLocal, byte[] buffer, int offset, int length, Action<bool> forwarding)
        {
            if (!directLocal)
            {
                if (!this.SendToClient(buffer, offset, length, forwarding))
                {
                    return false;
                }
                if (this.AnonymousMode)
                {
                    return true;
                }
                MemoryStream stream = this._responsestream;
                if (stream == null)
                {
                    return true;
                }
                try
                {
                    stream.Write(buffer, offset, length);
                    {
                        byte[] headersBuf = stream.GetBuffer();
                        int headersBufsz = Convert.ToInt32(stream.Position);
                        if (!ReadHeadersText(headersBuf, 0, headersBufsz, out int headersEndSeek) || headersEndSeek < 0)
                        {
                            return true;
                        }
                        else
                        {
                            using (stream)
                            {
                                this._responsestream = null;
                            }
                        }
                        return this.ProcessResponse(headersBuf, 0, headersEndSeek);
                    }
                }
                catch
                {
                    return false;
                }
            }
            else
            {
                return this.SendToServer(buffer, offset, length, forwarding);
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
        protected virtual bool RepullListener(bool directLocal)
        {
            if (directLocal)
            {
                this.ProcessRecvSocket(null);
            }
            else
            {
                this.ProcessRecvServer(null);
            }
            return true;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
        protected virtual bool SendToServer(byte[] buffer, int offset, int length, Action<bool> forwarding)
        {
            bool success = SocketExtension.BeginSend(this._server, buffer, offset, length, (ar) =>
            {
                bool ok = SocketExtension.EndSend(this._server, ar);
                if (forwarding != null)
                {
                    forwarding(ok);
                }
                if (!ok)
                {
                    this.Dispose();
                }
                else
                {
                    this.ActiveTunnel();
                }
            });
            if (!success)
            {
                this.Dispose();
            }
            return success;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
        protected virtual bool SendToClient(byte[] buffer, int offset, int length, Action<bool> forwarding)
        {
            bool success = SocketExtension.BeginSend(this._socket, buffer, offset, length, (ar) =>
            {
                bool ok = SocketExtension.EndSend(this._socket, ar);
                if (forwarding != null)
                {
                    forwarding(ok);
                }
                if (!ok)
                {
                    this.Dispose();
                }
                else
                {
                    this.ActiveTunnel();
                }
            });
            if (!success)
            {
                this.Dispose();
            }
            return success;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
        public virtual void Dispose()
        {
            Interlocked.CompareExchange(ref this._disposed, 1, 0);
            SocketExtension.Closesocket(Interlocked.Exchange(ref this._socket, null));
            SocketExtension.Closesocket(Interlocked.Exchange(ref this._server, null));
            this._socketbuffer = null;
            this._serverbuffer = null;
            this._socketRecvAc = null;
            this._serverRecvAc = null;
            this._cached = null;
            using (MemoryStream ms = this._requeststream)
            {
                this._requeststream = null;
            }
            using (MemoryStream ms = this._responsestream)
            {
                this._responsestream = null;
            }
            this.Listener.Unwatch(this);
            GC.SuppressFinalize(this);
        }
    }
}
