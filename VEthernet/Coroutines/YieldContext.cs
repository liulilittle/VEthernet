namespace VEthernet.Coroutines
{
    using System;
    using System.Collections;
    using System.Net;
    using System.Net.Sockets;
    using System.Threading;
#if NETCOREAPP
    using System.Runtime.CompilerServices;
#endif
    using VEthernet.Net.Auxiliary;

    public sealed class YieldContext : IDisposable
    {
        private IEnumerator _coroutines = null;
        private int _next = 0;
        private YieldScheduler _scheduler = null;

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static YieldContext Run(Func<YieldContext, IEnumerable> coroutines)
            => Run(YieldScheduler.Default, coroutines);

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static YieldContext Run(YieldScheduler scheduler, Func<YieldContext, IEnumerable> coroutines)
            => New(scheduler ?? YieldScheduler.Default, coroutines);

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static YieldContext New(YieldScheduler scheduler, Func<YieldContext, IEnumerable> coroutines)
        {
            YieldContext context = new YieldContext();
            IEnumerable enumerable = coroutines(context);
            if (enumerable == null)
            {
                return null;
            }
            context._coroutines = enumerable.GetEnumerator();
            context._coroutines.MoveNext();
            if (scheduler != null)
            {
                context._scheduler = scheduler;
                scheduler.Add(context);
            }
            return context;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        private YieldContext() { }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        ~YieldContext() => this.Dispose();

        public YieldScheduler Scheduler
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            get => Interlocked.CompareExchange(ref this._scheduler, null, null);
        }

        public bool IsNext => Interlocked.CompareExchange(ref this._next, 0, 0) == 1;

        public bool IsCompleted => Interlocked.CompareExchange(ref this._coroutines, null, null) == null;

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public int Yield()
        {
            IEnumerator coroutines = Interlocked.CompareExchange(ref this._coroutines, null, null);
            if (coroutines == null)
            {
                return -1;
            }
            if (Interlocked.CompareExchange(ref this._next, 0, 1) < 1)
            {
                return 0;
            }
            if (coroutines.MoveNext())
            {
                return 1;
            }
            return Interlocked.Exchange(ref this._coroutines, null) != null ? 0 : -1;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        private bool NextYield()
        {
            IEnumerator coroutines = Interlocked.CompareExchange(ref this._coroutines, null, null);
            if (coroutines == null)
            {
                return false;
            }
            if (!coroutines.MoveNext())
            {
                if (Interlocked.CompareExchange(ref this._next, 1, 0) != 0)
                {
                    throw new InvalidProgramException("Single coroutines does not allow the same clock cycle there are multiple asynchronous call operation.");
                }
                ThreadPool.QueueUserWorkItem((state) => ((YieldContext)state).Yield(), this);
            }
            return true;
        }

        public sealed class Integer
        {
            public int Value
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
            public Integer() => this.Value = 0;

#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            public static implicit operator int(Integer i)
            {
                if (i == null)
                {
                    return 0;
                }
                return i.Value;
            }

#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            public static implicit operator Integer(int i)
            {
                return new Integer() { Value = i };
            }

#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            public static bool operator ==(Integer x, int y)
            {
                if (x == null)
                {
                    return false;
                }
                return x.Value == y;
            }

#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            public static bool operator !=(Integer x, int y) => x == y ? false : true;

#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            public static bool operator ==(Integer x, Integer y)
            {
                object ox = x;
                object oy = y;
                if (ox == oy)
                {
                    return true;
                }
                if (ox == null || oy == null)
                {
                    return false;
                }
                return x.Value == y.Value;
            }

#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            public static bool operator !=(Integer x, Integer y) => x == y ? false : true;

#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            public override bool Equals(object obj)
            {
                if (obj == (object)this)
                {
                    return true;
                }
                if (obj is Integer r)
                {
                    return this.Value == r.Value;
                }
                return base.Equals(obj);
            }

#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            public override int GetHashCode() => this.Value;

#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            public override string ToString() => this.Value.ToString();
        }

        public sealed class Boolean
        {
            public bool Value
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
            public static implicit operator bool(Boolean b)
            {
                if (b == null)
                {
                    return false;
                }
                return b.Value;
            }

#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            public static implicit operator Boolean(bool b)
            {
                return new Boolean() { Value = b };
            }
        }

        public sealed class Object
        {
            public object Value
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
        }

        private sealed class ReceiveYield
        {
            public Socket socket;
            public byte[] buffer;
            public int offset;
            public int length;
            public YieldContext context;

#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            public bool Run(Integer outLength)
            {
                if (SocketExtension.CleanedUp(socket))
                {
                    return false;
                }
                try
                {
                    return socket.BeginReceive(buffer, offset, length, SocketFlags.None, (ar) =>
                    {
                        SocketError error = SocketError.SocketError;
                        int length = -1;
                        try
                        {
                            if (!SocketExtension.CleanedUp(socket))
                            {
                                length = socket.EndReceive(ar, out error);
                            }
                        }
                        catch { }
                        if (error != SocketError.Success)
                        {
                            length = -1;
                        }
                        outLength.Value = length;
                        context.NextYield();
                    }, null) != null;
                }
                catch
                {
                    return false;
                }
            }
        }

        private sealed class SendYield
        {
            public Socket socket;
            public byte[] buffer;
            public int offset;
            public int length;
            public YieldContext context;

#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            public bool Run(Integer outLength)
            {
                if (SocketExtension.CleanedUp(socket))
                {
                    return false;
                }
                try
                {
                    return socket.BeginSend(buffer, offset, length, SocketFlags.None, (ar) =>
                    {
                        SocketError error = SocketError.SocketError;
                        int length = -1;
                        try
                        {
                            if (!SocketExtension.CleanedUp(socket))
                            {
                                length = socket.EndSend(ar, out error);
                            }
                        }
                        catch { }
                        if (error != SocketError.Success)
                        {
                            if (error == SocketError.IOPending)
                            {
                                length = 0;
                            }
                            else
                            {
                                length = -1;
                            }
                        }
                        outLength.Value = length;
                        context.NextYield();
                    }, null) != null;
                }
                catch
                {
                    return false;
                }
            }
        }

        private sealed class ConnectYield
        {
            public Socket socket;
            public IPEndPoint remoteEP;
            public YieldContext context;

#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            public bool Run(Boolean outSuccess)
            {
                if (SocketExtension.CleanedUp(socket))
                {
                    return false;
                }
                try
                {
                    return socket.BeginConnect(remoteEP, (ar) =>
                    {
                        bool ok = false;
                        try
                        {
                            if (!SocketExtension.CleanedUp(socket))
                            {
                                socket.EndConnect(ar);
                                ok = socket.Connected;
                            }
                        }
                        catch { }
                        outSuccess.Value = ok;
                        context.NextYield();
                    }, null) != null;
                }
                catch
                {
                    return false;
                }
            }
        }

        private sealed class AcceptYield
        {
            public Socket socket;
            public YieldContext context;

#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            public bool Run(Object outSocket)
            {
                if (SocketExtension.CleanedUp(socket))
                {
                    return false;
                }
                try
                {
                    return socket.BeginAccept((ar) =>
                    {
                        Socket session = null;
                        try
                        {
                            if (!SocketExtension.CleanedUp(socket))
                            {
                                session = socket.EndAccept(ar);
                            }
                        }
                        catch { }
                        outSocket.Value = session;
                        context.NextYield();
                    }, null) != null;
                }
                catch
                {
                    return false;
                }
            }
        }

        private sealed class ReadYield
        {
            public Socket socket;
            public byte[] buffer;
            public int offset;
            public int length;
            public int byread = 0;
            public YieldContext context;

#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            public bool Run(Integer outLength)
            {
                if (SocketExtension.CleanedUp(socket))
                {
                    return false;
                }
                try
                {
                    return socket.BeginReceive(buffer, offset + byread, length - byread, SocketFlags.None, (ar) =>
                    {
                        SocketError error = SocketError.SocketError;
                        int size = -1;
                        try
                        {
                            if (!SocketExtension.CleanedUp(socket))
                            {
                                size = socket.EndReceive(ar, out error);
                            }
                        }
                        catch { }
                        if (error != SocketError.Success)
                        {
                            size = -1;
                        }
                        if (size > 0)
                        {
                            byread += size;
                            if (byread >= this.length)
                            {
                                outLength.Value = byread;
                                context.NextYield();
                            }
                            else if (!this.Run(outLength))
                            {
                                size = -1;
                            }
                        }
                        else
                        {
                            outLength.Value = size;
                            context.NextYield();
                        }
                    }, null) != null;
                }
                catch
                {
                    return false;
                }
            }
        }

        private sealed class GetHostAddressesYield
        {
            public YieldContext context;

#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            public bool Run(string hostNameOrAddress, Object outAddresses)
            {
                try
                {
                    return Dns.BeginGetHostAddresses(hostNameOrAddress, (ar) =>
                    {
                        IPAddress[] addresses = null;
                        try
                        {
                            addresses = Dns.EndGetHostAddresses(ar);
                        }
                        catch { }
                        outAddresses.Value = addresses;
                        context.NextYield();
                    }, null) != null;
                }
                catch
                {
                    return false;
                }
            }
        }

        private sealed class GetHostEntryYield
        {
            public YieldContext context;

#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            public bool Run(string hostNameOrAddress, Object outHostEntry)
            {
                try
                {
                    return Dns.BeginGetHostEntry(hostNameOrAddress, (ar) =>
                    {
                        IPHostEntry hostEntry = null;
                        try
                        {
                            hostEntry = Dns.EndGetHostEntry(ar);
                        }
                        catch { }
                        outHostEntry.Value = hostEntry;
                        context.NextYield();
                    }, null) != null;
                }
                catch
                {
                    return false;
                }
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public object GetHostEntry(string hostNameOrAddress, Object outHostEntry)
        {
            if (outHostEntry == null)
            {
                throw new ArgumentNullException(nameof(outHostEntry));
            }
            else
            {
                outHostEntry.Value = null;
            }
            GetHostEntryYield context = new GetHostEntryYield()
            {
                context = this,
            };
            if (!context.Run(hostNameOrAddress, outHostEntry))
            {
                this.NextYield();
            }
            return context;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public object GetHostAddresses(string hostNameOrAddress, Object outAddresses)
        {
            if (outAddresses == null)
            {
                throw new ArgumentNullException(nameof(outAddresses));
            }
            else
            {
                outAddresses.Value = null;
            }
            GetHostAddressesYield context = new GetHostAddressesYield()
            {
                context = this,
            };
            if (!context.Run(hostNameOrAddress, outAddresses))
            {
                this.NextYield();
            }
            return context;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public object Accept(Socket socket, Object outSocket)
        {
            if (outSocket == null)
            {
                throw new ArgumentNullException(nameof(outSocket));
            }
            else
            {
                outSocket.Value = null;
            }
            AcceptYield context = new AcceptYield()
            {
                socket = socket,
                context = this,
            };
            if (!context.Run(outSocket))
            {
                this.NextYield();
            }
            return context;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public object Connect(Socket socket, IPEndPoint remoteEP, Boolean outSuccess)
        {
            if (outSuccess == null)
            {
                throw new ArgumentNullException(nameof(outSuccess));
            }
            else
            {
                outSuccess.Value = false;
            }
            ConnectYield context = new ConnectYield()
            {
                socket = socket,
                remoteEP = remoteEP,
                context = this,
            };
            if (!context.Run(outSuccess))
            {
                this.NextYield();
            }
            return context;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public object Read(Socket socket, byte[] buffer, int offset, int length, Integer outLength)
        {
            if (outLength == null)
            {
                throw new ArgumentNullException(nameof(outLength));
            }
            else
            {
                outLength.Value = -1;
            }
            ReadYield context = new ReadYield()
            {
                buffer = buffer,
                offset = offset,
                length = length,
                context = this,
                socket = socket,
            };
            if (!context.Run(outLength))
            {
                this.NextYield();
            }
            return context;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public object Write(Socket socket, byte[] buffer, int offset, int length, Integer outLength) => this.Send(socket, buffer, offset, length, outLength);

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public object Receive(Socket socket, byte[] buffer, int offset, int length, Integer outLength)
        {
            if (outLength == null)
            {
                throw new ArgumentNullException(nameof(outLength));
            }
            else
            {
                outLength.Value = -1;
            }
            ReceiveYield context = new ReceiveYield()
            {
                socket = socket,
                buffer = buffer,
                offset = offset,
                length = length,
                context = this,
            };
            if (!context.Run(outLength))
            {
                this.NextYield();
            }
            return context;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public object Send(Socket socket, byte[] buffer, int offset, int length, Integer outLength)
        {
            if (outLength == null)
            {
                throw new ArgumentNullException(nameof(outLength));
            }
            else
            {
                outLength.Value = -1;
            }
            SendYield context = new SendYield()
            {
                socket = socket,
                buffer = buffer,
                offset = offset,
                length = length,
                context = this,
            };
            if (!context.Run(outLength))
            {
                this.NextYield();
            }
            return context;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public void Dispose()
        {
            YieldScheduler scheduler = Interlocked.Exchange(ref this._scheduler, null);
            if (scheduler != null)
            {
                scheduler.Remove(this);
            }
            Interlocked.Exchange(ref this._coroutines, null);
            Interlocked.Exchange(ref this._next, 0);
            GC.SuppressFinalize(this);
        }
    }
}
