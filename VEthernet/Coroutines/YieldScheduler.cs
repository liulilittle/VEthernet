namespace VEthernet.Coroutines
{
    using System;
    using System.Collections.Generic;
    using System.Threading;
#if NETCOREAPP
    using System.Runtime.CompilerServices;
#endif
    using VEthernet.Collections;

    public sealed class YieldScheduler : IDisposable
    {
        private static readonly object _syncobj = new object();
        private static YieldScheduler _default = null;
        private Thread _mta;
        private bool _disposed;
        private LinkedList<YieldContext> _s;
        private LinkedListIterator<YieldContext> _i;
        private IDictionary<YieldContext, LinkedListNode<YieldContext>> _m;

        public static YieldScheduler Default
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            get
            {
                lock (_syncobj)
                {
                    if (_default == null)
                    {
                        _default = new YieldScheduler();
                    }
                    return _default;
                }
            }
        }

        public int Id
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            get
            {
                return _mta.ManagedThreadId;
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        ~YieldScheduler()
        {
            this.Dispose();
        }

        public int Count
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            get => _s.Count;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public YieldScheduler()
        {
            _m = new Dictionary<YieldContext, LinkedListNode<YieldContext>>();
            _s = new LinkedList<YieldContext>();
            _i = new LinkedListIterator<YieldContext>(this, _s);
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        private bool Run()
        {
            lock (this)
            {
                if (_disposed)
                {
                    return false;
                }
                if (_mta != null)
                {
                    return false;
                }
                _mta = new Thread(() =>
                {
                    while (!_disposed)
                    {
                        int m = Math.Max(_s.Count, 10);
                        for (int i = 0; i < m; i++)
                        {
                            this.Next();
                        }
                        Thread.Sleep(1);
                    }
                });
                _mta.IsBackground = true;
                _mta.Priority = ThreadPriority.Lowest;
                _mta.Start();
                return true;
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        private void Next()
        {
            for (int i = 0; i < _s.Count; i++)
            {
                LinkedListNode<YieldContext> node = _i++.Node;
                if (node == null)
                {
                    break;
                }

                YieldContext y = node.Value;
                if (y == null)
                {
                    continue;
                }

                int rc = y.Yield();
                if (rc < 0)
                {
                    Remove(y);
                    continue;
                }
                break;
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        internal bool Add(YieldContext y)
        {
            lock (this)
            {
                if (_disposed)
                {
                    return false;
                }

                if (y == null)
                {
                    return false;
                }

                if (_m.ContainsKey(y))
                {
                    return false;
                }

                LinkedListNode<YieldContext> node = _s.AddLast(y);
                if (node == null)
                {
                    return false;
                }

                _m.Add(y, node);
                try
                {
                    return true;
                }
                finally
                {
                    this.Run();
                }
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        internal bool Remove(YieldContext y)
        {
            lock (this)
            {
                if (_disposed)
                {
                    return false;
                }

                if (y == null)
                {
                    return false;
                }

                if (!_m.TryGetValue(y, out LinkedListNode<YieldContext> n))
                {
                    return false;
                }

                _s.Remove(n);
                _m.Remove(y);
                _i.Remove(n);
                return true;
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public void Dispose()
        {
            lock (this)
            {
                if (!_disposed)
                {
                    _disposed = true;

                    _s.Clear();
                    _m.Clear();
                    _mta = null;

                    _s = null;
                    _m = null;
                    _i = null;
                }
            }

            GC.SuppressFinalize(this);
        }
    }
}
