#if !AARCH
namespace VEthernet.Net.Auxiliary
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
#if NETCOREAPP
    using System.Runtime.CompilerServices;
#endif

    public sealed class AsyncScheduler : IDisposable
    {
        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private readonly LinkedList<AsyncContext> _contexts = new LinkedList<AsyncContext>();
        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private readonly object _syncobj = new object();

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public AsyncScheduler(int concurrent)
        {
            if (concurrent < 1)
            {
                concurrent = 1;
            }
            for (int i = 0; i < concurrent; i++)
            {
                AsyncContext context = new AsyncContext();
                this._contexts.AddLast(context);
            }
        }

        public int Concurrent
        {
#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            get => _contexts.Count;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public void Dispose()
        {
            lock (this._syncobj)
            {
                LinkedListNode<AsyncContext> node = this._contexts.First;
                while (node != null)
                {
                    node.Value.Dispose();
                    node = node.Next;
                }
                this._contexts.Clear();
            }
            GC.SuppressFinalize(this);
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public AsyncContext GetContext()
        {
            lock (this._syncobj)
            {
                LinkedListNode<AsyncContext> node = this._contexts.First;
                if (node == null)
                {
                    return null;
                }
                this._contexts.RemoveFirst();
                this._contexts.AddLast(node);
                return node.Value;
            }
        }
    }
}
#endif
