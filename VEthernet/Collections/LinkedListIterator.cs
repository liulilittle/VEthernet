namespace VEthernet.Collections
{
    using System;
    using System.Collections.Generic;
#if NETCOREAPP
    using System.Runtime.CompilerServices;
#endif

    public sealed class LinkedListIterator<T>
    {
        private LinkedListNode<T> current; // 当前节点
        private LinkedList<T> linkedlist; // 链首指针
        private readonly object syncobj; // 临界点

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        private bool MoveNext()
        {
            lock (this.syncobj)
            {
                if (current != null)
                {
                    current = current.Next;
                }
                if (current == null)
                {
                    current = linkedlist.First;
                }
                return current != null;
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        private bool MovePrevious()
        {
            lock (this.syncobj)
            {
                if (current == null)
                {
                    current = linkedlist.Last;
                }
                else
                {
                    current = current.Previous;
                }
                return current != null;
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public void Reset()
        {
            lock (this.syncobj)
            {
                current = linkedlist.First;
            }
        }


        public LinkedListNode<T> Node
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            get // 线程安全与增删节安全
            {
                lock (this.syncobj)
                {
                    return current;
                }
            }
        }

        public T Value
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            get
            {
                lock (this.syncobj)
                {
                    LinkedListNode<T> node = this.Node;
                    if (node == null)
                        return default(T);
                    return node.Value;
                }
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public bool Remove(LinkedListNode<T> node)
        {
            lock (this.syncobj)
            {
                if (node == null)
                {
                    return false;
                }
                if (current == node)
                {
                    current = current.Next;
                }
                return current != null;
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public LinkedListIterator(object cp, LinkedList<T> linkedlist)
        {
            this.syncobj = cp ?? throw new ArgumentNullException(nameof(cp));
            this.linkedlist = linkedlist ?? throw new ArgumentNullException(nameof(linkedlist));
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static LinkedListIterator<T> operator ++(LinkedListIterator<T> iterator) // 移动指针到下一个节点
        {
            if (iterator != null)
            {
                lock (iterator.syncobj)
                {
                    if (!iterator.MoveNext())
                    {
                        iterator.MoveNext();
                    }
                }
            }
            return iterator;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static LinkedListIterator<T> operator --(LinkedListIterator<T> iterator) // 移动指针到上一个节点
        {
            if (iterator != null)
            {
                lock (iterator.syncobj)
                {
                    if (!iterator.MovePrevious())
                    {
                        iterator.MovePrevious();
                    }
                }
            }
            return iterator;
        }
    }
}
