namespace VEthernet.Core
{
    using System;
    using System.Collections;
    using System.Collections.Generic;
    using System.IO;
    using System.Text;
#if NETCOREAPP
    using System.Runtime.CompilerServices;
#endif

    public sealed unsafe class BufferSegment : EventArgs, IEnumerable<byte>
    {
        public new static readonly byte[] Empty = new byte[0];
        public static readonly IntPtr Null = IntPtr.Zero;

        public byte[] Buffer
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

        public int Offset
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

        public int Length
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

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public BufferSegment(byte[] buffer) : this(buffer, buffer?.Length ?? 0)
        {

        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public BufferSegment(byte[] buffer, int length) : this(buffer, 0, length)
        {

        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public BufferSegment(byte[] buffer, int offset, int length)
        {
            if (offset < 0)
            {
                offset = 0;
            }
            if (length < 0)
            {
                length = 0;
            }
            if (offset > buffer.Length)
            {
                offset = buffer.Length;
            }
            if (unchecked(offset + length) > buffer.Length)
            {
                length = unchecked(buffer.Length - offset);
            }
            this.Offset = offset;
            this.Length = length;
            this.Buffer = buffer ?? BufferSegment.Empty;
        }

        public byte this[int index]
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            get
            {
                return this.Buffer[index + this.Offset];
            }
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            set
            {
                this.Buffer[index + this.Offset] = value;
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        ~BufferSegment()
        {
            this.Buffer = null;
            this.Offset = 0;
            this.Length = 0;
            GC.SuppressFinalize(this);
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public BufferSegment Depth()
        {
            byte[] b = null;
            int length = this.Length;
            if (length < 1)
            {
                b = BufferSegment.Empty;
            }
            else
            {
                b = new byte[length];
            }
            BufferSegment s = new BufferSegment(b);
            if (b.Length > 0)
            {
                this.CopyTo(s.Buffer);
            }
            return s;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static implicit operator BufferSegment(byte[] b)
        {
            if (b == null)
            {
                return new BufferSegment(Empty);
            }
            return new BufferSegment(b);
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public ArraySegment<byte> ToArraySegment()
        {
            return new ArraySegment<byte>(this.Buffer, this.Offset, this.Length);
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public byte[] ToArrayFast()
        {
            byte[] buffer = this.Buffer;
            if (buffer == null)
            {
                return BufferSegment.Empty;
            }
            if (this.Length < 1)
            {
                return BufferSegment.Empty;
            }
            if (this.Offset != 0)
            {
                return this.ToArray();
            }
            if (buffer.Length != this.Length)
            {
                return this.ToArray();
            }
            return buffer;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public byte[] ToArray()
        {
            return ToArraySegment().ToArray();
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public void CopyTo(byte[] destination)
        {
            ToArraySegment().CopyTo(destination, 0);
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public void CopyTo(byte[] destination, int destinationIndex)
        {
            ToArraySegment().CopyTo(destination, destinationIndex);
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public void CopyTo(Stream stream)
        {
            if (stream == null)
            {
                throw new ArgumentNullException(nameof(stream));
            }

            stream.Write(this.Buffer, this.Offset, this.Length);
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public IntPtr UnsafeAddrOfPinnedArrayElement()
        {
            return UnsafeAddrOfPinnedArrayElement(null);
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public IntPtr UnsafeAddrOfPinnedArrayElement(Action<IntPtr> callback)
        {
            IntPtr ptr = IntPtr.Zero;
            var buffer = this.Buffer;
            fixed (byte* pinned = buffer)
            {
                if (pinned != null)
                {
                    int num = (this.Offset + this.Length);
                    if (buffer.Length >= num)
                    {
                        ptr = (IntPtr)(pinned + this.Offset);
                    }
                }
                callback?.Invoke(ptr);
            }
            return ptr;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public override string ToString()
        {
            string s = string.Empty;
            UnsafeAddrOfPinnedArrayElement((p) =>
            {
                if (p == null)
                    s = null;
                else
                    s = new string((sbyte*)p, 0, this.Length, Encoding.Default);
            });
            return s;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public IEnumerator GetEnumerator()
        {
            IEnumerable<byte> enumerator = this;
            return enumerator.GetEnumerator();
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        IEnumerator<byte> IEnumerable<byte>.GetEnumerator()
        {
            byte[] buf = this.Buffer;
            int i = this.Offset;
            int l = this.Length;
            for (; i < l; i++)
            {
                yield return buf[i];
            }
        }
    }

    public unsafe static class Extension
    {
        // KMP
#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static int IndexOf(ref int[] next, byte* src, int src_len, byte* sub, int sub_len)
        {
            int i = 0;
            int j = 0;
            FindNext(ref next, sub, sub_len);
            while (i < src_len && j < sub_len)
            {
                if (j == -1 || src[i] == sub[j])
                {
                    i++;
                    j++;
                }
                else
                {
                    j = next[j];
                }
            }
            if (j >= sub_len)
            {
                return i - sub_len;
            }
            else
            {
                return -1;
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        private static void FindNext(ref int[] next, byte* sub, int sub_len)
        {
            int l = sub_len - 1;
            int i = 0;
            int j = -1;
            next[0] = -1;
            while (i < l)
            {
                if (j == -1 || sub[i] == sub[j])
                {
                    j++;
                    i++;
                    if (sub[i] == sub[j])
                    {
                        next[i] = next[j];
                    }
                    else
                    {
                        next[i] = j;
                    }
                }
                else
                {
                    j = next[j];
                }
            }
        }

#if !NETCOREAPP2_0
        public static T[] ToArray<T>(this ArraySegment<T> segment)
        {
            T[] s = null;
            if (segment != null)
            {
                s = new T[segment.Count];
                CopyTo(segment, s, 0);
            }
            return s;
        }

        public static void CopyTo<T>(this ArraySegment<T> segment, T[] destination, int destinationIndex)
        {
            if (segment != null && destination != null && destinationIndex >= 0)
            {
                Buffer.BlockCopy(segment.Array, segment.Offset, destination, destinationIndex, segment.Count);
            }
        }

        public static bool Remove<TKey, TValue>(this IDictionary<TKey, TValue> dictionary, TKey key, out TValue value)
        {
            value = default(TValue);
            if (dictionary == null)
            {
                return false;
            }

            lock (dictionary)
            {
                if (!dictionary.TryGetValue(key, out value))
                {
                    return false;
                }

                return dictionary.Remove(key);
            }
        }

        public static IEnumerable<KeyValuePair<TKey, TValue>> ToList<TKey, TValue>(this IDictionary<TKey, TValue> d)
        {
            if (d is System.Collections.Concurrent.ConcurrentDictionary<TKey, TValue>)
            {
                return d;
            }
            return System.Linq.Enumerable.ToList(d);
        }

        public static bool TryAdd<TKey, TValue>(this IDictionary<TKey, TValue> dictionary, TKey key, TValue value)
        {
            if (dictionary == null)
            {
                return false;
            }

            lock (dictionary)
            {
                if (dictionary.ContainsKey(key))
                {
                    return false;
                }

                dictionary.Add(key, value);
            }
            return true;
        }
#endif
#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static byte GetBitValueAt(this byte b, byte offset, byte length)
        {
            return (byte)((b >> offset) & ~(0xff << length));
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static byte GetBitValueAt(this byte b, byte offset)
        {
            return b.GetBitValueAt(offset, 1);
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static byte SetBitValueAt(this byte b, byte offset, byte length, byte value)
        {
            int mask = ~(0xff << length);
            value = (byte)(value & mask);

            return (byte)((value << offset) | (b & ~(mask << offset)));
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static byte SetBitValueAt(this byte b, byte offset, byte value)
        {
            return b.SetBitValueAt(offset, 1, value);
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public unsafe static void* Memcpy(void* dst, void* src, int size)
        {
            if (null == dst || null == src)
            {
                return null;
            }
            if ((src < dst) && ((((byte*)src) + size) > (byte*)dst)) // 自后向前拷贝  
            {
                byte* psrc = ((byte*)src) + size;
                byte* pdst = ((byte*)src) + size;
                while (size-- > 0)
                {
                    *--pdst = *--psrc;
                }
            }
            else
            {
                byte* psrc = (byte*)src;
                byte* pdst = (byte*)dst;
                while (size-- > 0)
                {
                    *pdst++ = *psrc++;
                }
            }
            return dst;
        }
    }
}
