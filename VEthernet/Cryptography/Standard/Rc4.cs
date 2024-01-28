namespace VEthernet.Cryptography.Standard
{
    using System;
#if NETCOREAPP
    using System.Runtime.CompilerServices;
#endif
    using global::VEthernet.Core;
    using Base = global::VEthernet.Core.Cryptography.Rc4;

    public unsafe sealed class Rc4
    {
        public const int MAXBIT = Base.MAXBIT;

        private readonly byte[] vk; // s-box
        private readonly string key;

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public Rc4(string key, byte[] vk)
        {
            if (string.IsNullOrEmpty(key))
            {
                throw new ArgumentException("key");
            }
            this.vk = vk;
            this.key = key;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static byte[] SBox(string key)
        {
            byte[] result = new byte[MAXBIT];
            fixed (byte* box = result)
            {
                for (int i = 0; i < MAXBIT; i++)
                {
                    box[MAXBIT - (i + 1)] = (byte)i;
                }
                for (int i = 0, j = 0; i < MAXBIT; i++)
                {
                    j = (j + box[i] + key[i % key.Length]) % MAXBIT;
                    byte b = box[i];
                    box[i] = box[j];
                    box[j] = b;
                }
            }
            return result;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        private void Encrypt(string key, byte[] sbox, byte* num, int len)
        {
            byte[] vk_ = new byte[sbox.Length];
            Buffer.BlockCopy(sbox, 0, vk_, 0, vk_.Length);
            fixed (byte* vk = vk_)
            {
                for (int i = 0, low = 0, high = 0, mid; i < len; i++)
                {
                    low = (low + key.Length) % MAXBIT;
                    high = (high + vk[i % MAXBIT]) % MAXBIT;

                    byte b = vk[low];
                    vk[low] = vk[high];
                    vk[high] = b;

                    mid = (vk[low] + vk[high]) % MAXBIT;
                    num[i] ^= (byte)vk[mid];
                }
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public BufferSegment Encrypt(byte[] buffer, int offset, int length)
        {
            int counts = 0;
            if (buffer != null)
            {
                counts = buffer.Length;
            }
            if (buffer == null && (offset != 0 || length != 0))
            {
                throw new ArgumentOutOfRangeException("buffer == null && (offset != 0 || length != 0)");
            }
            if (offset < 0)
            {
                throw new ArgumentOutOfRangeException("offset < 0");
            }
            if (length < 0)
            {
                throw new ArgumentOutOfRangeException("length < 0");
            }
            int m = (offset + length);
            if (m > counts)
            {
                throw new ArgumentOutOfRangeException("(offset + length) > buffer.Length");
            }
            if (offset == counts)
            {
                return new byte[0];
            }
            byte[] content = new byte[length];
            Buffer.BlockCopy(buffer, offset, content, 0, length);
            fixed (byte* pinned = content)
            {
                Encrypt(key, vk, pinned, length);
            }
            return content;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public BufferSegment Decrypt(byte[] buffer, int offset, int length)
        {
            int counts = 0;
            if (buffer != null)
            {
                counts = buffer.Length;
            }
            if (buffer == null && (offset != 0 || length != 0))
            {
                throw new ArgumentOutOfRangeException("buffer == null && (offset != 0 || length != 0)");
            }
            if (offset < 0)
            {
                throw new ArgumentOutOfRangeException("offset < 0");
            }
            if (length < 0)
            {
                throw new ArgumentOutOfRangeException("length < 0");
            }
            int m = (offset + length);
            if (m > counts)
            {
                throw new ArgumentOutOfRangeException("(offset + length) > buffer.Length");
            }
            if (offset == counts)
            {
                return new byte[0];
            }
            byte[] content = new byte[length];
            Buffer.BlockCopy(buffer, offset, content, 0, length);
            fixed (byte* pinned = content)
            {
                Encrypt(key, vk, pinned, length);
            }
            return content;
        }
    }
}
