namespace VEthernet.Core.Cryptography
{
#if NETCOREAPP
    using System.Runtime.CompilerServices;
#endif

    public unsafe static class Rc4
    {
        public const int MAXBIT = byte.MaxValue;

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        private static void rc4_sbox(byte* box, string key)
        {
            if (null == box || null == key || key.Length < 1)
                return;

            for (int i = 0; i < MAXBIT; i++)
                box[i] = (byte)i;

            for (int i = 0, j = 0; i < MAXBIT; i++)
            {
                j = (j + box[i] + (byte)key[i % key.Length]) % MAXBIT;
                byte b = box[i];
                box[i] = box[j];
                box[j] = b;
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static void rc4_crypt(string key, byte* data, int datalen, int subtract, int E)
        {
            if (null == key || key.Length < 1 || null == data || datalen < 1)
                return;

            byte* box = stackalloc byte[MAXBIT];
            rc4_sbox(box, key);

            byte x = (byte)(0 != E ? subtract : -subtract);
            for (int i = 0, low = 0, high = 0, mid; i < datalen; i++)
            {
                low = low % MAXBIT;
                high = (high + box[i % MAXBIT]) % MAXBIT;

                byte b = box[low];
                box[low] = box[high];
                box[high] = b;

                mid = (box[low] + box[high]) % MAXBIT;
                if (0 != E)
                    data[i] = (byte)((data[i] ^ box[mid]) - x);
                else
                    data[i] = (byte)((data[i] - x) ^ box[mid]);
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        private static void rc4_sbox(byte* box, byte* key, int keylen)
        {
            if (null == box || null == key || keylen < 1)
                return;

            for (int i = 0; i < MAXBIT; i++)
                box[i] = (byte)i;

            for (int i = 0, j = 0; i < MAXBIT; i++)
            {
                j = (j + box[i] + (byte)key[i % keylen]) % MAXBIT;
                byte b = box[i];
                box[i] = box[j];
                box[j] = b;
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static void rc4_crypt(byte* key, int keylen, byte* data, int datalen, int subtract, int E)
        {
            if (null == key || keylen < 1 || null == data || datalen < 1)
                return;

            byte* box = stackalloc byte[MAXBIT];
            rc4_sbox(box, key, keylen);

            byte x = (byte)(0 != E ? subtract : -subtract);
            for (int i = 0, low = 0, high = 0, mid; i < datalen; i++)
            {
                low = low % MAXBIT;
                high = (high + box[i % MAXBIT]) % MAXBIT;

                byte b = box[low];
                box[low] = box[high];
                box[high] = b;

                mid = (box[low] + box[high]) % MAXBIT;
                if (0 != E)
                    data[i] = (byte)((data[i] ^ box[mid]) - x);
                else
                    data[i] = (byte)((data[i] - x) ^ box[mid]);
            }
        }
    }
}
