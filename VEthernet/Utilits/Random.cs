namespace VEthernet.Utilits
{
    using System;
#if NETCOREAPP
    using System.Runtime.CompilerServices;
#endif

    public sealed class Random
    {
        private uint seed;

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public Random() => this.seed = (uint)Environment.TickCount;

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public Random(int seed) => this.seed = (uint)seed;

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        private static int Next(ref uint seed)
        {
            uint next = seed;
            int result;

            next *= 1103515245;
            next += 12345;
            result = (int)(next / 65536) % 2048;

            next *= 1103515245;
            next += 12345;
            result <<= 10;
            result ^= (int)(next / 65536) % 1024;

            next *= 1103515245;
            next += 12345;
            result <<= 10;
            result ^= (int)(next / 65536) % 1024;

            seed = next;
            return result;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public int Next() => Next(ref seed);

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public int Next(int min, int max)
        {
            int v = Next(ref this.seed);
            return v % (max - min + 1) + min;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public double NextDouble()
        {
            unsafe
            {
                double* d = stackalloc double[1];
                int* p = (int*)d;
                *p++ = Next();
                *p++ = Next();
                return *d;
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public void NextBytes(byte[] buffer)
        {
            unsafe
            {
                fixed (byte* p = buffer)
                {
                    for (int i = 0; i < buffer.Length; i++)
                    {
                        p[i] = (byte)Next(byte.MinValue, byte.MaxValue);
                    }
                }
            }
        }
    }
}
