namespace VEthernet.IO.Compression
{
    using System;
    using System.IO;
    using System.IO.Compression;
#if NETCOREAPP
    using System.Runtime.CompilerServices;
#endif

    public static class LZ77Auxiliary
    {
        public enum LZ77Algorithm
        {
            GZip = 0,
            Deflate = 1
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static byte[] Compress(byte[] buffer, LZ77Algorithm algorithm)
        {
            using (MemoryStream ms = new MemoryStream())
            {
                using (Stream cs = New(ms, CompressionMode.Compress, algorithm))
                {
                    cs.Write(buffer, 0, buffer.Length);
                }
                return ms.ToArray();
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        private static Stream New(Stream stream, CompressionMode mode, LZ77Algorithm algorithm)
        {
            if (algorithm == LZ77Algorithm.GZip)
            {
                return new GZipStream(stream, mode);
            }
            if (algorithm == LZ77Algorithm.Deflate)
            {
                return new DeflateStream(stream, mode);
            }
            throw new NotSupportedException("algorithm");
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static byte[] Decompress(byte[] buffer, LZ77Algorithm algorithm)
        {
            using (MemoryStream ms = new MemoryStream(buffer))
            {
                using (Stream ds = New(ms, CompressionMode.Decompress, algorithm))
                {
                    using (MemoryStream ss = new MemoryStream())
                    {
                        byte[] tmp = new byte[1024];
                        int size = 0;
                        while ((size = ds.Read(tmp, 0, tmp.Length)) > 0)
                        {
                            ss.Write(tmp, 0, size);
                        }
                        return ss.ToArray();
                    }
                }
            }
        }
    }
}
