namespace VEthernet.Core.Cryptography
{
    using System;
    using System.Security.Cryptography;
    using System.Text;
#if NETCOREAPP
    using System.Runtime.CompilerServices;
#endif
    using VEthernet.Core;

    public static class Hash<T> where T : HashAlgorithm
    {
#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        private static T NewInstance()
        {
            if (typeof(T) == typeof(MD5))
            {
                return (T)(object)MD5.Create();
            }
            if (typeof(T) == typeof(HMACMD5))
            {
                return (T)(object)HMAC.Create();
            }
            if (typeof(T) == typeof(SHA1))
            {
                return (T)(object)SHA1.Create();
            }
            if (typeof(T) == typeof(SHA256))
            {
                return (T)(object)SHA256.Create();
            }
            if (typeof(T) == typeof(SHA384))
            {
                return (T)(object)SHA384.Create();
            }
            if (typeof(T) == typeof(SHA512))
            {
                return (T)(object)SHA512.Create();
            }
            if (typeof(T) == typeof(HMACSHA1))
            {
                return (T)(object)HMACSHA1.Create();
            }
            if (typeof(T) == typeof(HMACSHA256))
            {
                return (T)(object)HMACSHA256.Create();
            }
            if (typeof(T) == typeof(HMACSHA384))
            {
                return (T)(object)HMACSHA384.Create();
            }
            if (typeof(T) == typeof(HMACSHA512))
            {
                return (T)(object)HMACSHA512.Create();
            }
            throw new NotSupportedException(typeof(T).FullName);
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static byte[] ComputeHash(byte[] buffer) => ComputeHash(buffer, buffer?.Length ?? 0);

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static byte[] ComputeHash(byte[] buffer, int length)
        {
            if (buffer == null || buffer.Length < 1)
            {
                return BufferSegment.Empty;
            }
            return ComputeHash(buffer, 0, length);
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static byte[] ComputeHash(byte[] buffer, int offset, int length)
        {
            if (buffer == null || buffer.Length < 1)
            {
                return BufferSegment.Empty;
            }
            using (T hash = NewInstance())
            {
                try
                {
                    return hash.ComputeHash(buffer, offset, length);
                }
                catch
                {
                    return BufferSegment.Empty;
                }
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public unsafe static string ToString(byte[] buffer, int offset, int length)
        {
            buffer = ComputeHash(buffer, offset, length);
            if (buffer == null || buffer.Length < 1)
            {
                return string.Empty;
            }
            string message = string.Empty;
            fixed (byte* p = buffer)
            {
                for (int i = 0; i < buffer.Length; i++)
                {
                    message += p[i].ToString("X2");
                }
            }
            return message;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static string ToString(string value, Encoding encoding)
        {
            if (string.IsNullOrEmpty(value))
            {
                return string.Empty;
            }
            byte[] bytes = encoding.GetBytes(value);
            return ToString(bytes, 0, bytes.Length);
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static string ToString(string value)
        {
            return ToString(value, Encoding.UTF8);
        }
    }
}
