namespace VEthernet.IO
{
    using System;
    using System.IO;
    using System.Text;
#if NETCOREAPP
    using System.Runtime.CompilerServices;
#endif

    public static class FileAuxiliary
    {
#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static Encoding GetEncoding(byte[] s) => GetEncoding(s, null);

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public unsafe static Encoding GetEncoding(byte[] s, Encoding defaultEncoding)
        {
            fixed (byte* p = s)
            {
                return GetEncoding(p, unchecked(s != null ? s.Length : 0), defaultEncoding);
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static unsafe Encoding GetEncoding(byte* s, int datalen) => GetEncoding(s, datalen, null);

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static unsafe Encoding GetDefaultEncoding() => GetDefaultEncoding(null);

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static unsafe Encoding GetDefaultEncoding(Encoding defaultEncoding) => GetEncoding(null, 0, defaultEncoding);

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static unsafe Encoding GetEncoding(byte* s, int datalen, Encoding defaultEncoding, out int offset)
        {
            offset = 0;
            Encoding encoding = defaultEncoding ?? Encoding.Default;
            if (s == null || datalen < 3)
            {
                return encoding;
            }
            // byte[] Unicode = new byte[] { 0xFF, 0xFE, 0x41 };
            // byte[] UnicodeBIG = new byte[] { 0xFE, 0xFF, 0x00 };
            // byte[] UTF8 = new byte[] { 0xEF, 0xBB, 0xBF }; // 带BOM 
            if (s[0] == 0xEF && s[1] == 0xBB && s[2] == 0xBF)
            {
                offset += 3;
                encoding = Encoding.UTF8;
            }
            else if (s[0] == 0xFE && s[1] == 0xFF && s[2] == 0x00)
            {
                offset += 3;
                encoding = Encoding.BigEndianUnicode;
            }
            else if (s[0] == 0xFF && s[1] == 0xFE && s[2] == 0x41)
            {
                offset += 3;
                encoding = Encoding.Unicode;
            }
            return encoding;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static unsafe Encoding GetEncoding(byte* s, int datalen, Encoding defaultEncoding) =>
            GetEncoding(s, datalen, defaultEncoding, out int offset);

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static bool TryReadAllText(string path, out string value) => TryReadAllText(path, null, out value);

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static Encoding GetEncoding(string path) => GetEncoding(path, null);

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static unsafe Encoding GetEncoding(string path, Encoding defaultEncoding)
        {
            if (!File.Exists(path))
            {
                return GetDefaultEncoding(defaultEncoding);
            }
            FileStream stream = null;
            Encoding encoding = null;
            try
            {
                stream = new FileStream(path, FileMode.Open, FileAccess.Read);
                if (stream.Length < 1)
                {
                    encoding = GetDefaultEncoding(defaultEncoding);
                }
                else
                {
                    byte[] data = new byte[5];
                    int datalen = stream.Read(data, 0, data.Length);
                    fixed (byte* p = data)
                    {
                        encoding = GetEncoding(p, datalen, defaultEncoding);
                    }
                }
            }
            catch
            {
                encoding = GetDefaultEncoding(defaultEncoding);
            }
            if (stream != null)
            {
                stream.Dispose();
            }
            return encoding;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static bool TryReadAllText(string path, Encoding encoding, out string value)
        {
            value = null;
            if (!File.Exists(path))
            {
                return false;
            }
            try
            {
                byte[] buffer = File.ReadAllBytes(path);
                if (encoding == null)
                {
                    encoding = GetEncoding(buffer);
                }
                int length = buffer.Length;
                int offset = 0;
                unsafe
                {
                    fixed (byte* p = buffer)
                    {
                        GetEncoding(p, length, encoding, out offset);
                        if (offset > 0)
                        {
                            length = length - offset;
                        }
                    }
                };
                value = encoding.GetString(buffer, offset, length);
                return true;
            }
            catch
            {
                return false;
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static int GetFileLength(string path) => unchecked((int)GetFileLength64(path));

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static bool Exists(string path)
        {
            if (string.IsNullOrEmpty(path))
            {
                return false;
            }
            return File.Exists(path);
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static long GetFileLength64(string path)
        {
            try
            {
                if (!FileAuxiliary.Exists(path))
                {
                    return 0;
                }
                FileInfo info = new FileInfo(path);
                return info.Length;
            }
            catch
            {
                return 0;
            }
        }
    }
}
