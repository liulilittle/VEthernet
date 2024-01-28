namespace VEthernet.Converter
{
    using System;
    using System.Net;
    using System.Net.Sockets;
#if NETCOREAPP
    using System.Runtime.CompilerServices;
#endif

    public static unsafe partial class BitConverterr
    {
#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static int ToInt32(ref byte* p)
        {
            return (int)ToInt64(ref p, sizeof(int));
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static uint ToUInt32(ref byte* p)
        {
            return (uint)ToInt64(ref p, sizeof(uint));
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static ushort ToUInt16(ref byte* p)
        {
            return (ushort)ToInt64(ref p, sizeof(ushort));
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static long ToInt64(ref byte* p)
        {
            return ToInt64(ref p, sizeof(long));
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static short ToInt16(ref byte* p)
        {
            return (short)ToInt64(ref p, sizeof(short));
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static ulong ToUInt64(ref byte* p)
        {
            return (ulong)ToInt64(ref p, sizeof(ulong));
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static byte ToByte(ref byte* p)
        {
            return *p++;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static sbyte ToSByte(ref byte* p)
        {
            return (sbyte)*p++;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        private static long ToInt64(ref byte* p, int size)
        {
#pragma warning disable CS0675 // 对进行了带符号扩展的操作数使用了按位或运算符
            long num = 0;
            byte* x = (byte*)&num;
            for (int i = size - 1, j = 0; i >= 0; i--, j++)
            {
                x[j] = p[i];
            }
            p += size;
            return num;
#pragma warning restore CS0675 // 对进行了带符号扩展的操作数使用了按位或运算符
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static DateTime ToDateTime(ref byte* p)
        {
            return new DateTime(ToInt64(ref p, sizeof(long)));
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static double ToDouble(ref byte* p)
        {
            long num = ToInt64(ref p, sizeof(long));
            return BitConverter.Int64BitsToDouble(num);
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static float ToSingle(ref byte* p)
        {
            byte[] buf = new byte[4];
            fixed (byte* bp = buf)
            {
                for (int i = 3; i >= 0; i--)
                    bp[i] = *p++;
            }
            return BitConverter.ToSingle(buf, 0);
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static IPAddress ToIPAddress(ref byte* p)
        {
            byte[] buf = new byte[4];
            fixed (byte* bp = buf)
            {
                for (int i = 3; i >= 0; i--)
                    bp[i] = *p++;
            }
            return new IPAddress(buf);
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static bool ToBoolean(ref byte* buf)
        {
            return *buf++ != 0;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static byte[] GetBytes(long num)
        {
            return GetBytes(num, sizeof(long));
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static byte[] GetBytes(ulong num)
        {
            return GetBytes((long)num, sizeof(ulong));
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static byte[] GetBytes(uint num)
        {
            return GetBytes(num, sizeof(uint));
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static byte[] GetBytes(int num)
        {
            return GetBytes(num, sizeof(int));
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static byte[] GetBytes(short num)
        {
            return GetBytes(num, sizeof(short));
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static byte[] GetBytes(ushort num)
        {
            return GetBytes(num, sizeof(ushort));
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static byte[] GetBytes(char ch)
        {
            return GetBytes(ch, sizeof(char));
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static byte[] GetBytes(sbyte num)
        {
            return GetBytes(num, sizeof(sbyte));
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static byte[] GetBytes(bool num)
        {
            return GetBytes(num ? 1 : 0, sizeof(bool));
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static byte[] GetBytes(byte num)
        {
            return GetBytes(num, sizeof(byte));
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static byte[] GetBytes(double num)
        {
            long value = BitConverter.DoubleToInt64Bits(num);
            return GetBytes(value, sizeof(long));
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static byte[] GetBytes(float num)
        {
            return GetBytes(*(int*)&num, sizeof(float));
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static byte[] GetBytes(DateTime datetime)
        {
            return GetBytes(datetime.Ticks, sizeof(long));
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static byte[] GetBytes(IPAddress address)
        {
#pragma warning disable CS0618 // 类型或成员已过时
            if (address.AddressFamily != AddressFamily.InterNetwork)
                throw new ArgumentException();
            return GetBytes(address.Address, sizeof(int));
#pragma warning restore CS0618 // 类型或成员已过时
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        private static byte[] GetBytes(long value, int size)
        {
            byte[] buf = new byte[size];
            byte* y = (byte*)&value;
            fixed (byte* x = buf)
            {
                for (int i = size - 1, j = 0; i >= 0; i--, j++)
                    x[j] = y[i];
            }
            return buf;
        }
    }
}
