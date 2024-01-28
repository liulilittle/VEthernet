namespace VEthernet.Core
{
#if NETCOREAPP
    using System.Runtime.CompilerServices;
#endif

    public unsafe static class CheckSum
    {
#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static ushort ip_standard_chksum(void* dataptr, int len)
        {
            uint acc;
            ushort src;
            byte* octetptr;

            acc = 0;
            /* dataptr may be at odd or even addresses */
            octetptr = (byte*)dataptr;
            while (len > 1)
            {
                /* declare first octet as most significant
                   thus assume network order, ignoring host order */
                src = (ushort)((*octetptr) << 8);
                octetptr++;
                /* declare second octet as least significant */
                src |= (*octetptr);
                octetptr++;
                acc += src;
                len -= 2;
            }
            if (len > 0)
            {
                /* accumulate remaining octet */
                src = (ushort)((*octetptr) << 8);
                acc += src;
            }
            /* add deferred carry bits */
            acc = (uint)((acc >> 16) + (acc & 0x0000ffffUL));
            if ((acc & 0xffff0000UL) != 0)
            {
                acc = (uint)((acc >> 16) + (acc & 0x0000ffffUL));
            }
            /* This maybe a little confusing: reorder sum using htons()
               instead of ntohs() since it has a little less call overhead.
               The caller must invert bits for Internet sum ! */
            return ntohs((ushort)acc);
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static ushort inet_chksum(void* dataptr, int len)
        {
            return (ushort)~ip_standard_chksum(dataptr, len);
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        private static uint FOLD_U32T(uint u)
        {
            return ((uint)(((u) >> 16) + ((u) & 0x0000ffffUL)));
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        private static uint SWAP_BYTES_IN_WORD(uint w)
        {
            return (((w) & 0xff) << 8) | (((w) & 0xff00) >> 8);
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static ushort ntohs(ushort n)
        {
            ushort r = 0;
            byte* p1 = (byte*)&n;
            byte* p2 = (byte*)&r;

            p2[0] = p1[1];
            p2[1] = p1[0];
            return r;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static uint ntohl(uint n)
        {
            uint r = 0;
            byte* p1 = (byte*)&n;
            byte* p2 = (byte*)&r;

            p2[0] = p1[3];
            p2[1] = p1[2];
            p2[2] = p1[1];
            p2[3] = p1[0];
            return r;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static uint htonl(uint n)
        {
            return ntohl(n);
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static ushort htons(ushort n)
        {
            return ntohs(n);
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static ushort inet_cksum_pseudo_base(byte* payload, uint proto, uint proto_len, uint acc)
        {
            bool swapped = false;
            acc += ip_standard_chksum(payload, (int)proto_len);
            acc = FOLD_U32T(acc);

            if (proto_len % 2 != 0)
            {
                swapped = !swapped;
                acc = SWAP_BYTES_IN_WORD(acc);
            }

            if (swapped)
            {
                acc = SWAP_BYTES_IN_WORD(acc);
            }

            acc += htons((ushort)proto);
            acc += htons((ushort)proto_len);

            acc = FOLD_U32T(acc);
            acc = FOLD_U32T(acc);

            return (ushort)~(acc & 0xffffUL);
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static ushort inet_chksum_pseudo(byte* payload, uint proto, uint proto_len, uint src, uint dest)
        {
            uint acc;
            uint addr;

            addr = src;
            acc = (addr & 0xffff);
            acc = (acc + ((addr >> 16) & 0xffff));
            addr = dest;
            acc = (acc + (addr & 0xffff));
            acc = (acc + ((addr >> 16) & 0xffff));
            /* fold down to 16 bits */
            acc = FOLD_U32T(acc);
            acc = FOLD_U32T(acc);

            return inet_cksum_pseudo_base(payload, proto, proto_len, acc);
        }
    }
}
