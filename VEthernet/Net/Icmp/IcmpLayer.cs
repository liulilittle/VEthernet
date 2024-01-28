namespace VEthernet.Net.Icmp
{
    using System;
    using System.Net.Sockets;
#if NETCOREAPP
    using System.Runtime.CompilerServices;
#endif
    using System.Runtime.InteropServices;
    using VEthernet.Core;
    using VEthernet.Net.IP;

    public unsafe sealed class IcmpLayer
    {
        [StructLayout(LayoutKind.Sequential, Pack = 1)] // RFC 792(http://www.faqs.org/rfcs/rfc792.html)
        private struct icmp_hdr
        {
            public byte icmp_type;      // icmp service type, 8 echo request, 0 echo reply
            public byte icmp_code;      // icmp header code
            public ushort icmp_chksum;  // icmp header chksum
            public ushort icmp_id;      // icmp packet identification
            public ushort icmp_seq;     // icmp packet sequent
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static IPFrame ToIPFrame(IcmpFrame frame)
        {
            if (frame == null)
            {
                throw new ArgumentNullException(nameof(frame));
            }
            if (frame.AddressFamily != AddressFamily.InterNetwork)
            {
                throw new ArgumentNullException("ICMP frames of this address family type are not supported.");
            }
            BufferSegment payload = frame.Payload;
            byte[] buffer = new byte[sizeof(icmp_hdr) + payload?.Length ?? 0];
            fixed (byte* pinned = buffer)
            {
                icmp_hdr* icmp = (icmp_hdr*)pinned;
                icmp->icmp_type = (byte)frame.Type;
                icmp->icmp_code = frame.Code;
                icmp->icmp_id = CheckSum.ntohs(frame.Identification);
                icmp->icmp_seq = CheckSum.ntohs(frame.Sequence);
                icmp->icmp_chksum = 0;
                if (payload != null)
                {
                    Marshal.Copy(payload.Buffer, payload.Offset, (IntPtr)(pinned + sizeof(icmp_hdr)), payload.Length);
                }
                icmp->icmp_chksum = CheckSum.inet_chksum(icmp, buffer.Length);
                if (icmp->icmp_chksum == 0)
                {
                    icmp->icmp_chksum = 0xffff;
                }
            }
            return new IPFrame(ProtocolType.Icmp, frame.Source, frame.Destination, new BufferSegment(buffer))
            {
                Ttl = frame.Ttl,
            };
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static IcmpFrame ParseFrame(IPFrame ip, bool checksum = true)
        {
            if (ip == null)
            {
                return null;
            }
            IcmpFrame frame = null;
            BufferSegment segment = ip.Payload;
            segment.UnsafeAddrOfPinnedArrayElement(p =>
            {
                icmp_hdr* icmp = (icmp_hdr*)p;
                #if PACKET_CHECKSUM
                if (checksum && icmp->icmp_chksum != 0)
                {
                    ushort cksum = CheckSum.inet_chksum(icmp, segment.Length);
                    if (cksum != 0)
                    {
                        return;
                    }
                }
                #endif
                int hdr_bytes_len = sizeof(icmp_hdr);
                int payload_size = segment.Length - hdr_bytes_len;
                if (payload_size < 0)
                {
                    return;
                }
                frame = new IcmpFrame(ip.Source, ip.Destination, new BufferSegment(segment.Buffer, segment.Offset + hdr_bytes_len, payload_size))
                {
                    Type = (IcmpType)icmp->icmp_type,
                    Code = icmp->icmp_code,
                    Identification = CheckSum.ntohs(icmp->icmp_id),
                    Sequence = CheckSum.ntohs(icmp->icmp_seq),
                    Ttl = ip.Ttl,
                };
            });
            return frame;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public IcmpFrame Parse(IPFrame ip) => ParseFrame(ip);
    }
}
