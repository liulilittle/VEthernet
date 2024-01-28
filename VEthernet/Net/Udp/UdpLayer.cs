namespace VEthernet.Net.Udp
{
    using System;
    using System.Net;
    using System.Net.Sockets;
#if NETCOREAPP
    using System.Runtime.CompilerServices;
#endif
    using System.Runtime.InteropServices;
    using VEthernet.Core;
    using VEthernet.Net.IP;

    public unsafe static class UdpLayer
    {
#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
        public static IPFrame ToIPFrame(UdpFrame frame)
        {
            if (frame == null)
            {
                throw new ArgumentNullException(nameof(frame));
            }

            if (frame.AddressFamily != AddressFamily.InterNetwork)
            {
                throw new ArgumentNullException("UDP frames of this address family type are not supported.");
            }

            int payload_size = frame.Payload.Length;
            if (payload_size < 1)
            {
                return null;
            }

            int payload_offset = sizeof(udp_hdr);
            byte[] message = new byte[payload_offset + payload_size];
            fixed (byte* pinned = message)
            {
                udp_hdr* udphdr = (udp_hdr*)pinned;
                udphdr->src = CheckSum.htons((ushort)frame.Source.Port);
                udphdr->dest = CheckSum.htons((ushort)frame.Destination.Port);
                udphdr->len = CheckSum.htons((ushort)message.Length);
                udphdr->chksum = 0;

                Buffer.BlockCopy(frame.Payload.Buffer,
                    frame.Payload.Offset,
                    message,
                    payload_offset,
                    payload_size);

                ushort pseudo_checksum = CheckSum.inet_chksum_pseudo(pinned,
                    (uint)ProtocolType.Udp,
                    (uint)message.Length,
                    IPFrame.GetAddressV4(frame.Source.Address),
                    IPFrame.GetAddressV4(frame.Destination.Address));
                if (pseudo_checksum == 0)
                {
                    pseudo_checksum = 0xffff;
                }

                udphdr->chksum = pseudo_checksum;
            }
            return new IPFrame(ProtocolType.Udp,
                frame.Source.Address,
                frame.Destination.Address,
                new BufferSegment(message))
            {
                Ttl = frame.Ttl,
                Tos = 0x04,
                Flags = 0x00,
            };
        }

        [StructLayout(LayoutKind.Explicit, Pack = 1, Size = 8)]
        private struct udp_hdr
        {
            [FieldOffset(0)]
            public ushort src;
            [FieldOffset(2)]
            public ushort dest;  /* src/dest UDP ports */
            [FieldOffset(4)]
            public ushort len;
            [FieldOffset(6)]
            public ushort chksum;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
        public static UdpFrame ParseFrame(IPFrame ip, bool checksum = true)
        {
            if (ip == null)
            {
                return null;
            }

            UdpFrame frame = null;
            BufferSegment messages = ip.Payload;
            messages.UnsafeAddrOfPinnedArrayElement((p) =>
            {
                udp_hdr* udphdr = (udp_hdr*)p;
                if (udphdr == null)
                {
                    return;
                }

                if (messages.Length != CheckSum.ntohs(udphdr->len)) // 错误的数据报
                {
                    return;
                }

                int offset = sizeof(udp_hdr);
                int len = messages.Length - offset;
                if (len < 1)
                {
                    return;
                }

                #if PACKET_CHECKSUM
                if (checksum && udphdr->chksum != 0)
                {
                    uint pseudo_checksum = CheckSum.inet_chksum_pseudo((byte*)p.ToPointer(),
                        (uint)ProtocolType.Udp,
                        (uint)messages.Length,
                        ip.SourceAddressV4,
                        ip.DestinationAddressV4);
                    if (pseudo_checksum != 0)
                    {
                        return;
                    }
                }
                #endif

                BufferSegment message = new BufferSegment(messages.Buffer, messages.Offset + offset, len);
                frame = new UdpFrame(
                    new IPEndPoint(ip.Source, CheckSum.ntohs(udphdr->src)),
                    new IPEndPoint(ip.Destination, CheckSum.ntohs(udphdr->dest)), message)
                {
                    Ttl = ip.Ttl,
                };
            });
            return frame;
        }
    }
}