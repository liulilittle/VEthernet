namespace VEthernet.Net.IP
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Net;
    using System.Net.Sockets;
#if NETCOREAPP
    using System.Runtime.CompilerServices;
#endif
    using System.Runtime.InteropServices;
    using System.Threading;
    using VEthernet.Core;

    public unsafe sealed class IPv4Layer
    {
        public const int MTU = 1500;

        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private static volatile int _locationId = Environment.TickCount;

        [StructLayout(LayoutKind.Sequential, Pack = 1, Size = 20)]
        internal struct ip_hdr
        {
#pragma warning disable 0649
            /* version / header length / type of service */
            public byte _v_hl;
            /* type of service */
            public byte _tos;
            /* total length */
            public ushort _len;
            /* identification */
            public ushort _id;
            /* fragment offset field */
            public ushort _flags;
            /* time to live */
            public byte _ttl;
            /* protocol */
            public byte _proto;
            /* checksum */
            public ushort _chksum;
            /* source and destination IP addresses */
            public uint src;
            public uint dest;
#pragma warning restore 0649

#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            public static int IPH_V(ip_hdr* hdr)
            {
                return ((hdr)->_v_hl >> 4);
            }

#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            public static int IPH_HL(ip_hdr* hdr)
            {
                return ((hdr)->_v_hl & 0x0f);
            }

#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            public static int IPH_PROTO(ip_hdr* hdr)
            {
                return ((hdr)->_proto & 0xff);
            }

#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            public static int IPH_OFFSET(ip_hdr* hdr)
            {
                return (hdr)->_flags;
            }

#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            public static int IPH_TTL(ip_hdr* hdr)
            {
                return ((hdr)->_ttl & 0xff);
            }
        }

        public const byte TOS_ROUTIN_MODE = 0x00;
        private const uint IP_ADDR_ANY_VALUE = 0x00000000;
        private const uint IP_ADDR_BROADCAST_VALUE = 0xffffffff;

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        private static bool ip_addr_isbroadcast(uint addr)
        {
            /* all ones (broadcast) or all zeroes (old skool broadcast) */
            if ((~addr == IP_ADDR_ANY_VALUE) ||
                (addr == IP_ADDR_ANY_VALUE))
                return true;
            return false;
        }

        public const int IP_PROTO_ICMP = 1;
        public const int IP_PROTO_UDP = 17;
        public const int IP_PROTO_TCP = 6;
        public const int IP_PROTO_IGMP = 2;
        public const int IP_PROTO_GRE = 47;
        private const int IP_HLEN = 20;

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public IPFrame Parse(BufferSegment buffer) => ParseFrame(buffer);

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static IPFrame ParseFrame(BufferSegment packet, bool checksum = true)
        {
            if (packet == null)
            {
                return null;
            }
            IPFrame frame = null;
            packet.UnsafeAddrOfPinnedArrayElement(payload =>
            {
                ip_hdr* iphdr = (ip_hdr*)payload;
                if (iphdr == null)
                {
                    return;
                }
                if (ip_hdr.IPH_V(iphdr) != 4)
                {
                    return;
                }
                int iphdr_hlen = ip_hdr.IPH_HL(iphdr) << 2;
                if (iphdr_hlen > packet.Length)
                {
                    return;
                }
                if (iphdr_hlen < IP_HLEN)
                {
                    return;
                }
                int ttl = ip_hdr.IPH_TTL(iphdr);
                if (ttl < 1)
                {
                    return;
                }
                if (ip_addr_isbroadcast(iphdr->src) || ip_addr_isbroadcast(iphdr->dest))
                {
                    return;
                }
                //if ((ip_hdr.IPH_OFFSET(iphdr) & CheckSum.ntohs((ushort)(IPFlags.IP_OFFMASK | IPFlags.IP_MF))) != 0) 
                //{
                //    return;
                //}
#if PACKET_CHECKSUM
                if (checksum && iphdr->_chksum != 0)
                {
                    int cksum = CheckSum.inet_chksum(iphdr, iphdr_hlen);
                    if (cksum != 0)
                    {
                        return;
                    }
                }
#endif
                ProtocolType protocolType = (ProtocolType)ip_hdr.IPH_PROTO(iphdr);
                if (protocolType == (ProtocolType)IP_PROTO_UDP ||
                    protocolType == (ProtocolType)IP_PROTO_TCP ||
                    protocolType == (ProtocolType)IP_PROTO_ICMP ||
                    protocolType == (ProtocolType)IP_PROTO_GRE)
                {
                    BufferSegment message_data = new BufferSegment(packet.Buffer,
                        packet.Offset + iphdr_hlen,
                        packet.Length - iphdr_hlen);
                    BufferSegment options_data = null;
                    int options_size = (iphdr_hlen - sizeof(ip_hdr));
                    if (options_size < 1)
                    {
                        options_data = new BufferSegment(BufferSegment.Empty);
                    }
                    else
                    {
                        options_data = new BufferSegment(packet.Buffer,
                                packet.Offset + sizeof(ip_hdr), options_size);
                    }
                    frame = new IPFrame(protocolType,
                        new IPAddress(iphdr->src),
                        new IPAddress(iphdr->dest),
                        message_data)
                    {
                        Tag = packet,
                        Id = CheckSum.ntohs(iphdr->_id),
                        Ttl = ttl,
                        Tos = iphdr->_tos,
                        Options = options_data,
                        Flags = (IPFlags)CheckSum.ntohs(iphdr->_flags),
                    };
                }
            });
            return frame;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static ushort NewId() => (ushort)Interlocked.Increment(ref _locationId);

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static IList<IPFrame> Subpackages(IPFrame frame)
        {
            if (frame == null)
            {
                throw new ArgumentNullException(nameof(frame));
            }
            List<IPFrame> subpackages = new List<IPFrame>();
            if (0 != (frame.Flags & IPFlags.IP_MF))
            {
                subpackages.Add(frame);
                return subpackages;
            }
            BufferSegment messages = frame.Payload;
            BufferSegment options = frame.Options;
            if (messages == null)
            {
                subpackages.Add(frame);
                return subpackages;
            }
            int max = IPv4Layer.MTU - sizeof(ip_hdr);
            if (options != null)
            {
                max -= options.Length;
            }
            int szz = messages.Length;
            max = unchecked((max >> 3) << 3);
            if (szz <= max)
            {
                subpackages.Add(frame);
                return subpackages;
            }
            int ofs = 0;
            IPFrame fragment = null;
            while (szz > max)
            {
                fragment = new IPFrame(frame.ProtocolType,
                    frame.Source,
                    frame.Destination,
                    new BufferSegment(messages.Buffer, messages.Offset + ofs, max))
                {
                    Flags = IPFlags.IP_MF,
                    Id = frame.Id,
                    Options = options,
                    Ttl = frame.Ttl,
                    Tos = frame.Tos,
                    FragmentOffset = ofs,
                };
                options = null;
                ofs += max;
                szz -= max;
                subpackages.Add(fragment);
            }
            if (szz > 0)
            {
                fragment = new IPFrame(frame.ProtocolType,
                    frame.Source,
                    frame.Destination,
                    new BufferSegment(messages.Buffer, messages.Offset + ofs, szz))
                {
                    Flags = ofs < 1 ? frame.Flags : 0,
                    Id = frame.Id,
                    Options = options,
                    Ttl = frame.Ttl,
                    Tos = frame.Tos,
                    FragmentOffset = ofs,
                };
                subpackages.Add(fragment);
            }
            return subpackages;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static int SizeOf(IPFrame frame)
        {
            if (frame == null)
            {
                throw new ArgumentNullException(nameof(frame));
            }
            BufferSegment payload_segment = frame.Payload;
            BufferSegment options_segment = frame.Options;
            int options_size = 0;
            if (options_segment != null)
            {
                options_size = options_segment.Length;
            }
            int payload_offset = sizeof(ip_hdr) + options_size;
            int payload_size = 0;
            if (payload_segment != null)
            {
                payload_size = payload_segment.Length;
            }
            return payload_offset + payload_size;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static BufferSegment ReassemblyHeader(IPFrame frame)
        {
            if (frame == null)
            {
                throw new ArgumentNullException(nameof(frame));
            }
            BufferSegment payload_segment = frame.Payload;
            BufferSegment options_segment = frame.Options;
            int options_size = 0;
            if (options_segment != null)
            {
                options_size = options_segment.Length;
            }
            int payload_offset = sizeof(ip_hdr) + options_size;
            int payload_size = 0;
            if (payload_segment != null)
            {
                payload_size = payload_segment.Length;
            }
            int packet_size = payload_offset + payload_size;
            byte[] message_data = frame.Payload.Buffer;
            fixed (byte* pinned = message_data)
            {
                ip_hdr* iphdr = (ip_hdr*)pinned;
                iphdr->dest = frame.DestinationAddressV4;
                iphdr->src = frame.SourceAddressV4;
                iphdr->_ttl = (byte)frame.Ttl;
                iphdr->_proto = (byte)frame.ProtocolType;
                iphdr->_v_hl = (byte)(4 << 4 | payload_offset >> 2);
                iphdr->_tos = frame.Tos; // Routine Mode
                iphdr->_len = CheckSum.htons((ushort)packet_size);
                iphdr->_id = CheckSum.htons(frame.Id);
                iphdr->_flags = CheckSum.ntohs((ushort)(frame.Flags == 0 ? IPFlags.IP_DF : frame.Flags));
                iphdr->_chksum = 0;

                iphdr->_chksum = CheckSum.inet_chksum(pinned, payload_offset);
                if (iphdr->_chksum == 0)
                {
                    iphdr->_chksum = 0xffff;
                }
            }
            return new BufferSegment(message_data, 0, packet_size);
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static BufferSegment ToArray(IPFrame frame)
        {
            if (frame == null)
            {
                throw new ArgumentNullException(nameof(frame));
            }
            BufferSegment payload_segment = frame.Payload;
            BufferSegment options_segment = frame.Options;
            int options_size = 0;
            if (options_segment != null)
            {
                options_size = options_segment.Length;
            }
            int payload_offset = sizeof(ip_hdr) + options_size;
            int payload_size = 0;
            if (payload_segment != null)
            {
                payload_size = payload_segment.Length;
            }
            byte[] message_data = new byte[payload_offset + payload_size];
            fixed (byte* pinned = message_data)
            {
                ip_hdr* iphdr = (ip_hdr*)pinned;
                iphdr->dest = frame.DestinationAddressV4;
                iphdr->src = frame.SourceAddressV4;
                iphdr->_ttl = (byte)frame.Ttl;
                iphdr->_proto = (byte)frame.ProtocolType;
                iphdr->_v_hl = (byte)(4 << 4 | payload_offset >> 2);
                iphdr->_tos = frame.Tos; // Routine Mode
                iphdr->_len = CheckSum.htons((ushort)message_data.Length);
                iphdr->_id = CheckSum.htons(frame.Id);
                iphdr->_flags = CheckSum.ntohs((ushort)(frame.Flags == 0 ? IPFlags.IP_DF : frame.Flags));
                iphdr->_chksum = 0;

                if (options_size > 0)
                {
                    IntPtr destination_options = (IntPtr)(pinned + sizeof(ip_hdr));
                    Marshal.Copy(options_segment.Buffer, options_segment.Offset, destination_options, options_size);
                }

                if (payload_size > 0)
                {
                    Buffer.BlockCopy(payload_segment.Buffer, payload_segment.Offset, message_data, payload_offset, payload_size);
                }

                iphdr->_chksum = CheckSum.inet_chksum(pinned, payload_offset);
                if (iphdr->_chksum == 0)
                {
                    iphdr->_chksum = 0xffff;
                }
            }
            return new BufferSegment(message_data);
        }
    }
}
