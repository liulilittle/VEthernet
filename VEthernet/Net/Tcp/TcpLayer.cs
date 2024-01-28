namespace VEthernet.Net.Tcp
{
    using System;
    using System.IO;
    using System.Net;
    using System.Net.Sockets;
    using System.Runtime.InteropServices;
    using VEthernet.Core;
    using VEthernet.Net.IP;
#if NETCOREAPP
    using System.Runtime.CompilerServices;
#endif

    public unsafe static class TcpLayer
    {
        /*
         * typedef struct _tcp_hdr  
         * {  
         *     unsigned short src_port;    //源端口号   
         *     unsigned short dst_port;    //目的端口号   
         *     unsigned int seq_no;        //序列号   
         *     unsigned int ack_no;        //确认号   
         *     #if LITTLE_ENDIAN   
         *     unsigned char reserved_1:4; //保留6位中的4位首部长度   
         *     unsigned char thl:4;        //tcp头部长度   
         *     unsigned char flag:6;       //6位标志   
         *     unsigned char reseverd_2:2; //保留6位中的2位   
         *     #else   
         *     unsigned char thl:4;        //tcp头部长度   
         *     unsigned char reserved_1:4; //保留6位中的4位首部长度   
         *     unsigned char reseverd_2:2; //保留6位中的2位   
         *     unsigned char flag:6;       //6位标志    
         *     #endif   
         *     unsigned short wnd_size;    //16位窗口大小   
         *     unsigned short chk_sum;     //16位TCP检验和   
         *     unsigned short urgt_p;      //16为紧急指针   
         * }tcp_hdr;  
         */

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct tcp_hdr
        {
            public ushort src;
            public ushort dest;
            public uint seqno;
            public uint ackno;
            public ushort _hdrlen_rsvd_flags;
            public ushort wnd;
            public ushort chksum;
            public ushort urgp; // 应用层不可能出现“URGP/UGR or OPT”的协议；这类紧急协议数据报文直接RST链接即可。
        }

        private const int TCP_HLEN = 20;

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
        private static ushort TCPH_HDRLEN(tcp_hdr* phdr)
        {
            return ((ushort)(CheckSum.ntohs((phdr)->_hdrlen_rsvd_flags) >> 12));
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
        private static byte TCPH_HDRLEN_BYTES(tcp_hdr* phdr)
        {
            return ((byte)(TCPH_HDRLEN(phdr) << 2));
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
        private static byte TCPH_FLAGS(tcp_hdr* phdr)
        {
            return ((byte)((CheckSum.ntohs((phdr)->_hdrlen_rsvd_flags) & (byte)TcpFlags.TCP_FLAGS)));
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
        private static ushort TCPH_HDRLEN_SET(tcp_hdr* phdr, int len)
        {
            var u = ((len) << 12) | TCPH_FLAGS(phdr);
            return (phdr)->_hdrlen_rsvd_flags = CheckSum.htons((ushort)u);
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
        private static ushort PP_HTONS(int x)
        {
            return ((ushort)((((x) & (ushort)0x00ffU) << 8) | (((x) & (ushort)0xff00U) >> 8)));
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
        private static ushort TCPH_FLAGS_SET(tcp_hdr* phdr, int flags)
        {
            return (phdr)->_hdrlen_rsvd_flags = (ushort)(((phdr)->_hdrlen_rsvd_flags &
                PP_HTONS(~(ushort)TcpFlags.TCP_FLAGS)) | CheckSum.htons((ushort)flags));
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
        public static IPFrame ReassemblyHeader(IPFrame packet, TcpFrame frame)
        {
            BufferSegment options_data = frame.Options;
            int options_size = options_data?.Length ?? 0;
            int payload_offset = sizeof(tcp_hdr) + options_size;

            byte[] message = packet.Payload.Buffer;
            fixed (byte* pinned = &message[packet.Payload.Offset])
            {
                tcp_hdr* tcphdr = (tcp_hdr*)pinned;
                tcphdr->dest = CheckSum.htons((ushort)frame.Destination.Port);
                tcphdr->src = CheckSum.htons((ushort)frame.Source.Port);
                tcphdr->seqno = CheckSum.htonl(frame.SequenceNo);
                tcphdr->ackno = CheckSum.htonl(frame.AcknowledgeNo);
                tcphdr->urgp = CheckSum.htons(frame.UrgentPointer);
                tcphdr->wnd = CheckSum.htons(frame.WindowSize);
                tcphdr->chksum = 0;

                TCPH_HDRLEN_SET(tcphdr, payload_offset >> 2);
                TCPH_FLAGS_SET(tcphdr, (int)frame.Flags);

                ushort pseudo_checksum = CheckSum.inet_chksum_pseudo(pinned, (uint)ProtocolType.Tcp, (uint)packet.Payload.Length,
                        IPFrame.GetAddressV4(frame.Source.Address),
                        IPFrame.GetAddressV4(frame.Destination.Address));
                if (pseudo_checksum == 0)
                {
                    pseudo_checksum = 0xffff;
                }

                tcphdr->chksum = pseudo_checksum;
            }

            packet.Ttl = frame.Ttl;
            packet.Source = frame.Source.Address;
            packet.Destination = frame.Destination.Address;
            return packet;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
        public static IPFrame ToIPFrame(TcpFrame frame)
        {
            if (frame == null)
            {
                throw new ArgumentNullException(nameof(frame));
            }

            if (frame.AddressFamily != AddressFamily.InterNetwork)
            {
                throw new ArgumentNullException("TCP frames of this address family type are not supported.");
            }

            BufferSegment options_data = frame.Options;
            int options_size = options_data?.Length ?? 0;
            int payload_offset = sizeof(tcp_hdr) + options_size;
            int payload_size = frame.Payload?.Length ?? 0;

            byte[] message = new byte[payload_offset + payload_size];
            fixed (byte* pinned = message)
            {
                tcp_hdr* tcphdr = (tcp_hdr*)pinned;
                tcphdr->dest = CheckSum.htons((ushort)frame.Destination.Port);
                tcphdr->src = CheckSum.htons((ushort)frame.Source.Port);
                tcphdr->seqno = CheckSum.htonl(frame.SequenceNo);
                tcphdr->ackno = CheckSum.htonl(frame.AcknowledgeNo);
                tcphdr->urgp = CheckSum.htons(frame.UrgentPointer);
                tcphdr->wnd = CheckSum.htons(frame.WindowSize);

                TCPH_HDRLEN_SET(tcphdr, payload_offset >> 2);
                TCPH_FLAGS_SET(tcphdr, (int)frame.Flags);

                if (options_size > 0)
                {
                    IntPtr destination_options = (IntPtr)(pinned + sizeof(tcp_hdr));
                    Marshal.Copy(options_data.Buffer, options_data.Offset, destination_options, options_size);
                }

                if (payload_size > 0)
                {
                    using (MemoryStream ms = new MemoryStream(message, payload_offset, payload_size))
                    {
                        ms.Write(frame.Payload.Buffer, frame.Payload.Offset, payload_size);
                    }
                }

                ushort pseudo_checksum = CheckSum.inet_chksum_pseudo(pinned, (uint)ProtocolType.Tcp, (uint)message.Length,
                        IPFrame.GetAddressV4(frame.Source.Address),
                        IPFrame.GetAddressV4(frame.Destination.Address));
                if (pseudo_checksum == 0)
                {
                    pseudo_checksum = 0xffff;
                }

                tcphdr->chksum = pseudo_checksum;
            }

            return new IPFrame(ProtocolType.Tcp, frame.Source.Address, frame.Destination.Address, new BufferSegment(message))
            {
                Ttl = frame.Ttl,
            };
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
# endif
        public static TcpFrame ParseFrame(IPFrame ip, bool checksum = true)
        {
            if (ip == null)
            {
                return null;
            }

            TcpFrame frame = null;
            BufferSegment packet = ip.Payload;
            packet.UnsafeAddrOfPinnedArrayElement((p) =>
            {
                tcp_hdr* tcphdr = (tcp_hdr*)p;
                if (tcphdr == null)
                {
                    return;
                }

                int hdrlen_bytes = TCPH_HDRLEN_BYTES(tcphdr);
                if (hdrlen_bytes < TCP_HLEN || hdrlen_bytes > packet.Length) // 错误的数据报
                {
                    return;
                }

                int len = packet.Length - hdrlen_bytes;
                if (len < 0)
                {
                    return;
                }

                TcpFlags flags = (TcpFlags)TCPH_FLAGS(tcphdr);
                #if PACKET_CHECKSUM
                if (checksum && tcphdr->chksum != 0)
                {
                    uint pseudo_checksum = CheckSum.inet_chksum_pseudo((byte*)p.ToPointer(),
                        (uint)ProtocolType.Tcp,
                        (uint)packet.Length,
                        ip.SourceAddressV4,
                        ip.DestinationAddressV4);
                    if (pseudo_checksum != 0)
                    {
                        return;
                    }
                }
                #endif

                long payload_offset = 0;
                fixed (byte* stream = packet.Buffer)
                {
                    payload_offset = ((byte*)p + hdrlen_bytes) - stream;
                }

                BufferSegment message_data = new BufferSegment(packet.Buffer, unchecked((int)payload_offset), len);
                BufferSegment options_data = null;
                int options_size = hdrlen_bytes - sizeof(tcp_hdr);
                if (options_size < 1)
                {
                    options_data = new BufferSegment(BufferSegment.Empty);
                }
                else
                {
                    options_data = new BufferSegment(packet.Buffer,
                            packet.Offset + sizeof(tcp_hdr), options_size);
                }
                frame = new TcpFrame(new IPEndPoint(ip.Source, CheckSum.ntohs(tcphdr->src)), new IPEndPoint(ip.Destination, CheckSum.ntohs(tcphdr->dest)), message_data)
                {
                    Ttl = ip.Ttl,
                    AcknowledgeNo = CheckSum.ntohl(tcphdr->ackno),
                    SequenceNo = CheckSum.ntohl(tcphdr->seqno),
                    WindowSize = CheckSum.ntohs(tcphdr->wnd),
                    Flags = flags,
                    Options = options_data,
                    UrgentPointer = CheckSum.ntohs(tcphdr->urgp)
                };
            });
            return frame;
        }
    }
}
