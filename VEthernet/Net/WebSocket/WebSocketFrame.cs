namespace VEthernet.Net.WebSocket
{
    using System;
    using System.IO;

    //0                   1                   2                   3
    //0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //+-+-+-+-+-------+-+-------------+-------------------------------+
    //|F|R|R|R| opcode|M| Payload len |    Extended payload length    |
    //|I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
    //|N|V|V|V|       |S|             |   (if payload len==126/127)   |
    //| |1|2|3|       |K|             |                               |
    //+-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
    //|     Extended payload length continued, if payload len == 127  |
    //+ - - - - - - - - - - - - - - - +-------------------------------+
    //|                               |Masking-key, if MASK set to 1  |
    //+-------------------------------+-------------------------------+
    //| Masking-key (continued)       |          Payload Data         |
    //+-------------------------------- - - - - - - - - - - - - - - - +
    //:                     Payload Data continued ...                :
    //+ - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
    //|                     Payload Data continued ...                |
    //+---------------------------------------------------------------+
    unsafe class WebSocketFrame
    {
        public bool fin; // 1-bit
        public bool rsv1; // 1-bit
        public bool rsv2; // 1-bit
        public bool rsv3; // 1-bit
        public byte opcode; // 4-bit
        public bool masked; // 1-bit
        public long payload_length; // 7,7+16,7+64 bits
        public byte[] masking_key; // 4-bytes
        public byte[] payload_data; // n*8
        public long payload_offset; // ofs

        public long payload_surplus
        {
            get
            {
                return payload_length - payload_offset;
            }
        }

        private const int HEADERSIZE = 2;

        public static void PayloadAdditional(WebSocketFrame frame, byte* s, int len)
        {
            if (frame == null)
            {
                throw new ArgumentNullException("frame");
            }
            if (s == null)
            {
                throw new ArgumentNullException("s");
            }
            byte[] payload = frame.payload_data;
            byte[] mask = frame.masking_key;
            long ofs = frame.payload_offset;
            long count = (len + ofs);
            if (count > frame.payload_length)
            {
                count = frame.payload_length;
            }
            if (ofs < count)
            {
                for (long i = ofs; i < count; i++)
                {
                    if (!frame.masked)
                    {
                        payload[i] = *s++;
                    }
                    else
                    {
                        payload[i] = (byte)(*s++ ^ mask[i % 4]);
                    }
                }
            }
            frame.payload_offset = (count > frame.payload_length ? frame.payload_length : count);
        }

        public static WebSocketFrame Unpack(byte[] buffer, int ofs, int len)
        {
            if (buffer == null)
            {
                return default(WebSocketFrame);
            }
            fixed (byte* pinned = &buffer[ofs])
            {
                return Unpack(pinned, len);
            }
        }

        public static WebSocketFrame Unpack(byte* s, int len)
        {
            if (s == null || len < HEADERSIZE)
            {
                return default(WebSocketFrame);
            }
            WebSocketFrame frame = new WebSocketFrame();
            frame.fin = ((*s >> 7) & 0x01) == 1;
            frame.rsv1 = ((*s >> 6) & 0x01) == 1;
            frame.rsv2 = ((*s >> 5) & 0x01) == 1;
            frame.rsv3 = ((*s >> 4) & 0x01) == 1;
            frame.opcode = (byte)(0x0F & *s);
            frame.masked = (s[1] >> 7) == 0x01;
            frame.payload_length = (s[1] & 0x7F);
            s += 2;
            len -= 2;
            if (frame.payload_length == 0x7E)
            {
                // If 126, the following 2 bytes interpreted as a 16-bit unsigned integer are the payload length
                if (len < HEADERSIZE + 2)
                {
                    return null;
                }
                frame.payload_length = 
                    *s++ << 0x08 | 
                    *s++ & 0xFF;
                len -= 2;
            }
            else if (frame.payload_length == 0x7F)
            {
                // If 127, the following 8 bytes interpreted as a 64-bit unsigned integer (the most significant bit MUST be 0) are the payload length
                if (len < HEADERSIZE + 8)
                {
                    return null;
                }
                frame.payload_length = 
                    *s++ << 0x38 |
                    *s++ << 0x30 |
                    *s++ << 0x28 |
                    *s++ << 0x20 |
                    *s++ << 0x18 |
                    *s++ << 0x10 |
                    *s++ << 0x08 |
                    *s++ & 0xFF;
                len -= 8;
            }
            byte[] mask = new byte[4];
            if (frame.masked)
            {
                mask[0] = s[0];
                mask[1] = s[1];
                mask[2] = s[2];
                mask[3] = s[3];
                s += 4;
                len -= 4;
                frame.masking_key = mask;
            }
            frame.payload_data = new byte[frame.payload_length];
            PayloadAdditional(frame, s, len);
            return frame;
        }

        private static byte[] PackFrameHeader(WebSocketFrame frame)
        {
            if (frame == null || frame.payload_length < 0)
            {
                return null;
            }
            long h1 = (frame.opcode & 0x0F);
            long h2 = 0x00;
            if (frame.fin)
            {
                h1 |= (0x01 << 7);
            }
            if (frame.rsv1)
            {
                h1 |= (0x01 << 6);
            }
            if (frame.rsv2)
            {
                h1 |= (0x01 << 5);
            }
            if (frame.rsv3)
            {
                h1 |= (0x01 << 4);
            }
            if (frame.masked)
            {
                h2 |= (0x01 << 7);
            }
            if (0 <= frame.payload_length && frame.payload_length <= 0x7D)
            {
                h2 |= frame.payload_length;
            }
            else if (frame.payload_length <= 0xFFFF)
            {
                h2 |= 0x7E;
            }
            else
            {
                h2 |= 0x7F;
            }
            return new byte[] { (byte)h1, (byte)h2 };
        }

        public static MemoryStream Pack(WebSocketFrame frame)
        {
            byte[] header = PackFrameHeader(frame);
            if (header == null)
            {
                return null;
            }
            MemoryStream ms = new MemoryStream();
            ms.Write(header, 0, 2);
            int len = (header[1] & 0x7F);
            byte[] buffer = null;
            if (len == 0x7E)
            {
                buffer = new byte[2];
                fixed (long* pinned = &frame.payload_length)
                {
                    byte* s = (byte*)pinned;
                    buffer[1] = *s++;
                    buffer[0] = *s++;
                }
            }
            else if (len == 0x7F)
            {
                buffer = new byte[8];
                fixed (long* pinned = &frame.payload_length)
                {
                    byte* s = (byte*)pinned;
                    buffer[7] = *s++;
                    buffer[6] = *s++;
                    buffer[5] = *s++;
                    buffer[4] = *s++;
                    buffer[3] = *s++;
                    buffer[2] = *s++;
                    buffer[1] = *s++;
                    buffer[0] = *s++;
                }
            }
            if (buffer != null)
            {
                ms.Write(buffer, 0, buffer.Length);
            }
            byte[] mask = null;
            if (frame.masked)
            {
                var rand = new global::VEthernet.Utilits.Random();
                mask = new byte[4];
                for (int i = 0; i < 4; i++)
                {
                    mask[i] = (byte)rand.Next(0x00, 0xFF);
                }
                frame.masking_key = mask;
                ms.Write(mask, 0, 4);
            }
            byte[] payload = frame.payload_data;
            if (frame.masked)
            {
                long i = frame.payload_offset;
                long l = i + frame.payload_length;
                for (; i < l; i++)
                {
                    payload[i] ^= mask[i % 4];
                }
            }
            ms.Write(payload, Convert.ToInt32(frame.payload_offset), payload.Length);
            return ms;
        }
    }
}
