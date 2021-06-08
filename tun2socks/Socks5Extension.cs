namespace tun2socks
{
    using System;
    using System.IO;
    using System.Net;
    using System.Net.Sockets;
    using System.Runtime.InteropServices;
    using System.Text;
    using VEthernet.Net.Auxiliary;

    public unsafe static class Socks5Extension
    {
        public static NetworkAddress ResolveEP(byte[] buffer, int* offset, int len)
        {
            /*
                +----+------+------+----------+----------+----------+
                | RSV | FRAG | ATYP | DST.ADDR | DST.PORT | DATA |
                +----+------+------+----------+----------+----------+
                | 2 | 1 | 1 | Variable | 2 | Variable |
                +----+------+------+----------+----------+----------+
            */
            NetworkAddress remoteEP = null;
            *offset = -1;
            if (len < 4)
            {
                return null;
            }
            fixed (byte* pinned = buffer)
            {
                byte atype = pinned[3];
                switch (atype)
                {
                    case 0x01: // IPv4
                        *offset = 8;
                        if (len < *offset)
                        {
                            *offset = -1;
                            return null;
                        }
                        buffer = new byte[4];
                        Marshal.Copy((IntPtr)(pinned + 4), buffer, 0, 4);
                        remoteEP = new NetworkAddress
                        {
                            Type = atype,
                            Host = buffer,
                            Udp = true
                        };
                        break;
                    case 0x03: // 域名
                        *offset = 5;
                        if (len < *offset)
                        {
                            *offset = -1;
                            return null;
                        }
                        int size = pinned[4];
                        if (size > 0)
                        {
                            *offset += size;
                            buffer = new byte[size];
                            Marshal.Copy((IntPtr)(pinned + 5), buffer, 0, size);
                            remoteEP = new NetworkAddress
                            {
                                Type = atype,
                                Host = Encoding.ASCII.GetString(buffer),
                                Udp = true
                            };
                        }
                        break;
                    case 0x04: // IPv6
                        *offset = 20;
                        if (len < *offset)
                        {
                            *offset = -1;
                            return null;
                        }
                        buffer = new byte[16];
                        Marshal.Copy((IntPtr)(pinned + 4), buffer, 0, 16);
                        remoteEP = new NetworkAddress
                        {
                            Type = atype,
                            Host = buffer,
                            Udp = true
                        };
                        break;
                };
                if (*offset >= 0)
                {
                    byte* port = (pinned + *offset);
                    *offset += 2;
                    if (len < *offset)
                    {
                        *offset = -1;
                        return null;
                    }
                    remoteEP.Port = (port[0] << 8) | (port[1] & 0xff);
                }
            }
            return remoteEP;
        }

        public static bool SendTo(Socket s, byte[] buffer, int ofs, int len, EndPoint localEP, NetworkAddress address)
        {
            using (MemoryStream ms = new MemoryStream())
            {
                using (BinaryWriter bw = new BinaryWriter(ms))
                {
                    /*
                        | RSV | FRAG | ATYP | DST.ADDR | DST.PORT | DATA |
                        +----+------+------+----------+----------+----------+
                        | 2 | 1 | 1 | Variable | 2 | Variable |
                        +----+------+------+----------+----------+----------+
                    */
                    bw.Write((ushort)0x00); // RSV
                    bw.Write((byte)0x00); // FRAG
                    bw.Write((byte)address.Type);
                    if (address.Type == 0x01 || address.Type == 0x04)
                    {
                        bw.Write((byte[])address.Host);
                    }
                    else
                    {
                        string hostname = (address.Host ?? string.Empty).ToString();
                        byte[] hostbytes = Encoding.ASCII.GetBytes(hostname);
                        bw.Write((byte)hostbytes.Length);
                        bw.Write(hostbytes);
                    }
                    bw.Write(new byte[] { (byte)(address.Port >> 8), (byte)address.Port }); // DST.PORT
                    bw.Write(buffer, ofs, len); // DATA

                    byte[] message = ms.GetBuffer();
                    return SocketExtension.BeginSendTo(s, message, 0, (int)ms.Position, localEP, (ar) => SocketExtension.EndSendTo(s, ar));
                }
            }
        }

        public static bool SendTo(Socket s, byte[] buffer, int ofs, int len, EndPoint localEP, IPEndPoint remoteEP)
        {
            NetworkAddress address = new NetworkAddress();
            address.Host = remoteEP.Address.GetAddressBytes();
            address.Port = remoteEP.Port;
            address.Udp = true;
            address.Type = (byte)(remoteEP.AddressFamily == AddressFamily.InterNetwork ? 0x01 : 0x04);
            return Socks5Extension.SendTo(s, buffer, ofs, len, localEP, address);
        }
    }
}
