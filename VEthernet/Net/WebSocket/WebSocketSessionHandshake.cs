namespace VEthernet.Net.WebSocket
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Net.Sockets;
    using System.Security.Cryptography;
    using System.Text;
    using VEthernet.Net.Auxiliary;

    sealed class WebSocketSessionHandshake
    {
        private readonly object _signal;
        private readonly Socket _socket;
        private readonly Uri _uri;
        private readonly string _secWebSocketKey;
        private readonly byte[] _buffer;

        private WebSocketSessionHandshake(object signal, Socket socket, Uri uri)
        {
            this._signal = signal;
            this._socket = socket;
            this._uri = uri;
            this._secWebSocketKey = GeneratedSecWebSocketKey();
            this._buffer = new byte[SocketExtension.MSS];
        }

        private string GeneratedSecWebSocketKey()
        {
            byte[] buffer = new byte[32];
            var rand = new global::VEthernet.Utilits.Random();
            for (int i = 0; i < 32; i++)
            {
                buffer[i] = (byte)rand.Next(0x00, 0xFF);
            }
            return Convert.ToBase64String(buffer);
        }

        private bool SendUpgradeRequest()
        {
            lock (_signal)
            {
                if (!_socket.Connected || SocketExtension.CleanedUp(_socket))
                {
                    return false;
                }
            }
            StringBuilder sb = new StringBuilder();
            sb.AppendFormat("GET {0} HTTP/1.1\r\n", _uri.AbsolutePath);

            sb.AppendFormat("Host: {0}:{1}\r\n", _uri.Host, _uri.Port);
            sb.Append("Connection: Upgrade\r\n");
            sb.Append("Pragma: no-cache\r\n");
            sb.Append("Cache-Control: no-cache\r\n");
            sb.Append("Upgrade: websocket\r\n");
            sb.Append("Origin: null\r\n");

            sb.Append("Accept-Encoding: gzip, deflate, br\r\n");
            sb.Append("Accept-Language: zh-CN,zh;q=0.9\r\n");
            sb.Append("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36\r\n");

            sb.AppendFormat("Sec-WebSocket-Key: {0}\r\n", _secWebSocketKey);
            sb.Append("Sec-WebSocket-Origin: null\r\n");
            sb.Append("Sec-WebSocket-Version: 13\r\n");
            sb.Append("Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n\r\n");

            byte[] request = Encoding.UTF8.GetBytes(sb.ToString());
            if (!SocketExtension.BeginSend(_socket, request, 0, request.Length, (ar) =>
            {
                bool ok = SocketExtension.EndSend(_socket, ar);
                if (!ok)
                {
                    SocketExtension.Closesocket(_socket);
                }
            }))
            {
                return false;
            }
            return true;
        }

        private bool ReceiveUpgradeResponse()
        {
            return ReadAllHeaders((s) =>
            {
                if (s.EndOfStream)
                {
                    return false;
                }
                if (s.ReadLine() != "HTTP/1.1 101 Switching Protocols")
                {
                    return false;
                }
                Func<string, KeyValuePair<string, string>?> readkv = (line) =>
                {
                    if (string.IsNullOrEmpty(line))
                    {
                        return null;
                    }
                    int i = line.IndexOf(':');
                    if (i < 0)
                    {
                        return null;
                    }
                    string key = line.Substring(0, i++);
                    if (i >= line.Length)
                    {
                        return null;
                    }
                    if (line[i] == ' ')
                    {
                        i++;
                    }
                    if (i >= line.Length)
                    {
                        return null;
                    }
                    string value = line.Substring(i);
                    return new KeyValuePair<string, string>(key, value);
                };
                Func<string, bool> checkacceptkey = (acceptkey) =>
                {
                    using (SHA1 sha1 = SHA1.Create())
                    {
                        StringBuilder ss = new StringBuilder();
                        byte[] hash = sha1.ComputeHash(Encoding.UTF8.GetBytes(_secWebSocketKey + 
                            "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"));
                        return Convert.ToBase64String(hash) == acceptkey;
                    }
                };
                bool containsSecWebSocketLocation = false;
                while (!s.EndOfStream)
                {
                    KeyValuePair<string, string>? pair = readkv(s.ReadLine());
                    if (pair == null)
                    {
                        return false;
                    }
                    KeyValuePair<string, string> kv = pair.Value;
                    switch (kv.Key)
                    {
                        case "Connection":
                            if (kv.Value != "Upgrade")
                            {
                                return false;
                            }
                            break;
                        case "Upgrade":
                            if (kv.Value != "websocket")
                            {
                                return false;
                            }
                            break;
                        case "Sec-WebSocket-Location":
                            containsSecWebSocketLocation = true;
                            break;
                        case "Sec-WebSocket-Accept":
                            if (string.IsNullOrEmpty(kv.Value) || !checkacceptkey(kv.Value))
                            {
                                return false;
                            }
                            break;
                    }
                }
                return containsSecWebSocketLocation; 
            });
        }

        private bool Handle()
        {
            if (!SendUpgradeRequest())
            {
                return false;
            }
            if (!ReceiveUpgradeResponse())
            {
                return false;
            }
            return true;
        }

        private int Receive(int len)
        {
            return Receive(0, len);
        }

        private int Receive(int ofs, int len)
        {
            try
            {
                lock (_signal)
                {
                    if (!_socket.Connected || SocketExtension.CleanedUp(_socket))
                    {
                        return 0;
                    }
                }
                return _socket.Receive(_buffer, ofs, len, SocketFlags.None);
            }
            catch
            {
                return 0;
            }
        }

        private bool ReadAllHeaders(Func<StreamReader, bool> reader)
        {
            using (MemoryStream ms = new MemoryStream())
            {
                while (true)
                {
                    int len = Receive(SocketExtension.MSS);
                    if (len < 1)
                    {
                        return false;
                    }
                    ms.Write(_buffer, 0, len);
                    if (!(len >= SocketExtension.MSS && _socket.Available > 0))
                    {
                        break;
                    }
                }
                if (ms.Length < 1)
                {
                    return false;
                }
                ms.Seek(-4, SeekOrigin.End);
                if (!(ms.ReadByte() == '\r' &&
                    ms.ReadByte() == '\n' &&
                    ms.ReadByte() == '\r' &&
                    ms.ReadByte() == '\n'))
                {
                    return false;
                }
                ms.Seek(0, SeekOrigin.Begin);
                ms.SetLength(ms.Length - 4);
                using (StreamReader sr = new StreamReader(ms, Encoding.UTF8))
                {
                    return reader(sr);
                }
            }
        }

        public static WebSocketSessionHandshake Handshake(object signal, Socket socket, Uri uri)
        {
            if (signal == null || socket == null || uri == null)
            {
                return null;
            }
            WebSocketSessionHandshake handshake;
            lock (signal)
            {
                if (!socket.Connected || SocketExtension.CleanedUp(socket))
                {
                    return null;
                }
                handshake = new WebSocketSessionHandshake(signal, socket, uri);
            }
            if (handshake == null || !handshake.Handle())
            {
                return null;
            }
            return handshake;
        }
    }
}
