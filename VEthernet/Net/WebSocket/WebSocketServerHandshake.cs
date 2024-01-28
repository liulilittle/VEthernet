namespace VEthernet.Net.WebSocket
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Net;
    using System.Net.Sockets;
    using System.Security.Cryptography;
    using System.Text;
    using VEthernet.Net.Auxiliary;

    sealed class WebSocketServerHandshake
    {
        private Socket _socket;
        private byte[] _buffer;
        private object _signal;
        private string _rawUri;
        private string _host;
        private string _origin;
        private WebHeaderCollection _headers;
        private string _secWebSocketKey;
        private string _userAgent;
        private int _secWebSocketVersion;
        private string _secWebSocketExtensions;
        private string _acceptLanguage;
        private string _acceptEncoding;

        public WebHeaderCollection Headers
        {
            get
            {
                return _headers;
            }
        }

        public string RawUri
        {
            get
            {
                return _rawUri;
            }
        }

        public string Host
        {
            get
            {
                return _host;
            }
        }

        public string Origin
        {
            get
            {
                return _origin;
            }
        }

        public string SecWebSocketExtensions
        {
            get
            {
                return _secWebSocketExtensions;
            }
        }

        public int SecWebSocketVersion
        {
            get
            {
                return _secWebSocketVersion;
            }
        }

        public string SecWebSocketKey
        {
            get
            {
                return _secWebSocketKey;
            }
        }

        public string AcceptLanguage
        {
            get
            {
                return _acceptLanguage;
            }
        }

        public string AcceptEncoding
        {
            get
            {
                return _acceptEncoding;
            }
        }

        private WebSocketServerHandshake(object signal, Socket socket)
        {
            this._headers = new WebHeaderCollection();
            this._socket = socket;
            this._signal = signal;
            this._buffer = new byte[SocketExtension.MSS];
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

        private bool FillRawUriToModel(StreamReader stream)
        {
            string path = stream.ReadLine();
            if (string.IsNullOrEmpty(path))
            {
                return false;
            }
            string[] segments = path.Split(' ');
            if (segments.Length < 3)
            {
                return false;
            }
            if (segments[2] != "HTTP/1.1")
            {
                return false;
            }
            _rawUri = segments[1];
            if (string.IsNullOrEmpty(_rawUri))
            {
                return false;
            }
            return true;
        }

        private bool FillHeaderToModel(StreamReader stream)
        {
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
            bool containsSecWebSocketKey = false;
            bool containsUpgrade = false;
            bool containsConnection = false;
            while (!stream.EndOfStream)
            {
                KeyValuePair<string, string>? pair = readkv(stream.ReadLine());
                if (pair == null)
                {
                    return false;
                }
                KeyValuePair<string, string> kv = pair.Value;
                switch (kv.Key)
                {
                    case "Sec-WebSocket-Key":
                        if (string.IsNullOrEmpty(kv.Value))
                        {
                            return false;
                        }
                        _secWebSocketKey = kv.Value;
                        containsSecWebSocketKey = true;
                        break;
                    case "Host":
                        _host = kv.Value;
                        break;
                    case "Origin":
                        if (string.IsNullOrEmpty(kv.Value))
                        {
                            return false;
                        }
                        _origin = kv.Value;
                        break;
                    case "User-Agent":
                        _userAgent = kv.Value;
                        break;
                    case "Connection":
                        if (!kv.Value.Contains("Upgrade"))
                        {
                            return false;
                        }
                        containsConnection = true;
                        break;
                    case "Upgrade":
                        if (kv.Value != "websocket")
                        {
                            return false;
                        }
                        containsUpgrade = true;
                        break;
                    case "Sec-WebSocket-Version":
                        if (!int.TryParse(kv.Value, out _secWebSocketVersion))
                        {
                            return false;
                        }
                        break;
                    case "Sec-WebSocket-Extensions":
                        _secWebSocketExtensions = kv.Value;
                        break;
                    case "Accept-Language":
                        _acceptLanguage = kv.Value;
                        break;
                    case "Accept-Encoding":
                        _acceptEncoding = kv.Value;
                        break;
                }
                _headers.Add(kv.Key, kv.Value);
            };
            return containsSecWebSocketKey && containsConnection && containsUpgrade;
        }

        private bool HandleWebSocketUpgrade(StreamReader stream)
        {
            if (!FillRawUriToModel(stream))
            {
                return false;
            }
            if (!FillHeaderToModel(stream))
            {
                return false;
            }
            return HandleUpgradeResponse();
        }

        private bool HandleUpgradeResponse()
        {
            Func<string> acceptkey = () =>
            {
                using (SHA1 sha1 = SHA1.Create())
                {
                    StringBuilder ss = new StringBuilder();
                    string key = _secWebSocketKey + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
                    byte[] hash = sha1.ComputeHash(Encoding.UTF8.GetBytes(key));
                    return Convert.ToBase64String(hash);
                }
            };
            StringBuilder headers = new StringBuilder();
            headers.Append("HTTP/1.1 101 Switching Protocols\r\n");
            headers.Append("Upgrade: websocket\r\n");
            headers.Append("Connection: Upgrade\r\n");
            headers.AppendFormat("Sec-WebSocket-Accept: {0}\r\n", acceptkey());
            headers.AppendFormat("Sec-WebSocket-Origin: {0}\r\n", _origin);
            headers.AppendFormat("Sec-WebSocket-Location: ws://{0}{1}\r\n\r\n", _host, _rawUri);
            byte[] response = Encoding.UTF8.GetBytes(headers.ToString());
            lock (_signal)
            {
                return SocketExtension.BeginSend(_socket, response, 0, response.Length, (ar) =>
                {
                    bool ok = SocketExtension.EndSend(_socket, ar);
                    if (!ok)
                    {
                        SocketExtension.Closesocket(_socket);
                    }
                });
            }
        }

        private bool Handle()
        {
            if (ReadString(3) != "GET")
            {
                return false;
            }
            return ReadAllHeaders(HandleWebSocketUpgrade);
        }

        private string ReadString(int len)
        {
            lock (_signal)
            {
                if (!_socket.Connected || SocketExtension.CleanedUp(_socket))
                {
                    return null;
                }
            }
            byte[] buffer;
            if (!SocketExtension.Receive(_socket, 3, out buffer))
            {
                return null;
            }
            if (buffer == null)
            {
                return null;
            }
            return Encoding.UTF8.GetString(buffer);
        }

        public static WebSocketServerHandshake Handshake(object signal, Socket socket)
        {
            if (signal == null || socket == null)
            {
                return null;
            }
            WebSocketServerHandshake handshake;
            lock (signal)
            {
                if (!socket.Connected || SocketExtension.CleanedUp(socket))
                {
                    return null;
                }
                handshake = new WebSocketServerHandshake(signal, socket);
            }
            if (handshake == null || !handshake.Handle())
            {
                return null;
            }
            return handshake;
        }
    }
}
