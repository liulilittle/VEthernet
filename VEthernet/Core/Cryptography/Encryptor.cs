namespace VEthernet.Core.Cryptography
{
    using System;
    using System.Runtime.InteropServices;
    using System.Security.Cryptography;
    using System.Text;
#if NETCOREAPP
    using System.Runtime.CompilerServices;
#endif
    using OpenSSL;

    public unsafe sealed class Encryptor : IDisposable
    {
        private readonly string _method = string.Empty;
        private readonly string _password = string.Empty;
        private byte[] _key = BufferSegment.Empty;
        private Cipher _cipher = null;
        private IntPtr _encryptCTX = IntPtr.Zero;
        private IntPtr _decryptCTX = IntPtr.Zero;
        private byte[] iv = null;
        private readonly object _encryptlockObj = new object();
        private readonly object _decryptlockObj = new object();

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static bool Support(string method)
        {
            if (string.IsNullOrEmpty(method))
            {
                return false;
            }
            var buf = Encoding.ASCII.GetBytes(method);
            var ptr = Native.EVP_get_cipherbyname(buf);
            return ptr != IntPtr.Zero;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public Encryptor(string method, string password)
        {
            this._encryptCTX = IntPtr.Zero;
            this._decryptCTX = IntPtr.Zero;
            this._method = method;
            this._password = password;
            this.initKey(method, password);
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        ~Encryptor() => this.Dispose();

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public void Dispose()
        {
            lock (this._encryptlockObj)
            {
                lock (this._decryptlockObj)
                {
                    this._cipher = null;
                    this._key = null;
                    this.iv = null;
                    if (this._encryptCTX != IntPtr.Zero)
                    {
                        Native.OPENSSL_EVP_CIPHER_CTX_cleanup(this._encryptCTX);
                        Native.OPENSSL_EVP_CIPHER_CTX_free(this._encryptCTX);
                        this._encryptCTX = IntPtr.Zero;
                    }
                    if (this._decryptCTX != IntPtr.Zero)
                    {
                        Native.OPENSSL_EVP_CIPHER_CTX_cleanup(this._decryptCTX);
                        Native.OPENSSL_EVP_CIPHER_CTX_free(this._decryptCTX);
                        this._decryptCTX = IntPtr.Zero;
                    }
                }
            }
            GC.SuppressFinalize(this);
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        private bool initCipher(ref IntPtr context, byte[] iv, bool isCipher)
        {
            int enc = isCipher ? 1 : 0;
            if (context == IntPtr.Zero)
            {
                context = Native.OPENSSL_EVP_CIPHER_CTX_new();
                Native.OPENSSL_EVP_CIPHER_CTX_init(context);
                Native.ExpectSuccess(Native.EVP_CipherInit_ex(context, this._cipher.Handle, IntPtr.Zero, null, null, enc));
                Native.ExpectSuccess(Native.EVP_CIPHER_CTX_set_key_length(context, _key.Length));
                Native.ExpectSuccess(Native.EVP_CIPHER_CTX_set_padding(context, 1));
            }
            try
            {
                int err = Native.ExpectSuccess(Native.
                    EVP_CipherInit_ex(context, this._cipher.Handle, IntPtr.Zero, _key, iv, enc));
                return err > 0;
            }
            catch (OpenSslException)
            {
                context = IntPtr.Zero;
                return false;
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        private void initKey(string method, string password)
        {
            _cipher = Cipher.CreateByName(method);
            if (_cipher == null)
            {
                throw new ArgumentOutOfRangeException("Such encryption cipher methods are not supported");
            }

            byte[] passbuf = Encoding.Default.GetBytes(password);
            _key = new byte[_cipher.KeyLength];

            iv = new byte[_cipher.IVLength];
            if (Native.EVP_BytesToKey(_cipher.Handle, Native.EVP_md5(), null, passbuf, passbuf.Length, 1, _key, iv) < 1)
            {
                throw new ExternalException("Bytes to key calculations cannot be performed using cipher with md5(md) key password iv key etc");
            }

            int ivLen = _cipher.IVLength;
            iv = new byte[ivLen]; // RAND_bytes(iv.get(), ivLen); = new byte[ivLen]; // RAND_bytes(iv.get(), ivLen);

            // MD5->RC4
            Buffer.BlockCopy(Hash<MD5>.
                ComputeHash(
                    merges(
                        Encoding.Default.GetBytes($"Ppp@{method}."),
                        _key,
                        Encoding.Default.GetBytes($".{password}"))), 0, iv, 0, ivLen);
            fixed (byte* piv = iv)
            fixed (byte* pkey = _key)
            {
                Rc4.rc4_crypt(pkey, _cipher.KeyLength, piv, ivLen, 0, 0);
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        private static byte[] merges(params byte[][] s)
        {
            if (s == null || s.Length < 1)
            {
                return BufferSegment.Empty;
            }
            byte[] a = BufferSegment.Empty;
            foreach (byte[] i in s)
            {
                a = merge(a, i);
            }
            return a;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        private static byte[] merge(byte[] a, byte[] b)
        {
            int al = a?.Length ?? 0;
            int bl = b?.Length ?? 0;
            int rl = al + bl;
            if (rl < 1)
            {
                return BufferSegment.Empty;
            }
            byte[] r = new byte[rl];
            Buffer.BlockCopy(a, 0, r, 0, al);
            Buffer.BlockCopy(b, 0, r, al, bl);
            return r;
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public BufferSegment Encrypt(BufferSegment data)
        {
            if (data == null || data.Length < 1)
            {
                return new BufferSegment(BufferSegment.Empty);
            }
            lock (this._encryptlockObj)
            {
                if (this._cipher == null)
                {
                    return new BufferSegment(BufferSegment.Empty);
                }
                int outLen = data.Length + this._cipher.BlockSize;
                byte[] cipherText = new byte[outLen];
                fixed (byte* buf = &data.Buffer[data.Offset])
                {
                    bool b = true;
                    try
                    {
                        // INIT-CTX
                        b = initCipher(ref _encryptCTX, iv, true);
                        if (b)
                        {
                            b = Native.EVP_CipherUpdate(_encryptCTX, cipherText, out outLen, buf, data.Length) < 1;
                        }
                    }
                    catch { }
                    if (b)
                    {
                        return new BufferSegment(BufferSegment.Empty);
                    }
                }
                return new BufferSegment(cipherText, outLen);
            }
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public BufferSegment Decrypt(BufferSegment data)
        {
            if (data == null || data.Length < 1)
            {
                return new BufferSegment(BufferSegment.Empty);
            }
            lock (this._decryptlockObj)
            {
                if (this._cipher == null)
                {
                    return new BufferSegment(BufferSegment.Empty);
                }
                int outLen = data.Length + this._cipher.BlockSize;
                byte[] cipherText = new byte[outLen];
                fixed (byte* buf = &data.Buffer[data.Offset])
                {
                    bool b = true;
                    try
                    {
                        // INIT-CTX
                        b = initCipher(ref _decryptCTX, iv, false);
                        if (b)
                        {
                            b = Native.EVP_CipherUpdate(_decryptCTX, cipherText, out outLen, buf, data.Length) < 1;
                        }
                    }
                    catch { }
                    if (b)
                    {
                        return new BufferSegment(BufferSegment.Empty);
                    }
                }
                return new BufferSegment(cipherText, outLen);
            }
        }
    }
}
