namespace VEthernet.Cryptography
{
#if NETCOREAPP
    using System.Runtime.CompilerServices;
#endif
    using global::VEthernet.Core;
    using global::VEthernet.Core.Cryptography;

    public sealed class EVP : Cipher
    {
        private readonly Encryptor _aes;

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static bool Support(string method) => Encryptor.Support(method);

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public EVP(string name, string key) : base(name, key)
        {
            this._aes = new Encryptor(name, key);
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public override BufferSegment Decrypt(byte[] buffer, int offset, int length)
        {
            BufferSegment segment = new BufferSegment(buffer, offset, length);
            return this._aes.Decrypt(segment);
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public override BufferSegment Encrypt(byte[] buffer, int offset, int length)
        {
            BufferSegment segment = new BufferSegment(buffer, offset, length);
            return this._aes.Encrypt(segment);
        }
    }
}
