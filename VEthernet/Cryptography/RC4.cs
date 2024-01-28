namespace VEthernet.Cryptography
{
#if NETCOREAPP
    using System.Runtime.CompilerServices;
#endif
    using global::VEthernet.Core;
    using global::VEthernet.Cryptography.Standard;

    public sealed class RC4<T> : Cipher where T : System.Security.Cryptography.HashAlgorithm
    {
        private readonly Rc4 _rc4;

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public RC4(string name, string key) : base(name, key)
        {
            this._rc4 = new Rc4(key, Rc4.SBox(Hash<T>.ToString(key)));
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public override BufferSegment Decrypt(byte[] buffer, int offset, int length)
        {
            return this._rc4.Decrypt(buffer, offset, length);
        }

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public override BufferSegment Encrypt(byte[] buffer, int offset, int length)
        {
            return this._rc4.Encrypt(buffer, offset, length);
        }
    }
}
