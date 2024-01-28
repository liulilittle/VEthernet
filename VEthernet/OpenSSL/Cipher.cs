// Copyright (c) 2006-2007 Frank Laub
// All rights reserved.

// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
// 3. The name of the author may not be used to endorse or promote products
//    derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
// OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
// IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
// NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
// THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
namespace OpenSSL
{
    using System;
#if NETCOREAPP
    using System.Runtime.CompilerServices;
#endif
    using System.Runtime.InteropServices;
    using System.Text;

    /// <summary>
    /// Wraps the EVP_CIPHER object.
    /// </summary>
    public sealed class Cipher
    {
        private readonly EVP_CIPHER raw;

#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        internal Cipher(IntPtr ptr)
        {
            if (ptr == IntPtr.Zero)
            {
                throw new ArgumentNullException(nameof(ptr));
            }
            raw = (EVP_CIPHER)Marshal.PtrToStructure(ptr, typeof(EVP_CIPHER));
            this.Handle = ptr;
#if OPENSSL_1_0
            this.KeyLength = raw.key_len;
            this.IVLength = raw.iv_len;
            this.BlockSize = raw.block_size;
            this.Flags = raw.flags;
#else
			this.KeyLength = Native.EVP_CIPHER_key_length(ptr);
			this.IVLength = Native.EVP_CIPHER_iv_length(ptr);
			this.BlockSize = Native.EVP_CIPHER_block_size(ptr);
			this.Flags = Native.EVP_CIPHER_flags(ptr);
#endif
        }

        /// <summary>
        /// Returns EVP_get_cipherbyname()
        /// </summary>
        /// <param name="name"></param>
        /// <returns></returns>
#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static Cipher CreateByName(string name)
        {
            var buf = Encoding.ASCII.GetBytes(name);
            var ptr = Native.EVP_get_cipherbyname(buf);
            if (ptr == IntPtr.Zero)
            {
                return null;
            }
            return new Cipher(ptr);
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct EVP_CIPHER
        {
            public int nid;
            public int block_size;
            public int key_len;
            public int iv_len;
            public uint flags;
            public IntPtr init;
            public IntPtr do_cipher;
            public IntPtr cleanup;
            public int ctx_size;
            public IntPtr set_asn1_parameters;
            public IntPtr get_asn1_parameters;
            public IntPtr ctrl;
            public IntPtr app_data;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct EVP_CIPHER_CTX
        {
            public IntPtr cipher;
            public IntPtr engine;   /* functional reference if 'cipher' is ENGINE-provided */
            public int encrypt;     /* encrypt or decrypt */
            public int buf_len;     /* number we have left */

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = Native.EVP_MAX_IV_LENGTH)]
            public byte[] oiv;  /* original iv */
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = Native.EVP_MAX_IV_LENGTH)]
            public byte[] iv;   /* working iv */
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = Native.EVP_MAX_BLOCK_LENGTH)]
            public byte[] buf;/* saved partial block */
            public int num;             /* used by cfb/ofb mode */

            public IntPtr app_data;     /* application stuff */
            public int key_len;     /* May change for variable length cipher */
            public uint flags;  /* Various flags */
            public IntPtr cipher_data; /* per EVP data */
            public int final_used;
            public int block_mask;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = Native.EVP_MAX_BLOCK_LENGTH)]
            public byte[] final;/* possible final block */
        }

        /// <summary>
        /// Returns the key_len field
        /// </summary>
        public int KeyLength
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            get;
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            private set;
        }

        /// <summary>
        /// Returns the iv_len field
        /// </summary>
        public int IVLength
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            get;
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            private set;
        }

        /// <summary>
        /// Returns the block_size field
        /// </summary>
        public int BlockSize
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            get;
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            private set;
        }

        /// <summary>
        /// Returns the flags field
        /// </summary>
        public uint Flags
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            get;
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            private set;
        }

        /// <summary>
        /// Returns the long name for the nid field using OBJ_nid2ln()
        /// </summary>
        public string LongName
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            get { return Native.StaticString(Native.OBJ_nid2ln(raw.nid)); }
        }

        /// <summary>
        /// Returns the name for the nid field using OBJ_nid2sn()
        /// </summary>
        public string Name
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            get { return Native.StaticString(Native.OBJ_nid2sn(raw.nid)); }
        }

        /// <summary>
        /// Returns EVP_CIPHER_type()
        /// </summary>
        public int Type
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            get { return Native.EVP_CIPHER_type(this.Handle); }
        }

        /// <summary>
        /// Returns the long name for the type using OBJ_nid2ln()
        /// </summary>
        public string TypeName
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            get { return Native.StaticString(Native.OBJ_nid2ln(Type)); }
        }

        /// <summary>
        /// Returns EVP_CIPHER*()
        /// </summary>
        public IntPtr Handle
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            get;
        }
    }
}
