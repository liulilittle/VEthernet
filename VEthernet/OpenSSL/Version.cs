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

    using System.Text;
#if NETCOREAPP
    using System.Runtime.CompilerServices;
#endif

namespace OpenSSL
{
    /// <summary>
    /// Contains the set of elements that make up a Version.
    /// </summary>
    public sealed class Version
    {
        /// <summary>
        /// The kinds of status that 
        /// </summary>
        public enum StatusType
        {
            /// <summary>
            /// The status nibble has the value 0
            /// </summary>
            Development,

            /// <summary>
            /// The status nibble is 1 to 14 (0x0e)
            /// </summary>
            Beta,

            /// <summary>
            /// The status nibble is 0x0f
            /// </summary>
            Release,
        }

        /// <summary>
        /// Returns the current version of the native library.
        /// </summary>
        public static Version Library
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            get
            {
#if OPENSSL_1_0
                return new Version(Native.SSLeay());
#else
                return new Version(Native.OpenSSL_version_num());
#endif
            }
        }

        /// <summary>
        /// Create a Version from a raw uint value
        /// </summary>
        /// <param name="raw"></param>
#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public Version(uint raw)
        {
            this.Raw = raw;
        }

        /// <summary>
        /// Major portion of the Version.
        /// </summary>
        public uint Major
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            get { return (Raw & 0xf0000000) >> 28; }
        }

        /// <summary>
        /// Minor portion of the Version.
        /// </summary>
        public uint Minor
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            get { return (Raw & 0x0ff00000) >> 20; }
        }

        /// <summary>
        /// Fix portion of the Version.
        /// </summary>
        public uint Fix
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            get { return (Raw & 0x000ff000) >> 12; }
        }

        /// <summary>
        /// Patch portion of the Version. These should start at 'a' and continue to 'z'.
        /// </summary>
        public char? Patch
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            get
            {
                var patch = (Raw & 0x00000ff0) >> 4;
                if (patch == 0)
                    return null;

                var a = Encoding.ASCII.GetBytes("a")[0];
                var x = a + (patch - 1);
                var ch = Encoding.ASCII.GetString(new[] { (byte)x })[0];

                return ch;
            }
        }

        /// <summary>
        /// Status portion of the Version.
        /// </summary>
        public StatusType Status
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            get
            {
                var status = RawStatus;

                if (status == 0)
                    return StatusType.Development;
                else if (status == 0xf)
                    return StatusType.Release;
                else
                    return StatusType.Beta;
            }
        }

        /// <summary>
        /// The raw uint value.
        /// </summary>
        public uint Raw
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            get;
        }

        /// <summary>
        /// Returns the raw status portion of a Version.
        /// </summary>
        public uint RawStatus
        {
#if NETCOREAPP
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            get { return Raw & 0x0000000f; }
        }

        /// <summary>
        /// Conversion to a string.
        /// </summary>
        /// <returns></returns>
#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public override string ToString()
        {
            return string.Format("{0}.{1}.{2}{3} {4} (0x{5:x8})",
                Major,
                Minor,
                Fix,
                Patch,
                Status,
                Raw);
        }

        /// <summary>
        /// SSLEAY_* constants used for with GetVersion()
        /// </summary>
        public enum Format
        {
            /// <summary>
            /// SSLEAY_VERSION
            /// </summary>
            Text = 0,
            /// <summary>
            /// SSLEAY_CFLAGS
            /// </summary>
            CompilerFlags = 2,
            /// <summary>
            /// SSLEAY_BUILT_ON
            /// </summary>
            BuildDate = 3,
            /// <summary>
            /// SSLEAY_PLATFORM
            /// </summary>
            Platform = 4,
            /// <summary>
            /// SSLEAY_DIR
            /// </summary>
            BuildDirectory = 5,
        }

        /// <summary>
        /// Calls SSLeay_version()
        /// </summary>
        /// <param name="format"></param>
#if NETCOREAPP
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static string GetText(Format format)
        {
            return Native.StaticString(Native.SSLeay_version((int)format));
        }
    }
}
