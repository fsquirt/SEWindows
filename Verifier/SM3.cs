using System;
using System.Security.Cryptography;

namespace MeasuredBootParser.Verifier
{
    /// <summary>
    /// SM3 cryptographic hash algorithm (GM/T 0004-2012).
    /// Produces a 256-bit (32-byte) digest.
    /// Pure C# implementation, no external dependencies.
    /// </summary>
    public sealed class SM3 : HashAlgorithm
    {
        private readonly uint[] _v = new uint[8]; // state
        private readonly byte[] _buffer = new byte[64];
        private int _bufferOffset;
        private long _totalLength;

        private static readonly uint[] IV =
        [
            0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
            0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
        ];

        public SM3()
        {
            HashSizeValue = 256;
            Initialize();
        }

        public override void Initialize()
        {
            Array.Copy(IV, _v, 8);
            Array.Clear(_buffer);
            _bufferOffset = 0;
            _totalLength = 0;
        }

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            _totalLength += cbSize;
            int offset = ibStart;
            int remaining = cbSize;

            // Fill buffer first
            if (_bufferOffset > 0)
            {
                int fill = Math.Min(64 - _bufferOffset, remaining);
                Array.Copy(array, offset, _buffer, _bufferOffset, fill);
                _bufferOffset += fill;
                offset += fill;
                remaining -= fill;

                if (_bufferOffset == 64)
                {
                    ProcessBlock(_buffer, 0);
                    _bufferOffset = 0;
                }
            }

            // Process full blocks
            while (remaining >= 64)
            {
                ProcessBlock(array, offset);
                offset += 64;
                remaining -= 64;
            }

            // Buffer remaining
            if (remaining > 0)
            {
                Array.Copy(array, offset, _buffer, 0, remaining);
                _bufferOffset = remaining;
            }
        }

        protected override byte[] HashFinal()
        {
            // Padding
            long bitLen = _totalLength * 8;
            _buffer[_bufferOffset++] = 0x80;

            if (_bufferOffset > 56)
            {
                Array.Clear(_buffer, _bufferOffset, 64 - _bufferOffset);
                ProcessBlock(_buffer, 0);
                _bufferOffset = 0;
            }

            Array.Clear(_buffer, _bufferOffset, 56 - _bufferOffset);

            // Append length in bits (big-endian 64-bit)
            for (int i = 0; i < 8; i++)
                _buffer[56 + i] = (byte)(bitLen >> (56 - i * 8));

            ProcessBlock(_buffer, 0);

            // Output
            byte[] result = new byte[32];
            for (int i = 0; i < 8; i++)
            {
                result[i * 4] = (byte)(_v[i] >> 24);
                result[i * 4 + 1] = (byte)(_v[i] >> 16);
                result[i * 4 + 2] = (byte)(_v[i] >> 8);
                result[i * 4 + 3] = (byte)(_v[i]);
            }
            return result;
        }

        private void ProcessBlock(byte[] data, int offset)
        {
            uint[] w = new uint[68];
            uint[] wp = new uint[64];

            // Message expansion
            for (int i = 0; i < 16; i++)
                w[i] = ((uint)data[offset + i * 4] << 24) |
                       ((uint)data[offset + i * 4 + 1] << 16) |
                       ((uint)data[offset + i * 4 + 2] << 8) |
                       data[offset + i * 4 + 3];

            for (int i = 16; i < 68; i++)
                w[i] = P1(w[i - 16] ^ w[i - 9] ^ RotL(w[i - 3], 15)) ^ RotL(w[i - 13], 7) ^ w[i - 6];

            for (int i = 0; i < 64; i++)
                wp[i] = w[i] ^ w[i + 4];

            // Compression
            uint a = _v[0], b = _v[1], c = _v[2], d = _v[3];
            uint e = _v[4], f = _v[5], g = _v[6], h = _v[7];

            for (int i = 0; i < 64; i++)
            {
                uint t = i < 16 ? 0x79CC4519u : 0x7A879D8Au;
                uint ss1 = RotL(RotL(a, 12) + e + RotL(t, i), 7);
                uint ss2 = ss1 ^ RotL(a, 12);
                uint tt1 = (i < 16 ? (a ^ b ^ c) : ((a & b) | (a & c) | (b & c))) + d + ss2 + wp[i];
                uint tt2 = (i < 16 ? (e ^ f ^ g) : ((e & f) | (~e & g))) + h + ss1 + w[i];
                d = c;
                c = RotL(b, 9);
                b = a;
                a = tt1;
                h = g;
                g = RotL(f, 19);
                f = e;
                e = P0(tt2);
            }

            _v[0] ^= a; _v[1] ^= b; _v[2] ^= c; _v[3] ^= d;
            _v[4] ^= e; _v[5] ^= f; _v[6] ^= g; _v[7] ^= h;
        }

        private static uint RotL(uint x, int n) => (x << (n % 32)) | (x >> (32 - n % 32));
        private static uint P0(uint x) => x ^ RotL(x, 9) ^ RotL(x, 17);
        private static uint P1(uint x) => x ^ RotL(x, 15) ^ RotL(x, 23);
    }
}
