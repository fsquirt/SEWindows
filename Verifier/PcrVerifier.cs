using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using MeasuredBootParser.Models;

namespace MeasuredBootParser.Verifier
{
    // ══════════════════════════════════════════════════════════════════════
    //  PcrReplayer  —  从事件日志重放所有 PCR 值
    // ══════════════════════════════════════════════════════════════════════
    public static class PcrReplayer
    {
        /// <summary>
        /// 对日志中所有事件重新执行 extend 操作，返回各 PCR 的期望终值。
        /// 结果键：[算法ID][PCR编号] = 摘要字节
        /// </summary>
        public static Dictionary<ushort, Dictionary<uint, byte[]>> Replay(TcgEventLog log)
        {
            var banks = new Dictionary<ushort, Dictionary<uint, byte[]>>();

            // ── 1. 初始化 PCR banks（全零） ──
            if (log.IsCryptoAgile && log.SpecId != null)
                foreach (var (algId, _) in log.SpecId.AlgorithmList)
                    banks[algId] = new Dictionary<uint, byte[]>();
            else
                banks[0x0004] = new Dictionary<uint, byte[]>();

            // ── 2. 检测 StartupLocality ──
            byte startupLocality = DetectStartupLocality(log);
            if (startupLocality != 0)
            {
                foreach (var (algId, bank) in banks)
                {
                    int digestSize = TcgAlgorithmId.DigestSizes.TryGetValue(algId, out var s) ? s :
                                     log.SpecId?.AlgorithmList.FirstOrDefault(a => a.AlgId == algId).DigestSize ?? 32;
                    var seed = new byte[digestSize];
                    seed[digestSize - 1] = startupLocality;
                    bank[0] = seed;
                }
                Console.WriteLine($"  [i] Startup Locality = {startupLocality}: PCR0 seeded with 0x...0{startupLocality:X2}");
            }

            // ── 3. 逐事件 extend ──
            foreach (var evt in log.Events)
            {
                if (evt.EventType == 0x00000003) continue;  // EV_NO_ACTION 不参与 extend
                if (evt.PcrIndex == 0xFFFFFFFF) continue;

                foreach (var digest in evt.Digests)
                {
                    if (!banks.TryGetValue(digest.AlgorithmId, out var bank)) continue;
                    if (!bank.TryGetValue(evt.PcrIndex, out var current))
                        current = new byte[digest.Digest.Length];
                    bank[evt.PcrIndex] = Extend(digest.AlgorithmId, current, digest.Digest);
                }
            }

            return banks;
        }

        private static byte DetectStartupLocality(TcgEventLog log)
        {
            var sig = System.Text.Encoding.ASCII.GetBytes("StartupLocality\0");
            foreach (var evt in log.Events)
            {
                if (evt.EventType != 0x00000003) continue;
                if (evt.EventData == null || evt.EventData.Length < 17) continue;
                bool match = true;
                for (int i = 0; i < 16; i++)
                    if (evt.EventData[i] != sig[i]) { match = false; break; }
                if (match) return evt.EventData[16];
            }
            return 0;
        }

        private static byte[] Extend(ushort algId, byte[] pcr, byte[] digest)
        {
            var combined = new byte[pcr.Length + digest.Length];
            pcr.CopyTo(combined, 0);
            digest.CopyTo(combined, pcr.Length);
            using var hash = CreateHash(algId);
            return hash.ComputeHash(combined);
        }

        private static HashAlgorithm CreateHash(ushort algId) => algId switch
        {
            0x0004 => SHA1.Create(),
            0x000B => SHA256.Create(),
            0x000C => SHA384.Create(),
            0x000D => SHA512.Create(),
            0x0012 => new SM3(),
            _ => SHA256.Create(),
        };
    }

    // ══════════════════════════════════════════════════════════════════════
    //  SM3  —  GM/T 0004-2012 国密哈希算法，纯 C# 实现
    // ══════════════════════════════════════════════════════════════════════
    public sealed class SM3 : HashAlgorithm
    {
        private readonly uint[] _v = new uint[8];
        private readonly byte[] _buffer = new byte[64];
        private int _bufferOffset;
        private long _totalLength;

        private static readonly uint[] IV =
        [
            0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
            0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
        ];

        public SM3() { HashSizeValue = 256; Initialize(); }

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
            int offset = ibStart, remaining = cbSize;

            if (_bufferOffset > 0)
            {
                int fill = Math.Min(64 - _bufferOffset, remaining);
                Array.Copy(array, offset, _buffer, _bufferOffset, fill);
                _bufferOffset += fill; offset += fill; remaining -= fill;
                if (_bufferOffset == 64) { ProcessBlock(_buffer, 0); _bufferOffset = 0; }
            }

            while (remaining >= 64)
            {
                ProcessBlock(array, offset);
                offset += 64; remaining -= 64;
            }

            if (remaining > 0)
            {
                Array.Copy(array, offset, _buffer, 0, remaining);
                _bufferOffset = remaining;
            }
        }

        protected override byte[] HashFinal()
        {
            long bitLen = _totalLength * 8;
            _buffer[_bufferOffset++] = 0x80;
            if (_bufferOffset > 56)
            {
                Array.Clear(_buffer, _bufferOffset, 64 - _bufferOffset);
                ProcessBlock(_buffer, 0);
                _bufferOffset = 0;
            }
            Array.Clear(_buffer, _bufferOffset, 56 - _bufferOffset);
            for (int i = 0; i < 8; i++)
                _buffer[56 + i] = (byte)(bitLen >> (56 - i * 8));
            ProcessBlock(_buffer, 0);

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

            for (int i = 0; i < 16; i++)
                w[i] = ((uint)data[offset + i * 4] << 24) |
                       ((uint)data[offset + i * 4 + 1] << 16) |
                       ((uint)data[offset + i * 4 + 2] << 8) |
                       data[offset + i * 4 + 3];

            for (int i = 16; i < 68; i++)
                w[i] = P1(w[i - 16] ^ w[i - 9] ^ RotL(w[i - 3], 15)) ^ RotL(w[i - 13], 7) ^ w[i - 6];

            for (int i = 0; i < 64; i++)
                wp[i] = w[i] ^ w[i + 4];

            uint a = _v[0], b = _v[1], c = _v[2], d = _v[3];
            uint e = _v[4], f = _v[5], g = _v[6], h = _v[7];

            for (int i = 0; i < 64; i++)
            {
                uint t = i < 16 ? 0x79CC4519u : 0x7A879D8Au;
                uint ss1 = RotL(RotL(a, 12) + e + RotL(t, i), 7);
                uint ss2 = ss1 ^ RotL(a, 12);
                uint tt1 = (i < 16 ? (a ^ b ^ c) : ((a & b) | (a & c) | (b & c))) + d + ss2 + wp[i];
                uint tt2 = (i < 16 ? (e ^ f ^ g) : ((e & f) | (~e & g))) + h + ss1 + w[i];
                d = c; c = RotL(b, 9); b = a; a = tt1;
                h = g; g = RotL(f, 19); f = e; e = P0(tt2);
            }

            _v[0] ^= a; _v[1] ^= b; _v[2] ^= c; _v[3] ^= d;
            _v[4] ^= e; _v[5] ^= f; _v[6] ^= g; _v[7] ^= h;
        }

        private static uint RotL(uint x, int n) => (x << (n % 32)) | (x >> (32 - n % 32));
        private static uint P0(uint x) => x ^ RotL(x, 9) ^ RotL(x, 17);
        private static uint P1(uint x) => x ^ RotL(x, 15) ^ RotL(x, 23);
    }
}
