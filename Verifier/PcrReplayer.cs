using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using MeasuredBootParser.Models;

namespace MeasuredBootParser.Verifier
{
    public class PcrReplayResult
    {
        public ushort AlgorithmId { get; set; }
        public uint PcrIndex { get; set; }
        public byte[] ReplayedValue { get; set; } = [];
        public string ReplayedHex => Convert.ToHexString(ReplayedValue).ToLowerInvariant();
    }

    public static class PcrReplayer
    {
        /// <summary>
        /// Replays all PCR values from the event log by re-extending each event's digests.
        /// Returns the replayed PCR final values, keyed by [algId][pcrIndex].
        /// </summary>
        public static Dictionary<ushort, Dictionary<uint, byte[]>> Replay(TcgEventLog log)
        {
            var banks = new Dictionary<ushort, Dictionary<uint, byte[]>>();

            // ── 1. 初始化 PCR banks（全零） ──
            if (log.IsCryptoAgile && log.SpecId != null)
                foreach (var (algId, digestSize) in log.SpecId.AlgorithmList)
                    banks[algId] = new Dictionary<uint, byte[]>();
            else
                banks[0x0004] = new Dictionary<uint, byte[]>();

            // ── 2. 检测 StartupLocality（从 EV_NO_ACTION 事件里找） ──
            byte startupLocality = DetectStartupLocality(log);

            // ── 3. 如果 Locality != 0，PCR0 初始值不是全零 ──
            if (startupLocality != 0)
            {
                foreach (var (algId, bank) in banks)
                {
                    int digestSize = TcgAlgorithmId.DigestSizes.TryGetValue(algId, out var s) ? s :
                                     log.SpecId?.AlgorithmList.FirstOrDefault(a => a.AlgId == algId).DigestSize ?? 32;
                    var seed = new byte[digestSize];
                    // TCG spec: PCR0 init value for non-zero locality = 0x00..00 || locality byte
                    seed[digestSize - 1] = startupLocality;
                    bank[0] = seed;
                }
                Console.WriteLine($"  [i] Startup Locality = {startupLocality}: PCR0 seeded with 0x...0{startupLocality:X2}");
            }

            // ── 4. Replay 所有事件 ──
            foreach (var evt in log.Events)
            {
                if (evt.EventType == 0x00000003) continue;  // EV_NO_ACTION
                if (evt.PcrIndex == 0xFFFFFFFF) continue;   // WBCL marker

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

        // StartupLocality 藏在某个 EV_NO_ACTION 的 EventData 里
        // Signature = "StartupLocality\0" (16 bytes) + 1 byte locality
        private static byte DetectStartupLocality(TcgEventLog log)
        {
            var sig = System.Text.Encoding.ASCII.GetBytes("StartupLocality\0");  // 16 bytes
            foreach (var evt in log.Events)
            {
                if (evt.EventType != 0x00000003) continue;
                if (evt.EventData == null || evt.EventData.Length < 17) continue;

                bool match = true;
                for (int i = 0; i < 16; i++)
                    if (evt.EventData[i] != sig[i]) { match = false; break; }

                if (match)
                    return evt.EventData[16];
            }
            return 0;  // 默认 Locality 0
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
            0x0012 => new SM3(),     // SM3_256
            _ => SHA256.Create(),
        };
    }
}