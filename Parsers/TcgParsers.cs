using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using MeasuredBootParser.Models;

namespace MeasuredBootParser.Parsers
{
    // ══════════════════════════════════════════════════════════════════════
    //  EventLogParser  —  格式探测 + 分发入口
    // ══════════════════════════════════════════════════════════════════════
    public static class EventLogParser
    {
        private static readonly byte[] Tcg2Signature =
            Encoding.ASCII.GetBytes("Spec ID Event03\0");

        public static TcgEventLog Parse(string filePath)
            => Parse(File.ReadAllBytes(filePath), filePath);

        public static TcgEventLog Parse(byte[] data, string sourceName)
        {
            if (data.Length < 32)
                throw new InvalidDataException("File too small to be a valid TCG Event Log.");

            using var ms = new MemoryStream(data);
            using var br = new BinaryReader(ms);

            var log = new TcgEventLog
            {
                FilePath = sourceName,
                FileSize = data.Length,
                IsCryptoAgile = DetectFormat(data)
            };

            if (log.IsCryptoAgile)
                new Tcg20Parser().Parse(br, log);
            else
                new Tcg12Parser().Parse(br, log);

            return log;
        }

        private static bool DetectFormat(byte[] data)
        {
            try
            {
                using var ms = new MemoryStream(data);
                using var br = new BinaryReader(ms);

                br.ReadUInt32();                       // pcrIndex
                uint eventType = br.ReadUInt32();
                br.ReadBytes(20);                      // SHA1 (zeroed in 2.0)
                uint eventSize = br.ReadUInt32();

                if (eventType == 0x00000003 && eventSize >= 16)
                {
                    byte[] eventData = br.ReadBytes((int)eventSize);
                    if (eventData.Length >= 16)
                    {
                        var sig = new byte[16];
                        Array.Copy(eventData, sig, 16);
                        if (StructuralEquals(sig, Tcg2Signature)) return true;
                    }
                }
            }
            catch { /* fall through */ }
            return false;
        }

        private static bool StructuralEquals(byte[] a, byte[] b)
        {
            if (a.Length != b.Length) return false;
            for (int i = 0; i < a.Length; i++)
                if (a[i] != b[i]) return false;
            return true;
        }
    }

    // ══════════════════════════════════════════════════════════════════════
    //  Tcg12Parser  —  TCG 1.2 SHA-1-only 格式
    // ══════════════════════════════════════════════════════════════════════
    public class Tcg12Parser
    {
        public void Parse(BinaryReader br, TcgEventLog log)
        {
            log.IsCryptoAgile = false;
            int index = 0;

            while (br.BaseStream.Position < br.BaseStream.Length - 8)
            {
                long offset = br.BaseStream.Position;
                TcgEvent evt;
                try { evt = ReadEvent(br, index, offset); }
                catch (EndOfStreamException) { break; }

                log.Events.Add(evt);
                index++;
            }
        }

        private static TcgEvent ReadEvent(BinaryReader br, int index, long offset)
        {
            uint pcrIndex = br.ReadUInt32();
            uint eventType = br.ReadUInt32();
            byte[] sha1 = br.ReadBytes(20);
            uint eventSize = br.ReadUInt32();
            byte[] eventData = br.ReadBytes((int)eventSize);

            return new TcgEvent
            {
                Index = index,
                PcrIndex = pcrIndex,
                EventType = eventType,
                FileOffset = offset,
                Digests = [new DigestEntry { AlgorithmId = 0x0004, Digest = sha1 }],
                EventData = eventData,
                EventDataString = TryDecodeEventData(eventType, eventData),
            };
        }

        // 供 Tcg20Parser 复用
        internal static string? TryDecodeEventData(uint eventType, byte[] data)
        {
            if (data == null || data.Length == 0) return null;
            try
            {
                switch (eventType)
                {
                    case 0x00000005: // EV_ACTION
                    case 0x00000008: // EV_S_CRTM_VERSION
                    case 0x80000007: // EV_EFI_ACTION
                        return CleanString(Encoding.Unicode.GetString(data).TrimEnd('\0'));

                    case 0x80000001: // EV_EFI_VARIABLE_DRIVER_CONFIG
                    case 0x80000002: // EV_EFI_VARIABLE_BOOT
                    case 0x800000E0: // EV_EFI_VARIABLE_AUTHORITY
                        return DecodeEfiVariable(data);

                    default:
                        bool isAscii = true;
                        foreach (var b in data)
                            if (b != 0 && (b < 0x20 || b > 0x7E)) { isAscii = false; break; }
                        if (isAscii) return Encoding.ASCII.GetString(data).TrimEnd('\0');
                        return null;
                }
            }
            catch { return null; }
        }

        private static string DecodeEfiVariable(byte[] data)
        {
            if (data.Length < 28) return "<EFI_VARIABLE too short>";
            var guid = new Guid(
                BitConverter.ToUInt32(data, 0),
                BitConverter.ToUInt16(data, 4),
                BitConverter.ToUInt16(data, 6),
                data[8], data[9], data[10], data[11],
                data[12], data[13], data[14], data[15]);
            ulong nameLen = BitConverter.ToUInt64(data, 16);
            ulong dataLen = BitConverter.ToUInt64(data, 24);
            string name = "";
            if (nameLen > 0 && 32 + (long)nameLen * 2 <= data.Length)
                name = Encoding.Unicode.GetString(data, 32, (int)nameLen * 2).TrimEnd('\0');
            return $"GUID={guid} Name={name} DataLen={dataLen}";
        }

        private static string CleanString(string s)
        {
            var sb = new StringBuilder();
            foreach (char c in s)
                if (c >= 0x20 && c < 0xFFFD) sb.Append(c);
            return sb.ToString().Trim();
        }
    }

    // ══════════════════════════════════════════════════════════════════════
    //  Tcg20Parser  —  TCG 2.0 Crypto-Agile 格式
    // ══════════════════════════════════════════════════════════════════════
    public class Tcg20Parser
    {
        private List<(ushort AlgId, int DigestSize)> _algorithms = [];

        public void Parse(BinaryReader br, TcgEventLog log)
        {
            log.IsCryptoAgile = true;

            // ── Event 0: TCG 1.2-style header (SpecIdEvent) ──
            long offset0 = br.BaseStream.Position;
            uint pcrIdx0 = br.ReadUInt32();
            uint evType0 = br.ReadUInt32();
            byte[] sha1_0 = br.ReadBytes(20);
            uint evSize0 = br.ReadUInt32();
            byte[] evData0 = br.ReadBytes((int)evSize0);

            var specId = ParseSpecIdEvent(evData0);
            log.SpecId = specId;
            log.Events.Add(new TcgEvent
            {
                Index = 0,
                PcrIndex = pcrIdx0,
                EventType = evType0,
                FileOffset = offset0,
                Digests = [new DigestEntry { AlgorithmId = 0x0004, Digest = sha1_0 }],
                EventData = evData0,
                EventDataString = FormatSpecIdEvent(specId),
            });

            // ── Remaining events: Crypto Agile ──
            int index = 1;
            while (br.BaseStream.Position < br.BaseStream.Length - 8)
            {
                long offset = br.BaseStream.Position;
                TcgEvent evt;
                try { evt = ReadEvent20(br, index, offset); }
                catch (EndOfStreamException) { break; }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"  [!] Parse error at offset 0x{offset:X}: {ex.Message}");
                    break;
                }
                log.Events.Add(evt);
                index++;
            }
        }

        private TcgEvent ReadEvent20(BinaryReader br, int index, long offset)
        {
            uint pcrIndex = br.ReadUInt32();
            uint eventType = br.ReadUInt32();
            uint digestCount = br.ReadUInt32();
            var digests = new List<DigestEntry>();

            for (uint i = 0; i < digestCount; i++)
            {
                ushort algId = br.ReadUInt16();
                int size = GetDigestSize(algId);
                byte[] digest = br.ReadBytes(size);
                digests.Add(new DigestEntry { AlgorithmId = algId, Digest = digest });
            }

            uint eventSize = br.ReadUInt32();
            byte[] eventData = br.ReadBytes((int)eventSize);

            return new TcgEvent
            {
                Index = index,
                PcrIndex = pcrIndex,
                EventType = eventType,
                FileOffset = offset,
                Digests = digests,
                EventData = eventData,
                EventDataString = Tcg12Parser.TryDecodeEventData(eventType, eventData),
            };
        }

        private SpecIdEvent ParseSpecIdEvent(byte[] data)
        {
            var specId = new SpecIdEvent { IsTcg20 = true };
            if (data.Length < 24) return specId;

            int pos = 16; // skip "Spec ID Event03\0"
            pos += 4;     // platformClass
            specId.SpecVersionMinor = data[pos++];
            specId.SpecVersionMajor = data[pos++];
            specId.SpecErrata = data[pos++];
            pos++;         // uintnSize
            uint numAlgs = BitConverter.ToUInt32(data, pos); pos += 4;

            for (uint i = 0; i < numAlgs && pos + 4 <= data.Length; i++)
            {
                ushort algId = BitConverter.ToUInt16(data, pos); pos += 2;
                ushort digSize = BitConverter.ToUInt16(data, pos); pos += 2;
                specId.AlgorithmList.Add((algId, digSize));
                _algorithms.Add((algId, digSize));
            }
            return specId;
        }

        private static string FormatSpecIdEvent(SpecIdEvent s)
        {
            var algs = string.Join(", ", s.AlgorithmList.ConvertAll(
                a => $"{TcgAlgorithmId.GetName(a.AlgId)}({a.DigestSize * 8}bit)"));
            return $"TCG Spec {s.SpecVersionMajor}.{s.SpecVersionMinor} Errata={s.SpecErrata} Algorithms=[{algs}]";
        }

        private int GetDigestSize(ushort algId)
        {
            foreach (var (id, size) in _algorithms)
                if (id == algId) return size;
            if (TcgAlgorithmId.DigestSizes.TryGetValue(algId, out var s)) return s;
            throw new InvalidDataException($"Unknown algorithm ID 0x{algId:X4}");
        }
    }
}
