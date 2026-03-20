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

                    case 0x80000006: // EV_EFI_GPT_EVENT
                        return DecodeGptEvent(data);

                    case 0x80000008: // EV_EFI_PLATFORM_FIRMWARE_BLOB
                        return DecodeFirmwareBlob(data);

                    case 0x80000009: // EV_EFI_HANDOFF_TABLES
                        return DecodeHandoffTables(data);

                    case 0x8000000A: // EV_EFI_PLATFORM_FIRMWARE_BLOB2
                        return DecodeFirmwareBlob2(data);

                    case 0x8000000B: // EV_EFI_HANDOFF_TABLES2
                        return DecodeHandoffTables2(data);

                    case 0x800000E1: // EV_EFI_SPDM_FIRMWARE_BLOB
                    case 0x800000E2: // EV_EFI_SPDM_FIRMWARE_CONFIG
                    case 0x800000E3: // EV_EFI_SPDM_DEVICE_POLICY
                    case 0x800000E4: // EV_EFI_SPDM_DEVICE_AUTHORITY
                        return DecodeSpdmEvent(data);

                    case 0x0000000B: // EV_TABLE_OF_DEVICES
                        return DecodeTableOfDevices(data);

                    case 0x0000000F: // EV_NONHOST_CODE
                    case 0x00000010: // EV_NONHOST_CONFIG
                    case 0x00000011: // EV_NONHOST_INFO
                        return DecodeNonHostEvent(eventType, data);

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

        // ══════════════════════════════════════════════════════════════════════
        //  新增事件解析方法
        // ══════════════════════════════════════════════════════════════════════

        /// <summary>
        /// 解析 EV_TABLE_OF_DEVICES 事件
        /// </summary>
        private static string DecodeTableOfDevices(byte[] data)
        {
            if (data.Length < 4) return $"<TABLE_OF_DEVICES len={data.Length}>";
            // NumberOfDevices (UINT32)
            uint count = BitConverter.ToUInt32(data, 0);
            if (data.Length >= 8)
            {
                // 可能包含设备描述
                var sb = new StringBuilder();
                sb.Append($"NumberOfDevices={count}");
                // 尝试读取后续的设备路径信息
                if (data.Length > 4)
                {
                    // 跳过设备数量，查找是否有设备路径数据
                    sb.Append($" DataLen={data.Length - 4}");
                }
                return sb.ToString();
            }
            return $"NumberOfDevices={count}";
        }

        /// <summary>
        /// 解析 EV_NONHOST_CODE/CONFIG/INFO 事件
        /// 使用 EFI_IMAGE_LOAD_EVENT 或 UEFI_IMAGE_LOAD_EVENT 结构
        /// </summary>
        private static string DecodeNonHostEvent(uint eventType, byte[] data)
        {
            string eventName = eventType switch
            {
                0x0000000F => "NONHOST_CODE",
                0x00000010 => "NONHOST_CONFIG",
                0x00000011 => "NONHOST_INFO",
                _ => "NONHOST_UNKNOWN"
            };

            if (data.Length < 24) return $"<{eventName} len={data.Length}>";

            // 尝试解析为 UEFI_IMAGE_LOAD_EVENT (64-bit)
            // ImageLocationInMemory (8), ImageLengthInMemory (8), ImageLinkTimeAddress (8)
            ulong imageLocation = BitConverter.ToUInt64(data, 0);
            ulong imageLength = BitConverter.ToUInt64(data, 8);
            ulong imageLinkTime = BitConverter.ToUInt64(data, 16);

            var sb = new StringBuilder();
            sb.Append(eventName);
            sb.Append($" Location=0x{imageLocation:X16}");
            sb.Append($" Length=0x{imageLength:X16}");
            sb.Append($" LinkTimeAddr=0x{imageLinkTime:X16}");

            // 如果有更多数据，可能包含设备路径
            if (data.Length > 24)
            {
                uint devicePathLen = BitConverter.ToUInt32(data, 24);
                sb.Append($" DevicePathLen={devicePathLen}");
            }

            return sb.ToString();
        }

        /// <summary>
        /// 解析 EV_EFI_PLATFORM_FIRMWARE_BLOB (旧版)
        /// 结构: BlobBase (8) + BlobLength (8)
        /// </summary>
        private static string DecodeFirmwareBlob(byte[] data)
        {
            if (data.Length < 16) return $"<FIRMWARE_BLOB len={data.Length}>";

            ulong blobBase = BitConverter.ToUInt64(data, 0);
            ulong blobLength = BitConverter.ToUInt64(data, 8);

            return $"BlobBase=0x{blobBase:X16} BlobLength=0x{blobLength:X16} ({blobLength} bytes)";
        }

        /// <summary>
        /// 解析 EV_EFI_HANDOFF_TABLES 事件
        /// 结构: NumberOfTables (4/8) + TableEntry[]
        /// </summary>
        private static string DecodeHandoffTables(byte[] data)
        {
            if (data.Length < 8) return $"<HANDOFF_TABLES len={data.Length}>";

            // 检测是 32位还是 64位
            ulong numTables;
            int offset;
            if (data.Length >= 12 && data[8] == 0 && data[9] == 0 && data[10] == 0 && data[11] == 0)
            {
                // 64-bit: NumberOfTables 是 8 字节，后跟表条目
                numTables = BitConverter.ToUInt64(data, 0);
                offset = 8;
            }
            else
            {
                // 32-bit
                numTables = BitConverter.ToUInt32(data, 0);
                offset = 4;
            }

            var sb = new StringBuilder();
            sb.Append($"NumberOfTables={numTables}");

            // 尝试解析表条目 (每个 16 字节: GUID[16] + Size[4] + Offset[4])
            if (data.Length > offset)
            {
                int tableCount = (int)Math.Min(numTables, 10); // 最多显示 10 个
                for (int i = 0; i < tableCount && offset + 16 <= data.Length; i++)
                {
                    var guid = new Guid(data[offset..(offset + 16)]);
                    uint size = BitConverter.ToUInt32(data, offset + 16);
                    uint tblOffset = BitConverter.ToUInt32(data, offset + 20);
                    sb.Append($"\n  Table[{i}]: GUID={guid} Size={size} Offset=0x{tblOffset:X8}");
                    offset += 24;
                }
            }

            return sb.ToString();
        }

        /// <summary>
        /// 解析 EV_EFI_PLATFORM_FIRMWARE_BLOB2 事件
        /// 结构: BlobDescriptionSize (1) + BlobDescription (UTF-8) + BlobBase (8) + BlobLength (8)
        /// </summary>
        private static string DecodeFirmwareBlob2(byte[] data)
        {
            if (data.Length < 10) return $"<FIRMWARE_BLOB2 len={data.Length}>";

            int nameLen = data[0];
            if (nameLen == 0 || nameLen + 9 > data.Length)
                return $"<FIRMWARE_BLOB2 invalid nameLen={nameLen}>";

            string name = "";
            try
            {
                name = Encoding.UTF8.GetString(data, 1, Math.Min(nameLen, data.Length - 1)).TrimEnd('\0');
            }
            catch { name = "<invalid>"; }

            int dataOffset = 1 + nameLen;
            if (dataOffset + 16 > data.Length)
                return $"Name={name} DataLen={data.Length - dataOffset}";

            ulong blobBase = BitConverter.ToUInt64(data, dataOffset);
            ulong blobLength = BitConverter.ToUInt64(data, dataOffset + 8);

            return $"Name=\"{name}\" BlobBase=0x{blobBase:X16} BlobLength=0x{blobLength:X16}";
        }

        /// <summary>
        /// 解析 EV_EFI_HANDOFF_TABLES2 事件
        /// 结构: TableDescriptionSize (1) + TableDescription (UTF-8) + NumberOfTables (8) + TableEntry[]
        /// </summary>
        private static string DecodeHandoffTables2(byte[] data)
        {
            if (data.Length < 9) return $"<HANDOFF_TABLES2 len={data.Length}>";

            int descLen = data[0];
            if (descLen == 0 || descLen + 8 > data.Length)
                return $"<HANDOFF_TABLES2 invalid descLen={descLen}>";

            string desc = "";
            try
            {
                desc = Encoding.UTF8.GetString(data, 1, Math.Min(descLen, data.Length - 1)).TrimEnd('\0');
            }
            catch { desc = "<invalid>"; }

            int offset = 1 + descLen;
            if (offset + 8 > data.Length)
                return $"Description=\"{desc}\" DataLen={data.Length - offset}";

            ulong numTables = BitConverter.ToUInt64(data, offset);
            var sb = new StringBuilder();
            sb.Append($"Description=\"{desc}\" NumberOfTables={numTables}");

            // 尝试解析表条目
            offset += 8;
            int tableCount = (int)Math.Min(numTables, 10);
            for (int i = 0; i < tableCount && offset + 24 <= data.Length; i++)
            {
                var guid = new Guid(data[offset..(offset + 16)]);
                uint size = BitConverter.ToUInt32(data, offset + 16);
                uint tblOffset = BitConverter.ToUInt32(data, offset + 20);
                sb.Append($"\n  Table[{i}]: GUID={guid} Size={size} Offset=0x{tblOffset:X8}");
                offset += 24;
            }

            return sb.ToString();
        }

        /// <summary>
        /// 解析 EV_EFI_GPT_EVENT 事件
        /// 结构: EFI_PARTITION_TABLE_HEADER + NumberOfPartitions + Partitions[]
        /// </summary>
        private static string DecodeGptEvent(byte[] data)
        {
            if (data.Length < 92) return $"<GPT_EVENT len={data.Length}>";

            // EFI_PARTITION_TABLE_HEADER 至少 92 字节
            // 跳过前 8 字节 (Signature = "EFI PART")
            // HeaderSize (4), HeaderRevision (4), HeaderCRC32 (4), Reserved (4)
            // MyLBA (8), AlternateLBA (8), FirstUsableLBA (8), LastUsableLBA (8)
            // DiskGUID (16), PartitionEntryLBA (8), NumberOfPartitionEntries (4), SizeOfPartitionEntry (4), PartitionEntryArrayCRC32 (4)

            try
            {
                // 验证 EFI PART 签名
                string signature = Encoding.ASCII.GetString(data, 0, 8);
                if (signature != "EFI PART")
                {
                    return $"<GPT signature=\"{signature}\">";
                }

                var sb = new StringBuilder();
                sb.Append("EFI Partition Table: ");

                // Disk GUID
                var diskGuid = new Guid(data[56..72]);
                sb.Append($"DiskGUID={diskGuid} ");

                // 从 offset 72 开始读取关键字段
                ulong firstUsableLBA = BitConverter.ToUInt64(data, 72);
                ulong lastUsableLBA = BitConverter.ToUInt64(data, 80);
                ulong partitionEntryLBA = BitConverter.ToUInt64(data, 88);

                sb.Append($"FirstLBA={firstUsableLBA} LastLBA={lastUsableLBA} ");
                sb.Append($"PartitionsLBA={partitionEntryLBA}");

                if (data.Length >= 104)
                {
                    uint numParts = BitConverter.ToUInt32(data, 96);
                    uint partSize = BitConverter.ToUInt32(data, 100);
                    sb.Append($" NumPartitions={numParts} PartSize={partSize}");
                }

                return sb.ToString();
            }
            catch
            {
                return $"<GPT_EVENT parse error len={data.Length}>";
            }
        }

        /// <summary>
        /// 解析 EV_EFI_SPDM_* 系列事件
        /// 结构: TCG_DEVICE_SECURITY_EVENT_DATA_HEADER
        /// </summary>
        private static string DecodeSpdmEvent(byte[] data)
        {
            if (data.Length < 16) return $"<SPDM_EVENT len={data.Length}>";

            try
            {
                // 查找签名
                string sig = "";
                for (int i = 0; i < Math.Min(16, data.Length); i++)
                {
                    if (data[i] >= 0x20 && data[i] < 0x7F)
                        sig += (char)data[i];
                    else
                        break;
                }

                var sb = new StringBuilder();

                // 检查是否是 "SPDM Device Sec" 或 "SPDM Device Sec2"
                if (sig.StartsWith("SPDM Device Sec"))
                {
                    sb.Append($"Signature=\"{sig.Trim()}\" ");

                    if (data.Length >= 18)
                    {
                        ushort version = BitConverter.ToUInt16(data, 16);
                        sb.Append($"Version={version} ");

                        if (data.Length >= 20)
                        {
                            byte authState = data[18];
                            // byte reserved = data[19];
                            string authStateStr = authState switch
                            {
                                0 => "SUCCESS",
                                1 => "NO_AUTH",
                                2 => "NO_BINDING",
                                3 => "FAIL_NO_SIG",
                                4 => "FAIL_INVALID",
                                0xFF => "NO_SPDM",
                                _ => $"UNKNOWN(0x{authState:X2})"
                            };
                            sb.Append($"AuthState={authStateStr} ");
                        }

                        if (data.Length >= 24)
                        {
                            uint length = BitConverter.ToUInt32(data, 20);
                            sb.Append($"TotalLength={length} ");
                        }

                        if (data.Length >= 28)
                        {
                            uint deviceType = BitConverter.ToUInt32(data, 24);
                            string deviceStr = deviceType switch
                            {
                                0 => "NULL",
                                1 => "PCI",
                                2 => "USB",
                                _ => $"UNKNOWN({deviceType})"
                            };
                            sb.Append($"DeviceType={deviceStr}");
                        }
                    }
                }
                else
                {
                    // 未知签名，显示原始十六进制
                    sb.Append($"Signature=0x{Convert.ToHexString(data, 0, Math.Min(16, data.Length))}");
                    if (data.Length > 16)
                        sb.Append($"... TotalLen={data.Length}");
                }

                return sb.ToString();
            }
            catch
            {
                return $"<SPDM_EVENT parse error len={data.Length}>";
            }
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
