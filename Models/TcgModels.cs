using System;
using System.Collections.Generic;

namespace MeasuredBootParser.Models
{
    // ══════════════════════════════════════════════════════════════════════
    //  TCG Event Type 常量表
    // ══════════════════════════════════════════════════════════════════════
    public static class TcgEventType
    {
        public static readonly Dictionary<uint, string> Names = new()
        {
            [0x00000000] = "EV_PREBOOT_CERT",
            [0x00000001] = "EV_POST_CODE",
            [0x00000002] = "EV_UNUSED",
            [0x00000003] = "EV_NO_ACTION",
            [0x00000004] = "EV_SEPARATOR",
            [0x00000005] = "EV_ACTION",
            [0x00000006] = "EV_EVENT_TAG",
            [0x00000007] = "EV_S_CRTM_CONTENTS",
            [0x00000008] = "EV_S_CRTM_VERSION",
            [0x00000009] = "EV_CPU_MICROCODE",
            [0x0000000A] = "EV_PLATFORM_CONFIG_FLAGS",
            [0x0000000B] = "EV_TABLE_OF_DEVICES",
            [0x0000000C] = "EV_COMPACT_HASH",
            [0x0000000D] = "EV_IPL",
            [0x0000000E] = "EV_IPL_PARTITION_DATA",
            [0x0000000F] = "EV_NONHOST_CODE",
            [0x00000010] = "EV_NONHOST_CONFIG",
            [0x00000011] = "EV_NONHOST_INFO",
            [0x00000012] = "EV_OMIT_BOOT_DEVICE_EVENTS",
            // EFI events
            [0x80000001] = "EV_EFI_VARIABLE_DRIVER_CONFIG",
            [0x80000002] = "EV_EFI_VARIABLE_BOOT",
            [0x80000003] = "EV_EFI_BOOT_SERVICES_APPLICATION",
            [0x80000004] = "EV_EFI_BOOT_SERVICES_DRIVER",
            [0x80000005] = "EV_EFI_RUNTIME_SERVICES_DRIVER",
            [0x80000006] = "EV_EFI_GPT_EVENT",
            [0x80000007] = "EV_EFI_ACTION",
            [0x80000008] = "EV_EFI_PLATFORM_FIRMWARE_BLOB",
            [0x80000009] = "EV_EFI_HANDOFF_TABLES",
            [0x8000000A] = "EV_EFI_PLATFORM_FIRMWARE_BLOB2",
            [0x8000000B] = "EV_EFI_HANDOFF_TABLES2",
            [0x8000000C] = "EV_EFI_VARIABLE_BOOT2",
            [0x80000010] = "EV_EFI_HCRTM_EVENT",
            [0x800000E0] = "EV_EFI_VARIABLE_AUTHORITY",
            [0x800000E1] = "EV_EFI_SPDM_FIRMWARE_BLOB",
            [0x800000E2] = "EV_EFI_SPDM_FIRMWARE_CONFIG",
            [0x800000E3] = "EV_EFI_SPDM_DEVICE_POLICY",
            [0x800000E4] = "EV_EFI_SPDM_DEVICE_AUTHORITY",
        };

        public static string GetName(uint eventType)
            => Names.TryGetValue(eventType, out var name) ? name : $"UNKNOWN(0x{eventType:X8})";
    }

    // ══════════════════════════════════════════════════════════════════════
    //  TCG Algorithm ID 常量表
    // ══════════════════════════════════════════════════════════════════════
    public static class TcgAlgorithmId
    {
        public static readonly Dictionary<ushort, string> Names = new()
        {
            [0x0004] = "SHA1",
            [0x000B] = "SHA256",
            [0x000C] = "SHA384",
            [0x000D] = "SHA512",
            [0x0012] = "SM3_256",
        };

        public static readonly Dictionary<ushort, int> DigestSizes = new()
        {
            [0x0004] = 20,   // SHA1
            [0x000B] = 32,   // SHA256
            [0x000C] = 48,   // SHA384
            [0x000D] = 64,   // SHA512
            [0x0012] = 32,   // SM3_256
        };

        public static string GetName(ushort algId)
            => Names.TryGetValue(algId, out var name) ? name : $"ALG_0x{algId:X4}";
    }

    // ══════════════════════════════════════════════════════════════════════
    //  单条摘要（Crypto Agile 格式里的一个算法槽）
    // ══════════════════════════════════════════════════════════════════════
    public class DigestEntry
    {
        public ushort AlgorithmId { get; set; }
        public string AlgorithmName => TcgAlgorithmId.GetName(AlgorithmId);
        public byte[] Digest { get; set; } = [];
        public string DigestHex => Convert.ToHexString(Digest).ToLowerInvariant();
    }

    // ══════════════════════════════════════════════════════════════════════
    //  单条 TCG 事件（TCG 1.2 和 2.0 通用）
    // ══════════════════════════════════════════════════════════════════════
    public class TcgEvent
    {
        public int Index { get; set; }
        public uint PcrIndex { get; set; }
        public uint EventType { get; set; }
        public string EventTypeName => TcgEventType.GetName(EventType);
        public List<DigestEntry> Digests { get; set; } = [];
        public byte[] EventData { get; set; } = [];
        public string EventDataHex => Convert.ToHexString(EventData).ToLowerInvariant();
        public string? EventDataString { get; set; }
        public long FileOffset { get; set; }
    }

    // ══════════════════════════════════════════════════════════════════════
    //  解析后的 EFI Variable 事件数据
    // ══════════════════════════════════════════════════════════════════════
    public class EfiVariableData
    {
        public Guid VariableGuid { get; set; }
        public string VariableName { get; set; } = "";
        public byte[] VariableData { get; set; } = [];
    }

    // ══════════════════════════════════════════════════════════════════════
    //  Spec ID Event（第一条事件，EV_NO_ACTION）
    // ══════════════════════════════════════════════════════════════════════
    public class SpecIdEvent
    {
        public bool IsTcg20 { get; set; }
        public uint SpecVersionMajor { get; set; }
        public uint SpecVersionMinor { get; set; }
        public uint SpecErrata { get; set; }
        public List<(ushort AlgId, ushort DigestSize)> AlgorithmList { get; set; } = [];
    }

    // ══════════════════════════════════════════════════════════════════════
    //  整个 TCG 事件日志
    // ══════════════════════════════════════════════════════════════════════
    public class TcgEventLog
    {
        public bool IsCryptoAgile { get; set; }
        public SpecIdEvent? SpecId { get; set; }
        public List<TcgEvent> Events { get; set; } = [];
        public Dictionary<ushort, Dictionary<uint, byte[]>> PcrBanks { get; set; } = [];
        public string FilePath { get; set; } = "";
        public long FileSize { get; set; }
    }
}
