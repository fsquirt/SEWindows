using System.Collections.Generic;

namespace MeasuredBootParser.Models
{
    // TCG Event Type constants
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
        };

        public static string GetName(uint eventType)
            => Names.TryGetValue(eventType, out var name) ? name : $"UNKNOWN(0x{eventType:X8})";
    }

    // TCG Algorithm IDs
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
            [0x0004] = 20,  // SHA1
            [0x000B] = 32,  // SHA256
            [0x000C] = 48,  // SHA384
            [0x000D] = 64,  // SHA512
            [0x0012] = 32,  // SM3_256
        };

        public static string GetName(ushort algId)
            => Names.TryGetValue(algId, out var name) ? name : $"ALG_0x{algId:X4}";
    }

    // A single digest entry in a Crypto Agile event
    public class DigestEntry
    {
        public ushort AlgorithmId { get; set; }
        public string AlgorithmName => TcgAlgorithmId.GetName(AlgorithmId);
        public byte[] Digest { get; set; } = [];
        public string DigestHex => Convert.ToHexString(Digest).ToLowerInvariant();
    }

    // A parsed TCG event (works for both 1.2 and 2.0)
    public class TcgEvent
    {
        public int Index { get; set; }          // Event index (0-based)
        public uint PcrIndex { get; set; }
        public uint EventType { get; set; }
        public string EventTypeName => TcgEventType.GetName(EventType);
        public List<DigestEntry> Digests { get; set; } = [];
        public byte[] EventData { get; set; } = [];
        public string EventDataHex => Convert.ToHexString(EventData).ToLowerInvariant();
        public string? EventDataString { get; set; }  // Human-readable interpretation
        public long FileOffset { get; set; }           // Byte offset in the file
    }

    // Parsed EFI Variable event data
    public class EfiVariableData
    {
        public Guid VariableGuid { get; set; }
        public string VariableName { get; set; } = "";
        public byte[] VariableData { get; set; } = [];
    }

    // Spec ID Event (first event, EV_NO_ACTION)
    public class SpecIdEvent
    {
        public bool IsTcg20 { get; set; }
        public uint SpecVersionMajor { get; set; }
        public uint SpecVersionMinor { get; set; }
        public uint SpecErrata { get; set; }
        public List<(ushort AlgId, ushort DigestSize)> AlgorithmList { get; set; } = [];
    }
}