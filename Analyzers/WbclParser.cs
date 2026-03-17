using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using MeasuredBootParser.Models;

namespace MeasuredBootParser.Analyzers
{
    public class WbclTaggedEvent
    {
        public uint EventId { get; set; }
        public string EventName => WbclEventIds.GetName(EventId);
        public uint EventSize { get; set; }
        public byte[] EventData { get; set; } = [];
        public string? InterpretedValue { get; set; }
        public int SourceEventIndex { get; set; }  // 对应 TcgEvent.Index
        public uint SourcePcr { get; set; }
    }

    public static class WbclEventIds
    {
        private static readonly Dictionary<uint, string> Names = new()
        {
            [0x00040001] = "SIPAEVENT_BOOTREVOCATIONLIST",
            [0x00040002] = "SIPAEVENT_OSKERNELDEBUG",
            [0x00040003] = "SIPAEVENT_CODEINTEGRITY",
            [0x00040004] = "SIPAEVENT_BOOTDEBUGGING",
            [0x00060001] = "SIPAEVENT_TRANSFER_CONTROL",
            [0x00070001] = "SIPAEVENT_PREOSPARAMETER",
            [0x00080001] = "SIPAEVENT_HYPERVISOR_LAUNCH_TYPE",
            [0x00090001] = "SIPAEVENT_IOMMU_DMA_PROTECTION",
            [0x000A0001] = "SIPAEVENT_PLATFORM_FIRMWARE_BLOB",
            [0x000C0001] = "SIPAEVENT_BITLOCKER_UNLOCK",
            [0x000E0001] = "SIPAEVENT_LOADEDMODULE_AGGREGATION",
            [0x000F0001] = "SIPAEVENT_EVENT_AGGREGATION",
            [0x00100001] = "SIPAEVENT_HYPERCALL",
            [0x00110001] = "SIPAEVENT_HVCI_POLICY",
            [0x00120001] = "SIPAEVENT_VIRTUALIZATION_BASED_SECURITY",
            [0x00130001] = "SIPAEVENT_VBS_VSM_REQUIRED",
            [0x00140001] = "SIPAEVENT_VBS_SECUREBOOT_REQUIRED",
            [0x00150001] = "SIPAEVENT_VBS_IOMMU_REQUIRED",
            [0x00160001] = "SIPAEVENT_VBS_NX_PROTECTIONS_REQUIRED",
            [0x00170001] = "SIPAEVENT_VBS_SMM_SECURITY_REQUIRED",
            [0x00180001] = "SIPAEVENT_VBS_SYSTEM_INTEGRITY_POLICY",
            [0x00190001] = "SIPAEVENT_VSM_IDK_ENABLED",
            [0x001A0001] = "SIPAEVENT_OSDEVICE_AGGREGATION",
            [0x001B0001] = "SIPAEVENT_VBS_MSR_FILTER_REQUIRED",
            [0x40010001] = "SIPAEVENT_EVENT_AGGREGATION_V2", // Windows 11
        };
        public static string GetName(uint id) =>
            Names.TryGetValue(id, out var n) ? n : $"SIPAEVENT_UNKNOWN(0x{id:X8})";
    }

    public static class WbclParser
    {
        public static List<WbclTaggedEvent> ParseAll(TcgEventLog log)
        {
            var results = new List<WbclTaggedEvent>();

            foreach (var evt in log.Events)
            {
                // EV_EVENT_TAG (0x06) in PCR 11-14 are WBCL tagged events
                if (evt.EventType != 0x00000006) continue;
                if (evt.PcrIndex < 11 || evt.PcrIndex > 14) continue;

                var tagged = ParseTaggedEvents(evt.EventData, evt.Index, evt.PcrIndex);
                results.AddRange(tagged);
            }

            // Ensure that nested tags inside SIPAEVENT_EVENT_AGGREGATION (0x40010001) are included
            var expanded = new List<WbclTaggedEvent>();
            foreach (var r in results)
            {
                expanded.Add(r);
                if (r.EventId == 0x40010001 || r.EventId == 0x000F0001)
                {
                    var nested = ParseTaggedEvents(r.EventData, r.SourceEventIndex, r.SourcePcr);
                    expanded.AddRange(nested);
                }
            }

            return expanded;
        }

        private static List<WbclTaggedEvent> ParseTaggedEvents(
            byte[] data, int sourceIndex, uint sourcePcr)
        {
            var list = new List<WbclTaggedEvent>();
            if (data == null || data.Length < 8) return list;

            using var ms = new MemoryStream(data);
            using var br = new BinaryReader(ms);

            while (ms.Position + 8 <= ms.Length)
            {
                uint eventId = br.ReadUInt32();
                uint eventSize = br.ReadUInt32();

                if (ms.Position + eventSize > ms.Length) break;
                byte[] eventData = br.ReadBytes((int)eventSize);

                var tag = new WbclTaggedEvent
                {
                    EventId = eventId,
                    EventSize = eventSize,
                    EventData = eventData,
                    SourceEventIndex = sourceIndex,
                    SourcePcr = sourcePcr,
                    InterpretedValue = InterpretEvent(eventId, eventData),
                };
                list.Add(tag);
            }

            return list;
        }

        private static string? InterpretEvent(uint eventId, byte[] data)
        {
            try
            {
                switch (eventId)
                {
                    // ── Boolean flags (1 byte: 0=false, 1=true) ──
                    case 0x00040002: // OSKERNELDEBUG
                    case 0x00040003: // CODEINTEGRITY
                    case 0x00040004: // BOOTDEBUGGING
                        if (data.Length >= 1)
                            return data[0] == 0 ? "Disabled/Not set" : "Enabled/Set";
                        break;

                    // ── IOMMU DMA Protection ──
                    case 0x00090001: // SIPAEVENT_IOMMU_DMA_PROTECTION
                        if (data.Length >= 4)
                        {
                            uint flags = BitConverter.ToUInt32(data, 0);
                            // Bit definitions from Windows internals:
                            // Bit 0: DMA protection active
                            // Bit 1: Pre-boot DMA protection
                            // Bit 2: OS-initiated DMA protection
                            var parts = new List<string>();
                            if ((flags & 0x01) != 0) parts.Add("DMAProtectionActive");
                            if ((flags & 0x02) != 0) parts.Add("PreBootDMAProtection");
                            if ((flags & 0x04) != 0) parts.Add("OSDMAProtection");
                            if ((flags & 0x08) != 0) parts.Add("IOMMUPresent");
                            if ((flags & 0x10) != 0) parts.Add("DriverExclusionList");
                            string flagStr = parts.Count > 0 ? string.Join(" | ", parts) : "None";
                            return $"0x{flags:X8} [{flagStr}]";
                        }
                        else if (data.Length >= 1)
                        {
                            return data[0] == 0 ? "DMA Protection: Disabled/Inactive"
                                                 : "DMA Protection: Active";
                        }
                        break;

                    // ── Hypervisor Launch Type ──
                    case 0x00080001: // SIPAEVENT_HYPERVISOR_LAUNCH_TYPE
                        if (data.Length >= 4)
                        {
                            uint launchType = BitConverter.ToUInt32(data, 0);
                            return launchType switch
                            {
                                0 => "NotLaunched",
                                1 => "Launched (Hyper-V active)",
                                2 => "LaunchedWithVirtualization",
                                _ => $"Unknown(0x{launchType:X8})"
                            };
                        }
                        break;

                    // ── VBS (Virtualization Based Security) ──
                    case 0x00120001: // SIPAEVENT_VIRTUALIZATION_BASED_SECURITY
                        if (data.Length >= 4)
                        {
                            uint vbsFlags = BitConverter.ToUInt32(data, 0);
                            var parts = new List<string>();
                            if ((vbsFlags & 0x01) != 0) parts.Add("Enabled");
                            if ((vbsFlags & 0x02) != 0) parts.Add("Required");
                            if ((vbsFlags & 0x04) != 0) parts.Add("HVCIEnabled");
                            return parts.Count > 0 ? string.Join(" | ", parts) : $"0x{vbsFlags:X8}";
                        }
                        break;

                    // ── VBS IOMMU Required ──
                    case 0x00150001: // SIPAEVENT_VBS_IOMMU_REQUIRED
                        if (data.Length >= 1)
                            return data[0] == 0 ? "IOMMU not required by VBS" : "IOMMU required by VBS";
                        break;

                    // ── Code Integrity / HVCI policy ──
                    case 0x00110001: // SIPAEVENT_HVCI_POLICY
                        if (data.Length >= 4)
                        {
                            uint policy = BitConverter.ToUInt32(data, 0);
                            var parts = new List<string>();
                            if ((policy & 0x01) != 0) parts.Add("HVCIEnabled");
                            if ((policy & 0x02) != 0) parts.Add("HVCIStrictMode");
                            if ((policy & 0x04) != 0) parts.Add("HVCIDebug");
                            return parts.Count > 0 ? string.Join(" | ", parts) : $"0x{policy:X8}";
                        }
                        break;

                    // ── Transfer Control (boot loader handoff) ──
                    case 0x00060001:
                        if (data.Length >= 16)
                        {
                            // GUID identifying the component receiving control
                            var guid = new Guid(
                                BitConverter.ToUInt32(data, 0),
                                BitConverter.ToUInt16(data, 4),
                                BitConverter.ToUInt16(data, 6),
                                data[8], data[9], data[10], data[11],
                                data[12], data[13], data[14], data[15]);
                            return $"HandoffTo={guid}";
                        }
                        break;

                    // ── String types ──
                    case 0x000A0001: // PLATFORM_FIRMWARE_BLOB
                        if (data.Length > 0)
                        {
                            int nullPos = Array.IndexOf(data, (byte)0);
                            int len = nullPos >= 0 ? nullPos : data.Length;
                            return Encoding.UTF8.GetString(data, 0, Math.Min(len, 64));
                        }
                        break;
                }
            }
            catch { /* ignore parse errors in individual events */ }

            // Fallback: hex dump (first 16 bytes)
            if (data.Length == 0) return "(empty)";
            int dumpLen = Math.Min(data.Length, 16);
            return $"0x{Convert.ToHexString(data, 0, dumpLen)}{(data.Length > 16 ? "..." : "")}";
        }
    }
}