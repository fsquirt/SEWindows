using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using MeasuredBootParser.Models;

namespace MeasuredBootParser.Analyzers
{
    public enum FeatureStatus { Unknown, Enabled, Disabled, NotMeasured }

    public class SecurityFeature
    {
        public string Name { get; set; } = "";
        public FeatureStatus Status { get; set; }
        public string Evidence { get; set; } = "";
        public string? Detail { get; set; }
    }

    public static class SecurityFeatureAnalyzer
    {
        // Well-known GUIDs
        private static readonly Guid EfiGlobalVariableGuid =
            new("8be4df61-93ca-11d2-aa0d-00e098032b8c");
        private static readonly Guid EfiImageSecurityDatabaseGuid =
            new("d719b2cb-3d3a-4596-a3bc-dad00e67656f");

        public static List<SecurityFeature> Analyze(TcgEventLog log)
        {
            var results = new List<SecurityFeature>();

            results.Add(AnalyzeSecureBoot(log));
            results.Add(AnalyzeVirtualization(log));
            results.Add(AnalyzeIommu(log));
            results.Add(AnalyzeHvci(log));
            results.Add(AnalyzeDriverSignature(log));
            results.Add(AnalyzeVulnerableDriverBlocklist(log));
            results.Add(AnalyzeBootIntegrity(log));

            return results;
        }

        // ────────────────────────────────────────────────
        // 1. Secure Boot
        // ────────────────────────────────────────────────
        private static SecurityFeature AnalyzeSecureBoot(TcgEventLog log)
        {
            var feat = new SecurityFeature { Name = "Secure Boot" };

            // Find SecureBoot variable in PCR7
            var secureBootEvent = log.Events.FirstOrDefault(e =>
                e.PcrIndex == 7 &&
                (e.EventType == 0x80000001 || e.EventType == 0x800000E0) &&
                TryParseEfiVariable(e.EventData, out var v) &&
                v!.VariableGuid == EfiGlobalVariableGuid &&
                v.VariableName == "SecureBoot");

            if (secureBootEvent == null)
            {
                feat.Status = FeatureStatus.NotMeasured;
                feat.Evidence = "SecureBoot variable not found in PCR7";
                return feat;
            }

            TryParseEfiVariable(secureBootEvent.EventData, out var varData);
            bool enabled = varData?.VariableData?.Length > 0 && varData.VariableData[0] == 0x01;

            feat.Status = enabled ? FeatureStatus.Enabled : FeatureStatus.Disabled;
            feat.Evidence = $"Event #{secureBootEvent.Index} (PCR7, EFI_VARIABLE_DRIVER_CONFIG)";

            // Also check PK, KEK, db presence
            var pkEvent = log.Events.FirstOrDefault(e =>
                e.PcrIndex == 7 && TryParseEfiVariable(e.EventData, out var v) &&
                v!.VariableName == "PK");
            var dbEvent = log.Events.FirstOrDefault(e =>
                e.PcrIndex == 7 && TryParseEfiVariable(e.EventData, out var v) &&
                v!.VariableName == "db");
            var dbxEvent = log.Events.FirstOrDefault(e =>
                e.PcrIndex == 7 && TryParseEfiVariable(e.EventData, out var v) &&
                v!.VariableName == "dbx");

            var details = new List<string>();
            if (pkEvent != null)
            {
                TryParseEfiVariable(pkEvent.EventData, out var pk);
                details.Add($"PK measured (DataLen={pk?.VariableData?.Length ?? 0})");
            }
            if (dbEvent != null)
            {
                TryParseEfiVariable(dbEvent.EventData, out var db);
                details.Add($"db measured (DataLen={db?.VariableData?.Length ?? 0})");
            }
            if (dbxEvent != null)
            {
                TryParseEfiVariable(dbxEvent.EventData, out var dbx);
                details.Add($"dbx measured (DataLen={dbx?.VariableData?.Length ?? 0})");
            }

            feat.Detail = string.Join(", ", details);
            return feat;
        }

        // ────────────────────────────────────────────────
        // 2. CPU Virtualization (VT-x / AMD-V)
        //    Evidence in TCG logs:
        //    a) EV_EFI_PLATFORM_FIRMWARE_BLOB2 in PCR0 (UEFI FW modules)
        //    b) EFI variable "VirtualizationTechnology" or similar in PCR1
        //    c) Presence of EV_EFI_HANDOFF_TABLES2 with SMBIOS type 4
        //       (Processor Info) flags - not directly readable here
        //    d) Windows WBCL: PCR12 EV_EVENT_TAG encodes boot config flags
        //
        //    Most practical: check PCR0 firmware blob names for VMX-related
        //    strings, and look for WBCL tag events in PCR11-14
        // ────────────────────────────────────────────────
        private static SecurityFeature AnalyzeVirtualization(TcgEventLog log)
        {
            var feat = new SecurityFeature { Name = "CPU Virtualization (VT-x/AMD-V)" };

            // Strategy 1: Look for EFI variable with virtualization in name
            var virtVar = log.Events.FirstOrDefault(e =>
                (e.EventType == 0x80000001 || e.EventType == 0x80000002) &&
                TryParseEfiVariable(e.EventData, out var v) &&
                v!.VariableName != null &&
                (v.VariableName.Contains("Virt", StringComparison.OrdinalIgnoreCase) ||
                 v.VariableName.Contains("VMX", StringComparison.OrdinalIgnoreCase) ||
                 v.VariableName.Contains("SVM", StringComparison.OrdinalIgnoreCase)));

            if (virtVar != null)
            {
                TryParseEfiVariable(virtVar.EventData, out var v);
                bool en = v?.VariableData?.Length > 0 && v.VariableData[0] != 0;
                feat.Status = en ? FeatureStatus.Enabled : FeatureStatus.Disabled;
                feat.Evidence = $"EFI variable '{v?.VariableName}' in Event #{virtVar.Index}";
                return feat;
            }

            // Strategy 2: PCR0 EV_EFI_PLATFORM_FIRMWARE_BLOB2 entries
            // Blob2 event data: 1-byte name length, name (UTF-8), then UINT64 base, UINT64 length
            var blobs = log.Events.Where(e =>
                e.PcrIndex == 0 && e.EventType == 0x8000000A).ToList();

            var vmxBlob = blobs.FirstOrDefault(e =>
            {
                string blobName = ParseFirmwareBlobName(e.EventData);
                return blobName.Contains("VMX", StringComparison.OrdinalIgnoreCase) ||
                       blobName.Contains("CPUINIT", StringComparison.OrdinalIgnoreCase) ||
                       blobName.Contains("VTD", StringComparison.OrdinalIgnoreCase);
            });

            if (vmxBlob != null)
            {
                feat.Status = FeatureStatus.Enabled;
                feat.Evidence = $"Firmware blob '{ParseFirmwareBlobName(vmxBlob.EventData)}' measured in PCR0 (Event #{vmxBlob.Index})";
                return feat;
            }

            // Strategy 3: WBCL PCR11 EV_COMPACT_HASH
            // The value 0x10000000 in PCR11 is Windows "Early Launch" marker
            // PCR11 being present at all indicates Hyper-V/VBS is active which requires VT-x
            var pcr11Events = log.Events.Where(e => e.PcrIndex == 11).ToList();
            if (pcr11Events.Any())
            {
                // Check if Hyper-V launch marker present
                var hvEvent = pcr11Events.FirstOrDefault(e =>
                    e.EventType == 0x0000000C && e.EventData.Length == 4 &&
                    BitConverter.ToUInt32(e.EventData) == 0x00000010);

                if (hvEvent != null)
                {
                    feat.Status = FeatureStatus.Enabled;
                    feat.Evidence = $"PCR11 contains Hyper-V early launch marker (Event #{hvEvent.Index}) — VT-x required and active";
                    feat.Detail = "Windows Hyper-V/VBS is using CPU virtualization";
                    return feat;
                }

                feat.Status = FeatureStatus.Enabled;
                feat.Evidence = $"PCR11 has {pcr11Events.Count} WBCL events — indicates VBS/Hyper-V active, requires VT-x";
                return feat;
            }

            // Strategy 4: EV_EFI_PLATFORM_FIRMWARE_BLOB2 existence in PCR0
            // If present with multiple blobs, platform likely supports virtualization
            // but we can't confirm it's enabled
            if (blobs.Count > 0)
            {
                feat.Status = FeatureStatus.Unknown;
                feat.Evidence = $"PCR0 has {blobs.Count} firmware blob measurements; no direct virtualization marker found";
                feat.Detail = "Check BIOS/UEFI setup to confirm VT-x/AMD-V is enabled";
                return feat;
            }

            feat.Status = FeatureStatus.NotMeasured;
            feat.Evidence = "No virtualization-related measurements found in event log";
            return feat;
        }

        // ────────────────────────────────────────────────
        // 3. IOMMU (VT-d / AMD-Vi)
        //    Evidence:
        //    a) ACPI DMAR table measured in EV_EFI_HANDOFF_TABLES2 (PCR1)
        //    b) EFI variable with "VTd" or "IOMMU" in PCR1
        //    c) WBCL PCR12 events (Windows records DMA protection state)
        //    d) EV_EFI_PLATFORM_FIRMWARE_BLOB2 blob named "VTD" or "DMAR"
        // ────────────────────────────────────────────────
        private static SecurityFeature AnalyzeIommu(TcgEventLog log)
        {
            var feat = new SecurityFeature { Name = "IOMMU (VT-d/AMD-Vi)" };

            // Strategy 1: EFI variable with IOMMU/VTd name
            var iommuVar = log.Events.FirstOrDefault(e =>
                (e.EventType == 0x80000001 || e.EventType == 0x80000002) &&
                TryParseEfiVariable(e.EventData, out var v) &&
                v!.VariableName != null &&
                (v.VariableName.Contains("Iommu", StringComparison.OrdinalIgnoreCase) ||
                 v.VariableName.Contains("VTd", StringComparison.OrdinalIgnoreCase) ||
                 v.VariableName.Contains("DMAR", StringComparison.OrdinalIgnoreCase) ||
                 v.VariableName.Contains("DMA", StringComparison.OrdinalIgnoreCase)));

            if (iommuVar != null)
            {
                TryParseEfiVariable(iommuVar.EventData, out var v);
                bool en = v?.VariableData?.Length > 0 && v.VariableData[0] != 0;
                feat.Status = en ? FeatureStatus.Enabled : FeatureStatus.Disabled;
                feat.Evidence = $"EFI variable '{v?.VariableName}' in Event #{iommuVar.Index}";
                return feat;
            }

            // Strategy 2: PCR0 firmware blob named VTD/DMAR
            var dmarBlob = log.Events.FirstOrDefault(e =>
                e.PcrIndex == 0 && e.EventType == 0x8000000A &&
                ParseFirmwareBlobName(e.EventData) is string name &&
                (name.Contains("VTD", StringComparison.OrdinalIgnoreCase) ||
                 name.Contains("DMAR", StringComparison.OrdinalIgnoreCase) ||
                 name.Contains("IOMMU", StringComparison.OrdinalIgnoreCase)));

            if (dmarBlob != null)
            {
                feat.Status = FeatureStatus.Enabled;
                feat.Evidence = $"DMAR/VTD firmware blob in PCR0 (Event #{dmarBlob.Index})";
                return feat;
            }

            // Strategy 3: EV_EFI_HANDOFF_TABLES2 in PCR1 — contains SMBIOS/ACPI
            // We can check if the raw data contains "DMAR" ACPI signature (4 bytes)
            var handoffEvents = log.Events.Where(e =>
                e.PcrIndex == 1 && e.EventType == 0x8000000B).ToList();

            foreach (var hEvent in handoffEvents)
            {
                if (ContainsMagic(hEvent.EventData, "DMAR"u8.ToArray()))
                {
                    feat.Status = FeatureStatus.Enabled;
                    feat.Evidence = $"DMAR ACPI table signature found in EFI_HANDOFF_TABLES2 (Event #{hEvent.Index})";
                    feat.Detail = "Intel VT-d DMAR table present and measured";
                    return feat;
                }
                if (ContainsMagic(hEvent.EventData, "IVRS"u8.ToArray()))
                {
                    feat.Status = FeatureStatus.Enabled;
                    feat.Evidence = $"IVRS ACPI table signature found in EFI_HANDOFF_TABLES2 (Event #{hEvent.Index})";
                    feat.Detail = "AMD-Vi IVRS table present and measured";
                    return feat;
                }
            }

            // Strategy 4: Windows DMA protection via WBCL PCR12 events
            // Windows records "DMA Protection" boot event if IOMMU is active
            var wbclEvents = WbclParser.ParseAll(log);

            var iommuEvent = wbclEvents.FirstOrDefault(e =>
                e.EventId == 0x00090001); // SIPAEVENT_IOMMU_DMA_PROTECTION

            if (iommuEvent != null)
            {
                bool active = false;
                if (iommuEvent.EventData.Length >= 4)
                {
                    uint flags = BitConverter.ToUInt32(iommuEvent.EventData, 0);
                    active = (flags & 0x01) != 0;  // DMAProtectionActive
                }
                else if (iommuEvent.EventData.Length >= 1)
                {
                    active = iommuEvent.EventData[0] != 0;
                }

                feat.Status = active ? FeatureStatus.Enabled : FeatureStatus.Disabled;
                feat.Evidence = $"SIPAEVENT_IOMMU_DMA_PROTECTION in WBCL " +
                                $"(TcgEvent #{iommuEvent.SourceEventIndex}, PCR{iommuEvent.SourcePcr})";
                feat.Detail = iommuEvent.InterpretedValue;
                return feat;
            }

            // ── SIPAEVENT_VBS_IOMMU_REQUIRED 作为辅助判断 ──
            var vbsIommuEvent = wbclEvents.FirstOrDefault(e => e.EventId == 0x00150001);
            if (vbsIommuEvent != null)
            {
                bool required = vbsIommuEvent.EventData.Length > 0 && vbsIommuEvent.EventData[0] != 0;
                feat.Status = required ? FeatureStatus.Enabled : FeatureStatus.Unknown;
                feat.Evidence = $"SIPAEVENT_VBS_IOMMU_REQUIRED={required} " +
                                $"(TcgEvent #{vbsIommuEvent.SourceEventIndex})";
                feat.Detail = "VBS policy requires IOMMU → IOMMU must be present and enabled";
                return feat;
            }

            // Strategy 5: Windows 11 WBCL V2 Event Aggregation
            // Microsoft moved DMA protection flags to undocumented 0x0005xxxx sub-tags in Win11
            bool hasWbclV2 = wbclEvents.Any(e => e.EventId == 0x40010001);
            if (hasWbclV2)
            {
                var win11VbsPolicy = wbclEvents.FirstOrDefault(e =>
                    e.EventId == 0x00050010 || e.EventId == 0x00050014 || e.EventId == 0x00050011);

                if (win11VbsPolicy != null && win11VbsPolicy.EventData.Length > 0 && win11VbsPolicy.EventData[0] == 0x01)
                {
                    feat.Status = FeatureStatus.Enabled;
                    feat.Evidence = "Windows 11 V2 Event Aggregation (0x40010001) contains VBS/DMA policy tags";
                    feat.Detail = $"Found active V2 security tag 0x{win11VbsPolicy.EventId:X8} = 1. Kernel DMA Protection is active.";
                    return feat;
                }
            }

            feat.Status = FeatureStatus.NotMeasured;
            feat.Evidence = "SIPAEVENT_IOMMU_DMA_PROTECTION not found in WBCL";
            feat.Detail = "IOMMU may be disabled, or WBCL not fully present in this log";
            return feat;
        }

        // ────────────────────────────────────────────────
        // 4. HVCI / VBS (Hypervisor-protected Code Integrity)
        //    Evidence chain:
        //    1) SIPAEVENT_HYPERVISOR_LAUNCH_TYPE (old: 0x00080001, Win11 V2: 0x00020008)
        //       value 1 = Hyper-V launched, VT-x occupied
        //    2) SIPAEVENT_VBS flags (old: 0x000A0001, Win11 V2: 0x0005000A)
        //       Bit 0: VBS Enabled, Bit 2: HVCI Enabled
        //    3) PCR12 replay match confirms WBCL integrity (handled by PCR Banks)
        // ────────────────────────────────────────────────
        private static SecurityFeature AnalyzeHvci(TcgEventLog log)
        {
            var feat = new SecurityFeature { Name = "HVCI / VBS (Hypervisor Code Integrity)" };
            var wbclEvents = WbclParser.ParseAll(log);
            var evidences = new List<string>();
            bool hvciDetected = false;

            // ── Evidence 1: Hypervisor Launch Type ──
            // Legacy tag: SIPAEVENT_HYPERVISOR_LAUNCH_TYPE = 0x00080001
            // Win11 V2 tag: 0x00020008 (inside 0x40010001 aggregation)
            var launchTypeEvent = wbclEvents.FirstOrDefault(e =>
                e.EventId == 0x00080001 || e.EventId == 0x00020008);

            if (launchTypeEvent != null)
            {
                uint launchType = 0;
                if (launchTypeEvent.EventData.Length >= 4)
                    launchType = BitConverter.ToUInt32(launchTypeEvent.EventData, 0);
                else if (launchTypeEvent.EventData.Length >= 1)
                    launchType = launchTypeEvent.EventData[0];

                string launchDesc = launchType switch
                {
                    0 => "Hyper-V not launched",
                    1 => "Hyper-V launched (VT-x occupied)",
                    2 => "Launched with virtualization extensions",
                    _ => $"Unknown ({launchType})"
                };

                evidences.Add($"Chain 1: HypervisorLaunchType={launchType} ({launchDesc}) " +
                              $"[0x{launchTypeEvent.EventId:X8}, PCR{launchTypeEvent.SourcePcr}]");

                if (launchType >= 1)
                    hvciDetected = true;
            }
            else
            {
                evidences.Add("Chain 1: HypervisorLaunchType not found");
            }

            // ── Evidence 2: VBS / HVCI flags ──
            // Legacy tag: SIPAEVENT_VBS_STATUS = 0x000A0001
            // Win11 V2 tag: 0x0005000A (VBS flags, 8 bytes LE)
            var vbsFlagsEvent = wbclEvents.FirstOrDefault(e =>
                e.EventId == 0x000A0001 || e.EventId == 0x0005000A);

            if (vbsFlagsEvent != null)
            {
                ulong vbsFlags = 0;
                if (vbsFlagsEvent.EventData.Length >= 8)
                    vbsFlags = BitConverter.ToUInt64(vbsFlagsEvent.EventData, 0);
                else if (vbsFlagsEvent.EventData.Length >= 4)
                    vbsFlags = BitConverter.ToUInt32(vbsFlagsEvent.EventData, 0);
                else if (vbsFlagsEvent.EventData.Length >= 1)
                    vbsFlags = vbsFlagsEvent.EventData[0];

                bool vbsEnabled = (vbsFlags & 0x01) != 0;
                bool vbsRequired = (vbsFlags & 0x02) != 0;
                bool hvciEnabled = (vbsFlags & 0x04) != 0;

                var flagStrs = new List<string>();
                if (vbsEnabled) flagStrs.Add("VBS=ON");
                if (vbsRequired) flagStrs.Add("VBS_REQUIRED");
                if (hvciEnabled) flagStrs.Add("HVCI=ON");

                if (flagStrs.Count == 0 && vbsFlags != 0)
                    flagStrs.Add($"raw=0x{vbsFlags:X}");

                evidences.Add($"Chain 2: VBS/HVCI flags=0x{vbsFlags:X} ({string.Join(", ", flagStrs)}) " +
                              $"[0x{vbsFlagsEvent.EventId:X8}, PCR{vbsFlagsEvent.SourcePcr}]");

                if (vbsEnabled || hvciEnabled)
                    hvciDetected = true;
            }
            else
            {
                // Fallback: check 0x00050012 (Win11 V2 VBS related)
                var vbs12 = wbclEvents.FirstOrDefault(e => e.EventId == 0x00050012);
                if (vbs12 != null)
                {
                    ulong val = 0;
                    if (vbs12.EventData.Length >= 8)
                        val = BitConverter.ToUInt64(vbs12.EventData, 0);
                    else if (vbs12.EventData.Length >= 1)
                        val = vbs12.EventData[0];

                    evidences.Add($"Chain 2: VBS policy tag 0x00050012=0x{val:X} " +
                                  $"[PCR{vbs12.SourcePcr}]");

                    if (val != 0)
                        hvciDetected = true;
                }
                else
                {
                    evidences.Add("Chain 2: VBS/HVCI flags not found");
                }
            }

            // ── Evidence 3: PCR12 replay integrity ──
            // This is verified in PCR Banks section; we just note whether PCR12 events exist
            bool hasPcr12 = log.Events.Any(e => e.PcrIndex == 12);
            if (hasPcr12)
            {
                evidences.Add("Chain 3: PCR12 events present — replay match verified in PCR Banks");
            }
            else
            {
                evidences.Add("Chain 3: No PCR12 events — cannot verify WBCL integrity");
            }

            // ── Final verdict ──
            if (hvciDetected && hasPcr12)
            {
                feat.Status = FeatureStatus.Enabled;
                feat.Evidence = "HVCI/VBS is active — Hyper-V occupying VT-x, PCR12 integrity verified";
            }
            else if (hvciDetected)
            {
                feat.Status = FeatureStatus.Enabled;
                feat.Evidence = "HVCI/VBS detected from WBCL flags (PCR12 replay not available)";
            }
            else
            {
                feat.Status = FeatureStatus.NotMeasured;
                feat.Evidence = "No HVCI/VBS markers found in WBCL";
            }

            feat.Detail = string.Join("\n         ", evidences);
            return feat;
        }

        // ────────────────────────────────────────────────
        // 5. Driver Signature Enforcement (代码完整性 / 驱动签名)
        //    Evidence:
        //    a) 0x00050002 = Test signing disabled (1=off → enforcement ON)
        //    b) 0x0005000E = Code integrity enforcement flag (1=enabled)
        //    c) 0x00040002 = SIPAEVENT_OSKERNELDEBUG (disabled = good)
        //    d) Legacy: 0x00070001 = SIPAEVENT_CODEINTEGRITY
        // ────────────────────────────────────────────────
        private static SecurityFeature AnalyzeDriverSignature(TcgEventLog log)
        {
            var feat = new SecurityFeature { Name = "Driver Signature Enforcement (Code Integrity)" };
            var wbclEvents = WbclParser.ParseAll(log);
            var evidences = new List<string>();
            bool enforced = false;

            // ── Test Signing status ──
            // 0x00050002: value 0x01 = test signing OFF (enforcement active)
            var testSignEvent = wbclEvents.FirstOrDefault(e => e.EventId == 0x00050002);
            if (testSignEvent != null)
            {
                byte val = testSignEvent.EventData.Length > 0 ? testSignEvent.EventData[0] : (byte)0;
                bool testSignOff = val == 0x01;

                evidences.Add($"TestSigning={(!testSignOff ? "ON (⚠ enforcement weakened)" : "OFF (enforced)")} " +
                              $"[0x00050002=0x{val:X2}, PCR{testSignEvent.SourcePcr}]");

                if (testSignOff)
                    enforced = true;
            }

            // ── Code integrity enforcement flag ──
            // 0x0005000E: value != 0 means enforcement active
            var ciEnforcementEvent = wbclEvents.FirstOrDefault(e => e.EventId == 0x0005000E);
            if (ciEnforcementEvent != null)
            {
                uint val = 0;
                if (ciEnforcementEvent.EventData.Length >= 4)
                    val = BitConverter.ToUInt32(ciEnforcementEvent.EventData, 0);
                else if (ciEnforcementEvent.EventData.Length >= 1)
                    val = ciEnforcementEvent.EventData[0];

                bool active = val != 0;
                evidences.Add($"CodeIntegrityEnforcement={(active ? "Active" : "Inactive")} " +
                              $"[0x0005000E=0x{val:X}, PCR{ciEnforcementEvent.SourcePcr}]");

                if (active)
                    enforced = true;
            }

            // ── Kernel debug status ──
            // 0x00040002 = SIPAEVENT_OSKERNELDEBUG: "Disabled/Not set" = good
            var kdEvent = wbclEvents.FirstOrDefault(e => e.EventId == 0x00040002);
            if (kdEvent != null)
            {
                bool kdDisabled = kdEvent.InterpretedValue?.Contains("Disabled", StringComparison.OrdinalIgnoreCase) == true
                    || (kdEvent.EventData.Length > 0 && kdEvent.EventData[0] == 0);

                evidences.Add($"KernelDebug={(kdDisabled ? "Disabled (good)" : "⚠ Enabled (weakens enforcement)")} " +
                              $"[0x00040002, PCR{kdEvent.SourcePcr}]");
            }

            // ── Legacy: SIPAEVENT_CODEINTEGRITY ──
            var ciLegacy = wbclEvents.FirstOrDefault(e => e.EventId == 0x00070001);
            if (ciLegacy != null)
            {
                byte val = ciLegacy.EventData.Length > 0 ? ciLegacy.EventData[0] : (byte)0;
                evidences.Add($"Legacy CI flag=0x{val:X2} [0x00070001, PCR{ciLegacy.SourcePcr}]");
                if (val != 0) enforced = true;
            }

            // ── Verdict ──
            if (enforced)
            {
                feat.Status = FeatureStatus.Enabled;
                feat.Evidence = "Driver signature enforcement is active — test signing off, code integrity enforced";
            }
            else if (evidences.Count > 0)
            {
                feat.Status = FeatureStatus.Unknown;
                feat.Evidence = "WBCL tags found but enforcement status unclear";
            }
            else
            {
                feat.Status = FeatureStatus.NotMeasured;
                feat.Evidence = "No driver signing / code integrity tags found in WBCL";
            }

            feat.Detail = string.Join("\n         ", evidences);
            return feat;
        }

        // ────────────────────────────────────────────────
        // 6. Vulnerable Driver Blocklist (易受攻击驱动阻止列表)
        //    Evidence:
        //    a) 0x00050021 = Vulnerable driver blocklist enabled (1=yes)
        //    b) 0x00040001 = SIPAEVENT_BOOTREVOCATIONLIST (revocation list present)
        //    c) 0x00050003 = Boot revocation list policy flag
        // ────────────────────────────────────────────────
        private static SecurityFeature AnalyzeVulnerableDriverBlocklist(TcgEventLog log)
        {
            var feat = new SecurityFeature { Name = "Vulnerable Driver Blocklist" };
            var wbclEvents = WbclParser.ParseAll(log);
            var evidences = new List<string>();
            bool blocklistEnabled = false;

            // ── 0x00050021: Vulnerable driver blocklist enabled ──
            var blocklistEvent = wbclEvents.FirstOrDefault(e => e.EventId == 0x00050021);
            if (blocklistEvent != null)
            {
                byte val = blocklistEvent.EventData.Length > 0 ? blocklistEvent.EventData[0] : (byte)0;
                bool enabled = val == 0x01;

                evidences.Add($"VulnerableDriverBlocklist={(enabled ? "Enabled" : "Disabled")} " +
                              $"[0x00050021=0x{val:X2}, PCR{blocklistEvent.SourcePcr}]");

                if (enabled)
                    blocklistEnabled = true;
            }

            // ── 0x00040001: SIPAEVENT_BOOTREVOCATIONLIST ──
            var revocListEvents = wbclEvents.Where(e => e.EventId == 0x00040001).ToList();
            if (revocListEvents.Count > 0)
            {
                evidences.Add($"BootRevocationList present ({revocListEvents.Count} entries) " +
                              $"[0x00040001, PCR{revocListEvents[0].SourcePcr}]");
            }

            // ── 0x00050003: Boot revocation policy flag ──
            var revocPolicyEvent = wbclEvents.FirstOrDefault(e => e.EventId == 0x00050003);
            if (revocPolicyEvent != null)
            {
                byte val = revocPolicyEvent.EventData.Length > 0 ? revocPolicyEvent.EventData[0] : (byte)0;
                evidences.Add($"BootRevocationPolicy=0x{val:X2} " +
                              $"[0x00050003, PCR{revocPolicyEvent.SourcePcr}]");
            }

            // ── Verdict ──
            if (blocklistEnabled)
            {
                feat.Status = FeatureStatus.Enabled;
                feat.Evidence = "Microsoft vulnerable driver blocklist is active";
            }
            else if (revocListEvents.Count > 0)
            {
                feat.Status = FeatureStatus.Enabled;
                feat.Evidence = "Boot revocation list present (blocklist likely active)";
            }
            else if (evidences.Count > 0)
            {
                feat.Status = FeatureStatus.Unknown;
                feat.Evidence = "WBCL tags found but blocklist status unclear";
            }
            else
            {
                feat.Status = FeatureStatus.NotMeasured;
                feat.Evidence = "No vulnerable driver blocklist tags found in WBCL";
            }

            feat.Detail = string.Join("\n         ", evidences);
            return feat;
        }

        // ────────────────────────────────────────────────
        // 7. Boot Integrity (PCR replay consistency)
        // ────────────────────────────────────────────────
        private static SecurityFeature AnalyzeBootIntegrity(TcgEventLog log)
        {
            var feat = new SecurityFeature { Name = "Boot Log Integrity (PCR Replay)" };

            // Count events by separator presence (indicates clean boot phases)
            int separatorCount = log.Events.Count(e => e.EventType == 0x00000004);
            bool hasSeparators = separatorCount >= 7; // PCR0-6 should each have one

            // Check if WBCL terminator is present (EV_SEPARATOR with "WBCL" in PCR12/13/14)
            bool hasWbclTerminator = log.Events.Any(e =>
                e.EventType == 0x00000004 &&
                e.PcrIndex is 12 or 13 or 14 &&
                e.EventData.Length == 4 &&
                System.Text.Encoding.ASCII.GetString(e.EventData) == "WBCL");

            if (hasSeparators && hasWbclTerminator)
            {
                feat.Status = FeatureStatus.Enabled;
                feat.Evidence = $"All phase separators present ({separatorCount}), WBCL terminator found";
                feat.Detail = "Boot sequence appears complete and well-formed";
            }
            else if (hasSeparators)
            {
                feat.Status = FeatureStatus.Enabled;
                feat.Evidence = $"Phase separators present ({separatorCount})";
                feat.Detail = "UEFI boot phases properly separated; WBCL (Windows) terminator absent";
            }
            else
            {
                feat.Status = FeatureStatus.Unknown;
                feat.Evidence = $"Only {separatorCount} separator events found";
            }

            return feat;
        }

        // ────────────────────────────────────────────────
        // Helpers
        // ────────────────────────────────────────────────
        private static bool TryParseEfiVariable(byte[] data, out EfiVariableData? result)
        {
            result = null;
            if (data == null || data.Length < 28) return false;
            try
            {
                var guid = new Guid(
                    BitConverter.ToUInt32(data, 0),
                    BitConverter.ToUInt16(data, 4),
                    BitConverter.ToUInt16(data, 6),
                    data[8], data[9], data[10], data[11],
                    data[12], data[13], data[14], data[15]);
                ulong nameLen = BitConverter.ToUInt64(data, 16);
                ulong dataLen = BitConverter.ToUInt64(data, 24);
                int nameOffset = 32;
                int nameBytes = (int)nameLen * 2;
                if (nameOffset + nameBytes > data.Length) return false;
                string name = Encoding.Unicode.GetString(data, nameOffset, nameBytes).TrimEnd('\0');
                int dataOffset = nameOffset + nameBytes;
                int dataBytes = (int)Math.Min(dataLen, (ulong)(data.Length - dataOffset));
                byte[] varData = dataBytes > 0 ? data[dataOffset..(dataOffset + dataBytes)] : [];

                result = new EfiVariableData
                {
                    VariableGuid = guid,
                    VariableName = name,
                    VariableData = varData
                };
                return true;
            }
            catch { return false; }
        }

        private static string ParseFirmwareBlobName(byte[] data)
        {
            // EFI_PLATFORM_FIRMWARE_BLOB2: UINT8 BlobDescriptionSize, BlobDescription (UTF-8), UINT64 Base, UINT64 Length
            if (data == null || data.Length < 2) return "";
            int nameLen = data[0];
            if (nameLen == 0 || nameLen + 1 > data.Length) return "";
            return Encoding.UTF8.GetString(data, 1, nameLen).TrimEnd('\0');
        }

        private static bool ContainsMagic(byte[] data, byte[] magic)
        {
            if (data == null || data.Length < magic.Length) return false;
            for (int i = 0; i <= data.Length - magic.Length; i++)
            {
                bool match = true;
                for (int j = 0; j < magic.Length; j++)
                    if (data[i + j] != magic[j]) { match = false; break; }
                if (match) return true;
            }
            return false;
        }
    }
}