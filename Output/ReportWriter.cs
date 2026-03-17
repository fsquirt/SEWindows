using MeasuredBootParser.Analyzers;
using MeasuredBootParser.Models;
using Newtonsoft.Json.Linq;


namespace MeasuredBootParser.Output
{
    public static class ReportWriter
    {
        public static void PrintSummary(TcgEventLog log)
        {
            var w = Console.Out;
            w.WriteLine("╔══════════════════════════════════════════════════════════════╗");
            w.WriteLine("║           TCG Measured Boot Event Log Analysis               ║");
            w.WriteLine("╚══════════════════════════════════════════════════════════════╝");
            w.WriteLine();
            w.WriteLine($"  File   : {log.FilePath}");
            w.WriteLine($"  Size   : {log.FileSize:N0} bytes");
            w.WriteLine($"  Format : {(log.IsCryptoAgile ? "TCG 2.0 Crypto Agile" : "TCG 1.2 (SHA-1 only)")}");

            if (log.SpecId != null)
            {
                w.WriteLine($"  Spec   : v{log.SpecId.SpecVersionMajor}.{log.SpecId.SpecVersionMinor} Errata={log.SpecId.SpecErrata}");
                var algNames = log.SpecId.AlgorithmList
                    .Select(a => TcgAlgorithmId.GetName(a.AlgId))
                    .ToList();
                w.WriteLine($"  Algos  : {string.Join(", ", algNames)}");
            }

            var localityEvent = log.Events.FirstOrDefault(e =>
                e.EventType == 0x00000003 &&
                e.EventData?.Length >= 17 &&
                System.Text.Encoding.ASCII.GetString(e.EventData, 0, 16) == "StartupLocality\0");

            if (localityEvent != null)
                w.WriteLine($"  Locality : {localityEvent.EventData[16]} (TPM Startup Locality)");

            w.WriteLine($"  Events : {log.Events.Count}");
            w.WriteLine();
        }

        public static void PrintPcrBanks(TcgEventLog log,
            Dictionary<ushort, Dictionary<uint, byte[]>>? replayedBanks = null,
            Dictionary<ushort, Dictionary<uint, byte[]>>? tpmBanks = null)
        {
            Console.WriteLine("┌──────────────────────────────────────────────────────────────┐");
            Console.WriteLine("│                       PCR Banks                              │");
            Console.WriteLine("└──────────────────────────────────────────────────────────────┘");

            var sourceBanks = replayedBanks ?? log.PcrBanks;
            bool hasTpm = tpmBanks != null && tpmBanks.Count > 0;

            foreach (var (algId, bank) in sourceBanks.OrderBy(k => k.Key))
            {
                string algName = TcgAlgorithmId.GetName(algId);
                Console.WriteLine($"\n  [{algName}]");

                if (hasTpm)
                {
                    Console.WriteLine($"  {"PCR",-5}  {"Replayed Value",-64}  {"TPM Match"}");
                    Console.WriteLine($"  {new string('-', 5)}  {new string('-', 64)}  {new string('-', 12)}");
                }
                else
                {
                    Console.WriteLine($"  {"PCR",-5}  {"Value",-64}");
                    Console.WriteLine($"  {new string('-', 5)}  {new string('-', 64)}");
                }

                foreach (var (pcrIdx, val) in bank.OrderBy(k => k.Key))
                {
                    string hex = Convert.ToHexString(val).ToLowerInvariant();

                    if (hasTpm)
                    {
                        string match = "—";
                        if (tpmBanks!.TryGetValue(algId, out var tBank) &&
                            tBank.TryGetValue(pcrIdx, out var tVal))
                        {
                            string tHex = Convert.ToHexString(tVal).ToLowerInvariant();
                            match = (hex == tHex) ? "✓ MATCH" : "✗ MISMATCH";
                        }
                        Console.WriteLine($"  PCR{pcrIdx,-2}  {hex,-64}  {match}");
                    }
                    else
                    {
                        Console.WriteLine($"  PCR{pcrIdx,-2}  {hex,-64}");
                    }
                }
            }
            Console.WriteLine();
        }

        public static void PrintEvents(TcgEventLog log, uint? filterPcr = null)
        {
            Console.WriteLine("┌──────────────────────────────────────────────────────────────┐");
            Console.WriteLine("│                       Event List                             │");
            Console.WriteLine("└──────────────────────────────────────────────────────────────┘");
            Console.WriteLine();

            var events = filterPcr.HasValue
                ? log.Events.Where(e => e.PcrIndex == filterPcr.Value).ToList()
                : log.Events;

            foreach (var evt in events)
            {
                Console.WriteLine($"  ── Event #{evt.Index} ─────────────────────────────────");
                Console.WriteLine($"     PCR       : {evt.PcrIndex}");
                Console.WriteLine($"     Type      : {evt.EventTypeName} (0x{evt.EventType:X8})");
                Console.WriteLine($"     Offset    : 0x{evt.FileOffset:X}");

                foreach (var d in evt.Digests)
                    Console.WriteLine($"     {d.AlgorithmName,-10}: {d.DigestHex}");

                Console.WriteLine($"     DataLen   : {evt.EventData.Length} bytes");
                if (!string.IsNullOrEmpty(evt.EventDataString))
                    Console.WriteLine($"     Data      : {evt.EventDataString}");
                else if (evt.EventData.Length > 0 && evt.EventData.Length <= 64)
                    Console.WriteLine($"     DataHex   : {evt.EventDataHex}");

                Console.WriteLine();
            }
        }

        public static void ExportJson(TcgEventLog log,
            Dictionary<ushort, Dictionary<uint, byte[]>>? replayedBanks,
            string outPath)
        {
            var obj = new JObject
            {
                ["file"] = log.FilePath,
                ["format"] = log.IsCryptoAgile ? "TCG2.0-CryptoAgile" : "TCG1.2",
                ["eventCount"] = log.Events.Count,
                ["pcrBanks"] = BuildPcrBanksJson(log.PcrBanks, replayedBanks),
                ["events"] = BuildEventsJson(log.Events),
            };

            File.WriteAllText(outPath, obj.ToString(Newtonsoft.Json.Formatting.Indented));
            Console.WriteLine($"  [✓] JSON exported → {outPath}");
        }

        private static JObject BuildPcrBanksJson(
            Dictionary<ushort, Dictionary<uint, byte[]>> banks,
            Dictionary<ushort, Dictionary<uint, byte[]>>? replayedBanks)
        {
            var sourceBanks = replayedBanks ?? banks;
            var obj = new JObject();
            foreach (var (algId, bank) in sourceBanks)
            {
                string algName = TcgAlgorithmId.GetName(algId);
                var bankObj = new JObject();
                foreach (var (pcrIdx, val) in bank.OrderBy(k => k.Key))
                {
                    string hex = Convert.ToHexString(val).ToLowerInvariant();
                    bankObj[$"PCR{pcrIdx}"] = new JObject
                    {
                        ["value"] = hex
                    };
                }
                obj[algName] = bankObj;
            }
            return obj;
        }

        private static JArray BuildEventsJson(List<TcgEvent> events)
        {
            var arr = new JArray();
            foreach (var evt in events)
            {
                var digests = new JObject();
                foreach (var d in evt.Digests)
                    digests[d.AlgorithmName] = d.DigestHex;

                arr.Add(new JObject
                {
                    ["index"] = evt.Index,
                    ["pcr"] = evt.PcrIndex,
                    ["eventType"] = evt.EventTypeName,
                    ["offset"] = $"0x{evt.FileOffset:X}",
                    ["digests"] = digests,
                    ["dataLen"] = evt.EventData.Length,
                    ["dataText"] = evt.EventDataString,
                });
            }
            return arr;
        }

        public static void PrintJsonSidecar(string jsonPath)
        {
            if (!File.Exists(jsonPath)) return;
            Console.WriteLine("┌──────────────────────────────────────────────────────────────┐");
            Console.WriteLine("│               Windows MeasuredBoot JSON Sidecar              │");
            Console.WriteLine("└──────────────────────────────────────────────────────────────┘");

            try
            {
                var raw = File.ReadAllText(jsonPath);
                var obj = JObject.Parse(raw);
                // Print key top-level fields
                foreach (var prop in obj.Properties().Take(30))
                    Console.WriteLine($"  {prop.Name,-35}: {prop.Value}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  [!] Failed to parse JSON: {ex.Message}");
            }
            Console.WriteLine();
        }

        public static void PrintSecurityFeatures(List<MeasuredBootParser.Analyzers.SecurityFeature> features)
        {
            Console.WriteLine("┌──────────────────────────────────────────────────────────────┐");
            Console.WriteLine("│                  Security Feature Analysis                   │");
            Console.WriteLine("└──────────────────────────────────────────────────────────────┘");
            Console.WriteLine();

            foreach (var f in features)
            {
                string icon = f.Status switch
                {
                    FeatureStatus.Enabled => "✅",
                    FeatureStatus.Disabled => "❌",
                    FeatureStatus.Unknown => "⚠️ ",
                    FeatureStatus.NotMeasured => "➖",
                    _ => "?"
                };
                Console.WriteLine($"  {icon}  {f.Name}");
                Console.WriteLine($"       Status  : {f.Status}");
                Console.WriteLine($"       Evidence: {f.Evidence}");
                if (!string.IsNullOrEmpty(f.Detail))
                    Console.WriteLine($"       Detail  : {f.Detail}");
                Console.WriteLine();
            }
        }
    }
}