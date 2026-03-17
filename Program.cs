using MeasuredBootParser.Analyzers;
using MeasuredBootParser.Models;
using MeasuredBootParser.Output;
using MeasuredBootParser.Parsers;
using MeasuredBootParser.Verifier;
using System;
using System.IO;
using System.Linq;

namespace MeasuredBootParser
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.OutputEncoding = System.Text.Encoding.UTF8;

            // --- Resolve log source ---
            TcgEventLog log;
            string? jsonFile = null;

            if (args.Length >= 1 && File.Exists(args[0]))
            {
                // Explicit file path from command line
                string logFile = args[0];
                Console.WriteLine($"\n[*] Parsing file: {logFile}\n");
                log = EventLogParser.Parse(logFile);

                // Find matching .json sidecar
                string baseName = Path.GetFileNameWithoutExtension(logFile);
                string logDir = Path.GetDirectoryName(logFile) ?? ".";
                jsonFile = Path.Combine(logDir, baseName + ".json");
                if (!File.Exists(jsonFile)) jsonFile = null;
            }
            else
            {
                // Try TBS API first (requires admin)
                try
                {
                    Console.WriteLine("\n[*] Reading TCG log from TPM via Tbsi_Get_TCG_Log_Ex...");
                    byte[] tbsData = TbsApi.GetTcgLog();
                    Console.WriteLine($"[*] Got {tbsData.Length:N0} bytes from TBS API\n");
                    log = EventLogParser.Parse(tbsData, "<TPM via Tbsi_Get_TCG_Log_Ex>");
                }
                catch (Exception tbsEx)
                {
                    Console.WriteLine($"[!] TBS API failed: {tbsEx.Message}");
                    Console.WriteLine("[*] Falling back to disk log files...\n");

                    // Fall back to disk log files
                    string logDir = @"C:\Windows\Logs\MeasuredBoot";
                    string? logFile = null;

                    if (Directory.Exists(logDir))
                    {
                        logFile = Directory.GetFiles(logDir, "*.log")
                            .OrderByDescending(File.GetLastWriteTime)
                            .FirstOrDefault();

                        if (logFile != null)
                        {
                            string baseName = Path.GetFileNameWithoutExtension(logFile);
                            jsonFile = Path.Combine(logDir, baseName + ".json");
                            if (!File.Exists(jsonFile)) jsonFile = null;
                        }
                    }

                    if (logFile == null)
                    {
                        Console.Error.WriteLine("[!] No .log file found either. Usage: MeasuredBootParser [path.log]");
                        return;
                    }

                    Console.WriteLine($"[*] Parsing file: {logFile}\n");
                    try
                    {
                        log = EventLogParser.Parse(logFile);
                    }
                    catch (Exception ex)
                    {
                        Console.Error.WriteLine($"[!] Parse failed: {ex.Message}");
                        return;
                    }
                }
            }

            // --- Summary ---
            ReportWriter.PrintSummary(log);

            // --- JSON Sidecar ---
            if (jsonFile != null)
            {
                Console.WriteLine($"[*] JSON sidecar: {jsonFile}");
                ReportWriter.PrintJsonSidecar(jsonFile);
            }

            // --- PCR Replay Verification ---
            Console.WriteLine("[*] Replaying PCR values from event log...");
            var replayedBanks = PcrReplayer.Replay(log);

            // --- Read actual PCR values from TPM ---
            Dictionary<ushort, Dictionary<uint, byte[]>>? tpmBanks = null;
            try
            {
                var algIds = replayedBanks.Keys.ToList();
                var pcrIndices = replayedBanks.Values
                    .SelectMany(b => b.Keys)
                    .Distinct()
                    .OrderBy(x => x)
                    .ToList();

                Console.WriteLine("[*] Reading actual PCR values from TPM...");
                tpmBanks = TbsApi.ReadPcrValues(algIds, pcrIndices);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Could not read TPM PCR values: {ex.Message}");
            }

            // --- PCR Banks ---
            ReportWriter.PrintPcrBanks(log, replayedBanks, tpmBanks);

            // --- Events ---
            Console.WriteLine("[*] Showing all events (use --pcr=N to filter):");
            uint? filterPcr = null;
            foreach (var a in args)
                if (a.StartsWith("--pcr=") && uint.TryParse(a[6..], out uint p))
                    filterPcr = p;

            ReportWriter.PrintEvents(log, filterPcr);

            var wbclEvents = WbclParser.ParseAll(log);
            if (wbclEvents.Count > 0)
            {
                Console.WriteLine("┌──────────────────────────────────────────────────────────────┐");
                Console.WriteLine("│              WBCL Tagged Events (PCR11-14)                   │");
                Console.WriteLine("└──────────────────────────────────────────────────────────────┘");
                Console.WriteLine();
                foreach (var w in wbclEvents)
                {
                    Console.WriteLine($"  [PCR{w.SourcePcr}] TcgEvent#{w.SourceEventIndex}  " +
                                      $"0x{w.EventId:X8}  {w.EventName}");
                    Console.WriteLine($"           Value: {w.InterpretedValue}");
                }
                Console.WriteLine();
            }

            // --- Export JSON ---
            string exportName = log.FilePath.StartsWith("<")
                ? "tbs_tcglog.parsed.json"
                : Path.GetFileNameWithoutExtension(log.FilePath) + ".parsed.json";
            string exportPath = Path.Combine(Directory.GetCurrentDirectory(), exportName);
            ReportWriter.ExportJson(log, replayedBanks, exportPath);

            var features = SecurityFeatureAnalyzer.Analyze(log);
            ReportWriter.PrintSecurityFeatures(features);

            Console.WriteLine("\n[✓] Done.");
        }
    }
}