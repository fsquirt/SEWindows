using MeasuredBootParser.Analyzers;
using MeasuredBootParser.Models;
using MeasuredBootParser.Output;
using MeasuredBootParser.Parsers;
using MeasuredBootParser.Verifier;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace MeasuredBootParser
{
    /// <summary>
    /// 核心分析入口，负责协调 TCG 日志解析、PCR 回放、安全特性分析全流程。
    /// Program.cs 只负责 UI 启动，所有分析逻辑在此。
    /// </summary>
    public static class MeasuredBootCore
    {
        /// <summary>
        /// 主分析流程。args 兼容命令行参数：
        ///   args[0]        - 可选，手动指定 .log 文件路径
        ///   --pcr=N        - 只显示指定 PCR 的事件
        /// </summary>
        public static async Task Run(string[] args)
        {
            Console.OutputEncoding = System.Text.Encoding.UTF8;

            // ── 1. 解析日志来源 ──────────────────────────────────────────
            TcgEventLog log;
            string? jsonFile = null;

            if (args.Length >= 1 && File.Exists(args[0]))
            {
                string logFile = args[0];
                Console.WriteLine($"\n[*] Parsing file: {logFile}\n");
                log = EventLogParser.Parse(logFile);

                string baseName = Path.GetFileNameWithoutExtension(logFile);
                string logDir = Path.GetDirectoryName(logFile) ?? ".";
                jsonFile = Path.Combine(logDir, baseName + ".json");
                if (!File.Exists(jsonFile)) jsonFile = null;
            }
            else
            {
                log = TryReadFromTpm(out jsonFile);
                if (log == null) return;
            }

            // ── 2. 摘要输出 ──────────────────────────────────────────────
            ReportWriter.PrintSummary(log);

            if (jsonFile != null)
            {
                Console.WriteLine($"[*] JSON sidecar: {jsonFile}");
                ReportWriter.PrintJsonSidecar(jsonFile);
            }

            // ── 3. PCR 回放 ──────────────────────────────────────────────
            Console.WriteLine("[*] Replaying PCR values from event log...");
            var replayedBanks = PcrReplayer.Replay(log);

            // ── 4. 读取 TPM 实际 PCR 值 ──────────
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

            // ── 5. PCR Banks 对比报告 ────────────────────────────────────
            ReportWriter.PrintPcrBanks(log, replayedBanks, tpmBanks);

            // ── 6. 事件列表 ─────────────────────────────────────────────
            Console.WriteLine("[*] Showing all events (use --pcr=N to filter):");
            uint? filterPcr = null;
            foreach (var a in args)
                if (a.StartsWith("--pcr=") && uint.TryParse(a[6..], out uint p))
                    filterPcr = p;

            ReportWriter.PrintEvents(log, filterPcr);

            // ── 7. WBCL Tagged Events ────────────────────────────────────
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

            // ── 安全特性分析 ──────────────────────────────────────────
            var features = SecurityFeatureAnalyzer.Analyze(log);
            ReportWriter.PrintSecurityFeatures(features);
        }

        // ── 从 TBS API 读取日志 ───────────────────────────────
        private static TcgEventLog? TryReadFromTpm(out string? jsonFile)
        {
            jsonFile = null;

            try
            {
                Console.WriteLine("\n[*] Reading TCG log from TPM via Tbsi_Get_TCG_Log_Ex...");
                byte[] tbsData = TbsApi.GetTcgLog();
                Console.WriteLine($"[*] Got {tbsData.Length:N0} bytes from TBS API\n");
                return EventLogParser.Parse(tbsData, "<TPM via Tbsi_Get_TCG_Log_Ex>");
            }
            catch (Exception tbsEx)
            {
                Console.WriteLine($"[!] TBS API failed: {tbsEx.Message}");
                Console.WriteLine("[*] Falling back to disk log files...\n");

                return null;
            }
        }
    }
}
