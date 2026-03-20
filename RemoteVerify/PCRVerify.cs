using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Json;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Threading.Tasks;
using Tpm2Lib;

namespace SEWindows.RemoteVerify
{
    // ── 返回值 ─────────────────────────────────────────────────────────────────
    public class PCRVerifyResult
    {
        public bool Success { get; init; }
        public string Reason { get; init; } = "";
        public bool SigValid { get; init; }
        public bool MagicOk { get; init; }
        public bool NonceOk { get; init; }
        public bool PcrMatch { get; init; }
        public List<SecurityFeatureInfo> SecurityFeatures { get; init; } = [];
    }

    public class SecurityFeatureInfo
    {
        public string Name { get; init; } = "";
        public string Status { get; init; } = "";
        public string Evidence { get; init; } = "";
        public string Detail { get; init; } = "";

        public override string ToString() =>
            $"  {Name,-40} [{Status,-12}]  {Evidence}";
    }

    // ══════════════════════════════════════════════════════════════════════════
    // PCRVerify
    // ══════════════════════════════════════════════════════════════════════════
    public static class PCRVerify
    {
        // Quote PCR 0-14（与 wbcl_replay.py 保持一致）
        static readonly uint[] QuotedPcrs = Enumerable.Range(0, 15).Select(i => (uint)i).ToArray();

        /// <summary>
        /// 执行完整的 PCR Quote 远程验证流程。
        ///
        /// 前提：akResult.Success == true（AKVerify.RunAsync 已成功）。
        ///
        /// 流程:
        ///   1. POST /request_nonce  → 服务端分配 nonce + quote_sid
        ///   2. TBS API 读取 WBCL
        ///   3. TPM2_Quote(PCR 0-14, nonce)  →  TPMS_ATTEST + Signature
        ///   4. POST /verify_quote → 服务端四步验证 + 安全特性分析
        /// </summary>
        public static async Task<PCRVerifyResult> RunAsync(
            Tpm2 tpm, HttpClient http, AKVerifyResult akResult)
        {
            if (!akResult.Success || akResult.AkName == null)
                return Fail("AKVerify result is not successful");

            // ── Step 1: 向服务端请求 nonce ────────────────────────────────────
            Console.WriteLine("[*] PCRVerify: POST /request_nonce...");
            HttpResponseMessage nonceResp;
            try
            {
                nonceResp = await http.PostAsJsonAsync("/request_nonce", new
                {
                    ak_name = Convert.ToBase64String(akResult.AkName),
                });
            }
            catch (Exception ex) { return Fail($"HTTP /request_nonce: {ex.Message}"); }

            if (!nonceResp.IsSuccessStatusCode)
            {
                string err = await nonceResp.Content.ReadAsStringAsync();
                return Fail($"/request_nonce HTTP {(int)nonceResp.StatusCode}: {err}");
            }

            JsonElement nonceBody;
            try { nonceBody = await nonceResp.Content.ReadFromJsonAsync<JsonElement>(); }
            catch (Exception ex) { return Fail($"JSON: {ex.Message}"); }

            string quoteSid = nonceBody.GetProperty("quote_sid").GetString()!;
            byte[] nonce = Convert.FromBase64String(nonceBody.GetProperty("nonce").GetString()!);
            Console.WriteLine($"    quote_sid : {quoteSid[..8]}...");
            Console.WriteLine($"    nonce     : {Convert.ToHexString(nonce)[..16]}...");

            // ── Step 2: 读取 WBCL（优先 TBS API，失败回退到文件）────────────
            Console.WriteLine("[*] PCRVerify: 读取 WBCL...");
            byte[] wbcl;
            try { wbcl = ReadWbcl(tpm); }
            catch (Exception ex) { return Fail($"WBCL read: {ex.Message}"); }
            Console.WriteLine($"    WBCL: {wbcl.Length} bytes");

            // ── Step 3: TPM2_Quote（PCR 0-14, nonce 嵌入 extraData）──────────
            Console.WriteLine("[*] PCRVerify: TPM2_Quote (TPM 硬件)...");
            byte[] attestBytes;
            byte[] sigBytes;
            try
            {
                (attestBytes, sigBytes) = DoQuote(tpm, akResult.AkHandle, nonce);
            }
            catch (Exception ex) { return Fail($"TPM2_Quote: {ex.Message}"); }
            Console.WriteLine($"    attest: {attestBytes.Length} bytes  sig: {sigBytes.Length} bytes");

            // ── Step 4: 发送给服务端验证 ──────────────────────────────────────
            Console.WriteLine("[*] PCRVerify: POST /verify_quote...");
            HttpResponseMessage qResp;
            try
            {
                qResp = await http.PostAsJsonAsync("/verify_quote", new
                {
                    quote_sid = quoteSid,
                    attest = Convert.ToBase64String(attestBytes),
                    sig = Convert.ToBase64String(sigBytes),
                    wbcl = Convert.ToBase64String(wbcl),
                });
            }
            catch (Exception ex) { return Fail($"HTTP /verify_quote: {ex.Message}"); }

            JsonElement qBody;
            try { qBody = await qResp.Content.ReadFromJsonAsync<JsonElement>(); }
            catch (Exception ex) { return Fail($"JSON: {ex.Message}"); }

            // 解析响应
            string result = qBody.TryGetProperty("result", out var rv) ? rv.GetString() ?? "" : "";
            string reason = qBody.TryGetProperty("reason", out var rrv) ? rrv.GetString() ?? "" : "";
            bool sigValid = qBody.TryGetProperty("sig_valid", out var sv) && sv.GetBoolean();
            bool magicOk = qBody.TryGetProperty("magic_ok", out var mv) && mv.GetBoolean();
            bool nonceOk = qBody.TryGetProperty("nonce_ok", out var nov) && nov.GetBoolean();
            bool pcrMatch = qBody.TryGetProperty("pcr_match", out var pmv) && pmv.GetBoolean();

            var features = new List<SecurityFeatureInfo>();
            if (qBody.TryGetProperty("security_features", out var sf))
            {
                foreach (var el in sf.EnumerateArray())
                {
                    features.Add(new SecurityFeatureInfo
                    {
                        Name = el.TryGetProperty("name", out var n) ? n.GetString() ?? "" : "",
                        Status = el.TryGetProperty("status", out var s) ? s.GetString() ?? "" : "",
                        Evidence = el.TryGetProperty("evidence", out var ev) ? ev.GetString() ?? "" : "",
                        Detail = el.TryGetProperty("detail", out var d) ? d.GetString() ?? "" : "",
                    });
                }
            }

            bool success = result == "success";
            Console.WriteLine(success
                ? $"[✔] PCRVerify: ALL CHECKS PASSED"
                : $"[✘] PCRVerify: {reason}");

            PrintDetails(sigValid, magicOk, nonceOk, pcrMatch, features);

            return new PCRVerifyResult
            {
                Success = success,
                Reason = reason,
                SigValid = sigValid,
                MagicOk = magicOk,
                NonceOk = nonceOk,
                PcrMatch = pcrMatch,
                SecurityFeatures = features,
            };
        }

        // ── TPM2_Quote ────────────────────────────────────────────────────────

        static (byte[] attest, byte[] sig) DoQuote(Tpm2 tpm, TpmHandle akHandle, byte[] nonce)
        {
            var pcrSelBytes = new byte[3];
            foreach (var i in QuotedPcrs)
                pcrSelBytes[i / 8] |= (byte)(1 << (int)(i % 8));

            var pcrSel = new PcrSelection(TpmAlgId.Sha256, pcrSelBytes);

            // Quote 返回 Attest 对象，签名通过 out 参数
            Attest quoted = tpm.Quote(
                akHandle,
                qualifyingData: nonce,
                inScheme: new SchemeRsassa(TpmAlgId.Sha256),
                PCRselect: new[] { pcrSel },          // ← 直接 PcrSelection[]
                signature: out ISignatureUnion signature);

            // 把 Attest 序列化成字节（服务端需要 marshal 后的原始字节来验证签名）
            byte[] attestBytes = quoted.GetTpmRepresentation();

            byte[] sigBytes = ((SignatureRsassa)signature).sig;
            return (attestBytes, sigBytes);
        }

        // ── WBCL 读取（TBS API + 文件系统回退）───────────────────────────────

        static byte[] ReadWbcl(Tpm2 tpm)
        {
            // 优先通过 TBS API 读取（与 TPM 同一上下文）
            try
            {
                return ReadWbclViaTbs();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"    [!] TBS 读取失败 ({ex.Message})，回退到 MeasuredBoot 目录");
            }

            // 回退：读取 %SystemRoot%\Logs\MeasuredBoot\最新.log
            string sysRoot = Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows";
            string mbDir = Path.Combine(sysRoot, "Logs", "MeasuredBoot");
            var logs = Directory.GetFiles(mbDir, "*.log");
            if (logs.Length == 0)
                throw new FileNotFoundException($"MeasuredBoot 目录无 .log 文件: {mbDir}");
            Array.Sort(logs);
            string latest = logs[^1];
            Console.WriteLine($"    使用文件: {latest}");
            return File.ReadAllBytes(latest);
        }

        // TBS P/Invoke
        [StructLayout(LayoutKind.Sequential)]
        struct TbsContextParams2 { public uint version; public uint bitfield; }

        [DllImport("tbs.dll")] static extern uint Tbsi_Context_Create(ref TbsContextParams2 p, out IntPtr h);
        [DllImport("tbs.dll")] static extern uint Tbsi_Get_TCG_Log(IntPtr h, byte[]? buf, ref uint sz);
        [DllImport("tbs.dll")] static extern uint Tbsip_Context_Close(IntPtr h);

        const uint TBS_SUCCESS = 0x00000000;
        const uint TBS_E_BUFFER_TOO_SMALL = 0x80284008;

        static byte[] ReadWbclViaTbs()
        {
            var prm = new TbsContextParams2 { version = 2, bitfield = 0b100 };
            uint rc = Tbsi_Context_Create(ref prm, out IntPtr ctx);
            if (rc != TBS_SUCCESS)
                throw new InvalidOperationException($"Tbsi_Context_Create: 0x{rc:X8}");
            try
            {
                uint sz = 0;
                rc = Tbsi_Get_TCG_Log(ctx, null, ref sz);
                if (rc != TBS_SUCCESS && rc != TBS_E_BUFFER_TOO_SMALL)
                    throw new InvalidOperationException($"Tbsi_Get_TCG_Log size query: 0x{rc:X8}");
                if (sz == 0)
                    throw new InvalidOperationException("Tbsi_Get_TCG_Log returned sz=0");

                var buf = new byte[sz];
                rc = Tbsi_Get_TCG_Log(ctx, buf, ref sz);
                if (rc != TBS_SUCCESS)
                    throw new InvalidOperationException($"Tbsi_Get_TCG_Log read: 0x{rc:X8}");
                return buf[..(int)sz];
            }
            finally { Tbsip_Context_Close(ctx); }
        }

        // ── 输出辅助 ──────────────────────────────────────────────────────────

        static void PrintDetails(bool sigValid, bool magicOk, bool nonceOk, bool pcrMatch,
                                  List<SecurityFeatureInfo> features)
        {
            Console.WriteLine($"\n    ① AK 签名  : {(sigValid ? "✔ 有效" : "✘ 无效")}");
            Console.WriteLine($"    ② TPM magic: {(magicOk ? "✔ 0xFF544347" : "✘ 不匹配")}");
            Console.WriteLine($"    ③ nonce    : {(nonceOk ? "✔ 一致" : "✘ 不一致（疑似重放）")}");
            Console.WriteLine($"    ④ PCR重放  : {(pcrMatch ? "✔ 一致" : "✘ 不一致（WBCL可能被篡改）")}");

            if (features.Count == 0) return;
            Console.WriteLine("\n    ── 安全特性分析 ──────────────────────────────────");
            foreach (var f in features)
                Console.WriteLine(f.ToString());
        }

        static PCRVerifyResult Fail(string reason)
        {
            Console.WriteLine($"[✘] PCRVerify: {reason}");
            return new PCRVerifyResult { Success = false, Reason = reason };
        }
    }
}