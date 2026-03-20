using System;
using System.Net.Http;
using System.Threading.Tasks;
using Tpm2Lib;

namespace SEWindows.RemoteVerify
{
    // ── 最终汇总结果 ───────────────────────────────────────────────────────────
    public class AttestationResult
    {
        public bool Success { get; init; }
        public string Reason { get; init; } = "";
        public EKVerifyResult? EkResult { get; init; }
        public AKVerifyResult? AkResult { get; init; }
        public PCRVerifyResult? PcrResult { get; init; }
    }

    // ══════════════════════════════════════════════════════════════════════════
    // RemoteAttestation  —  完整远程验证流程串联
    // ══════════════════════════════════════════════════════════════════════════
    public static class RemoteAttestation
    {
        /// <summary>
        /// 一次性执行完整的 TPM 远程验证。
        ///
        /// 调用顺序：
        ///   Step 1  EKVerify.RunAsync   — 读取注册表 EK 证书链 → /verify_chain
        ///                                  成功后 EK 指纹写入 valid_eks.txt
        ///   Step 2  AKVerify.RunAsync   — MakeCredential / ActivateCredential
        ///                                  成功后 AK 公钥写入 valid_aks.txt
        ///   Step 3  PCRVerify.RunAsync  — TPM2_Quote + WBCL Replay → /verify_quote
        ///                                  返回四步验证结果 + 安全特性分析
        ///
        /// 任意一步失败则立即返回，不继续执行后续步骤。
        /// </summary>
        /// <param name="serverBase">服务端地址，如 "http://localhost:5000"</param>
        public static async Task<AttestationResult> RunAsync(string serverBase = "http://localhost:5000")
        {
            using var http = new HttpClient { BaseAddress = new Uri(serverBase) };
            using var device = new TbsDevice();
            device.Connect();
            using var tpm = new Tpm2(device);

            // ── Step 1: EK 验证 ───────────────────────────────────────────────
            Console.WriteLine("\n══════ Step 1/3  EK 证书链验证 ═════════════════════");
            var ekResult = await EKVerify.RunAsync(http);
            if (!ekResult.Success)
            {
                return new AttestationResult
                {
                    Success = false,
                    Reason = $"EKVerify failed: {ekResult.Reason}",
                    EkResult = ekResult,
                };
            }

            Thread.Sleep(1000);
            // ── Step 2: AK 验证（MakeCredential / ActivateCredential）────────
            Console.WriteLine("\n══════ Step 2/3  AK MakeCredential 验证 ════════════");
            var akResult = await AKVerify.RunAsync(tpm, http);
            if (!akResult.Success)
            {
                return new AttestationResult
                {
                    Success = false,
                    Reason = $"AKVerify failed: {akResult.Reason}",
                    EkResult = ekResult,
                    AkResult = akResult,
                };
            }

            Thread.Sleep(1000);
            // ── Step 3: PCR Quote 验证 ────────────────────────────────────────
            Console.WriteLine("\n══════ Step 3/3  PCR Quote 远程验证 ════════════════");
            PCRVerifyResult pcrResult;
            try
            {
                pcrResult = await PCRVerify.RunAsync(tpm, http, akResult);
            }
            finally
            {
                // 无论 PCRVerify 成功与否，都要释放 TPM 句柄
                akResult.Cleanup(tpm);
            }

            Thread.Sleep(1000);
            // ── 最终结果汇总 ──────────────────────────────────────────────────
            Console.WriteLine($"  EK 验证      : {(ekResult.Success ? "✔ 通过" : "✘ 失败")}");
            Console.WriteLine($"  AK 验证      : {(akResult.Success ? "✔ 通过" : "✘ 失败")}");
            Console.WriteLine($"  PCR Replay   : {(pcrResult.PcrMatch ? "✔ 一致" : "✘ 不一致")}");
            Console.WriteLine($"  总体结果     : {(pcrResult.Success ? "✔ 可信" : "✘ 不可信")}");
            if (!pcrResult.Success)
                Console.WriteLine($"  原因         : {pcrResult.Reason}");

            return new AttestationResult
            {
                Success = pcrResult.Success,
                Reason = pcrResult.Reason,
                EkResult = ekResult,
                AkResult = akResult,
                PcrResult = pcrResult,
            };
        }

        // ══════════════════════════════════════════════════════════════════════
        //   分步调用（而非一次性 RunAsync）
        //
        //   var http   = new HttpClient { BaseAddress = new Uri("http://localhost:5000") };
        //   var device = new TbsDevice(); device.Connect();
        //   var tpm    = new Tpm2(device);
        //
        //   // Step 1 - EK
        //   var ekResult = await EKVerify.RunAsync(http);
        //   if (!ekResult.Success) { /* 处理失败 */ return; }
        //
        //   // Step 2 - AK（要求 Step 1 已成功，服务端 valid_eks.txt 已有 EK）
        //   var akResult = await AKVerify.RunAsync(tpm, http);
        //   if (!akResult.Success) { /* 处理失败 */ return; }
        //
        //   // Step 3 - PCR Quote（要求 Step 2 已成功，akResult 中保有 TPM 句柄）
        //   var pcrResult = await PCRVerify.RunAsync(tpm, http, akResult);
        //   akResult.Cleanup(tpm);   // 释放 TPM 句柄
        //
        //   Console.WriteLine($"PCR 验证: {(pcrResult.Success ? "通过" : "失败")}");
        //   foreach (var f in pcrResult.SecurityFeatures)
        //       Console.WriteLine(f);
        // ══════════════════════════════════════════════════════════════════════
    }
}