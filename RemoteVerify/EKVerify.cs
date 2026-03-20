using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace SEWindows.RemoteVerify
{
    // ── 返回值 ─────────────────────────────────────────────────────────────────
    public class EKVerifyResult
    {
        public bool Success { get; init; }
        public string Reason { get; init; } = "";
        /// <summary>服务端 valid_eks.txt 中写入的 EK 指纹（成功时有值）</summary>
        public string EkFingerprint { get; init; } = "";
    }

    // ══════════════════════════════════════════════════════════════════════════
    // EKVerify
    // ══════════════════════════════════════════════════════════════════════════
    public static class EKVerify
    {
        /// <summary>
        /// 从注册表读取 EK 证书链，发送至服务端 /verify_chain 验证。
        /// 成功后服务端将 EK 指纹写入 valid_eks.txt。
        /// </summary>
        /// <returns>EKVerifyResult.Success == true 表示 EK 已通过验证并注册。</returns>
        public static async Task<EKVerifyResult> RunAsync(HttpClient http)
        {
            var allCerts = new List<(string src, byte[] der)>();

            ReadBlobsUnder(
                @"SYSTEM\CurrentControlSet\Services\TPM\WMI\Endorsement\EKCertStore\Certificates",
                allCerts);
            ReadBlobsUnder(
                @"SYSTEM\CurrentControlSet\Services\TPM\WMI\Endorsement\IntermediateCACertStore\Certificates",
                allCerts);

            Console.WriteLine($"[*] EKVerify: 共找到 {allCerts.Count} 张证书（含重复）");

            // 去重，leaf 保持在前
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var unique = new List<byte[]>();
            foreach (var (_, der) in allCerts)
            {
                X509Certificate2 cert;
                try { cert = new X509Certificate2(der); }
                catch { continue; }
                if (!seen.Add(cert.Thumbprint)) continue;
                Console.WriteLine($"    [{unique.Count}] {cert.Subject[..Math.Min(60, cert.Subject.Length)]}");
                unique.Add(der);
            }

            if (unique.Count == 0)
                return new EKVerifyResult { Success = false, Reason = "no usable certs in registry" };

            // 发送至服务端
            var b64 = unique.ConvertAll(Convert.ToBase64String);
            var json = JsonSerializer.Serialize(new { certs = b64 });

            HttpResponseMessage resp;
            try
            {
                using var content = new StringContent(json, Encoding.UTF8, "application/json");
                resp = await http.PostAsync("/verify_chain", content);
            }
            catch (Exception ex)
            {
                return new EKVerifyResult { Success = false, Reason = $"HTTP error: {ex.Message}" };
            }

            JsonElement body;
            try
            {
                body = await resp.Content.ReadAsJsonAsync<JsonElement>();
            }
            catch (Exception ex)
            {
                return new EKVerifyResult { Success = false, Reason = $"JSON parse: {ex.Message}" };
            }

            string result = body.TryGetProperty("result", out var rv) ? rv.GetString() ?? "" : "";
            string reason = body.TryGetProperty("reason", out var rrv) ? rrv.GetString() ?? "" : "";
            string fp = body.TryGetProperty("ek_fingerprint", out var fv) ? fv.GetString() ?? "" : "";

            if (body.TryGetProperty("chain", out var chain))
            {
                int i = 0;
                foreach (var el in chain.EnumerateArray())
                    Console.WriteLine($"    chain[{i++}] {el.GetString()}");
            }

            if (result == "success")
            {
                Console.WriteLine($"[✔] EKVerify: EK 验证并注册成功  fp={fp[..16]}...");
                return new EKVerifyResult { Success = true, EkFingerprint = fp };
            }

            Console.WriteLine($"[✘] EKVerify: {reason}");
            return new EKVerifyResult { Success = false, Reason = reason };
        }

        // ── 注册表 Blob 读取（保持原有逻辑）────────────────────────────────────

        static void ReadBlobsUnder(string regPath, List<(string, byte[])> result)
        {
            using var key = Registry.LocalMachine.OpenSubKey(regPath);
            if (key == null)
            {
                Console.WriteLine($"[!] 不存在: HKLM\\{regPath}");
                return;
            }
            foreach (string thumb in key.GetSubKeyNames())
            {
                using var ck = key.OpenSubKey(thumb);
                if (ck == null) continue;
                foreach (string vn in ck.GetValueNames())
                {
                    if (ck.GetValue(vn) is not byte[] data || data.Length < 4) continue;
                    foreach (var c in ParseDerBlob(data))
                        result.Add(($@"HKLM\{regPath}\{thumb}@{vn}", c.RawData));
                }
            }
        }

        static List<X509Certificate2> ParseDerBlob(byte[] data)
        {
            var out_ = new List<X509Certificate2>();

            // 如果不以 0x30 开头，先尝试 Windows CERT_PROP 格式
            if (data.Length > 12 && data[0] != 0x30)
            {
                var p = TryParseWinProps(data);
                if (p.Count > 0) return p;
            }

            int pos = 0;
            while (pos < data.Length - 4)
            {
                if (data[pos] != 0x30) { pos++; continue; }
                int hLen, len;
                if (data[pos + 1] < 0x80)
                {
                    len = data[pos + 1]; hLen = 2;
                }
                else
                {
                    int nb = data[pos + 1] & 0x7F;
                    if (pos + 2 + nb > data.Length) break;
                    len = 0;
                    for (int i = 0; i < nb; i++) len = (len << 8) | data[pos + 2 + i];
                    hLen = 2 + nb;
                }
                int total = hLen + len;
                if (pos + total > data.Length) break;
                try
                {
                    var der = new byte[total];
                    Array.Copy(data, pos, der, 0, total);
                    out_.Add(new X509Certificate2(der));
                }
                catch { }
                pos += total;
            }
            return out_;
        }

        static List<X509Certificate2> TryParseWinProps(byte[] data)
        {
            const uint CERT_CERT_PROP_ID = 32;
            var out_ = new List<X509Certificate2>();
            int pos = 0;
            while (pos + 12 <= data.Length)
            {
                uint propId = BitConverter.ToUInt32(data, pos);
                uint cbData = BitConverter.ToUInt32(data, pos + 8);
                pos += 12;
                if (cbData == 0) continue;
                if (pos + cbData > data.Length) break;
                if (propId == CERT_CERT_PROP_ID)
                {
                    var der = new byte[cbData];
                    Array.Copy(data, pos, der, 0, (int)cbData);
                    try { out_.Add(new X509Certificate2(der)); } catch { }
                }
                pos += (int)cbData;
            }
            return out_;
        }
    }

    // ── HttpContent 扩展辅助 ───────────────────────────────────────────────────
    internal static class HttpContentExt
    {
        internal static async Task<T> ReadAsJsonAsync<T>(this HttpContent content)
        {
            var stream = await content.ReadAsStreamAsync();
            return await System.Text.Json.JsonSerializer.DeserializeAsync<T>(stream)
                   ?? throw new InvalidOperationException("null JSON");
        }
    }
}