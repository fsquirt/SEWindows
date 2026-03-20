using System;
using System.Net.Http;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Tasks;
using Tpm2Lib;

namespace SEWindows.RemoteVerify
{
    // ── 返回值 ─────────────────────────────────────────────────────────────────
    public class AKVerifyResult
    {
        public bool Success { get; init; }
        public string Reason { get; init; } = "";

        // 成功时保留的 TPM 句柄，供 PCRVerify 直接使用
        public TpmHandle AkHandle { get; init; } = TpmHandle.RhNull;
        public TpmHandle SrkHandle { get; init; } = TpmHandle.RhNull;
        public TpmHandle EkHandle { get; init; } = TpmHandle.RhNull;
        public byte[]? AkName { get; init; }
        public bool EkPersisted { get; init; }   // true → EK 是持久化 handle，不要 Flush

        /// <summary>流程结束后释放 TPM 上下文（仅在不再需要 AK 时调用）</summary>
        public void Cleanup(Tpm2 tpm)
        {
            tpm._AllowErrors().FlushContext(AkHandle);
            tpm._AllowErrors().FlushContext(SrkHandle);
            if (!EkPersisted)
                tpm._AllowErrors().FlushContext(EkHandle);
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    // AKVerify
    // ══════════════════════════════════════════════════════════════════════════
    public static class AKVerify
    {
        // RSA EK 默认 Policy = SHA256(PolicySecret(RH_ENDORSEMENT))
        static readonly byte[] EkPolicy = Convert.FromHexString(
            "837197674484b3f81a90cc8d46a5d724fd52d76e06520b64f2a1da1b331469aa");

        /// <summary>
        /// 执行完整的 MakeCredential / ActivateCredential 流程。
        ///
        /// 前提：EKVerify.RunAsync 已成功（服务端 valid_eks.txt 中已有该 EK 指纹）。
        ///       /make_credential 收到未注册的 EK 会返回 403，本函数会直接失败。
        ///
        /// 成功后：
        ///   - 服务端将 AK 公钥写入 valid_aks.txt
        ///   - 返回包含 AkHandle / AkName 的 result，供 PCRVerify 继续使用
        /// </summary>
        public static async Task<AKVerifyResult> RunAsync(Tpm2 tpm, HttpClient http)
        {
            // ── 1. EK ────────────────────────────────────────────────────────
            Console.WriteLine("[*] AKVerify: 初始化 EK...");
            var (ekHandle, ekPub, ekPersisted) = GetOrCreateEk(tpm);

            var ekModulus = ((Tpm2bPublicKeyRsa)ekPub.unique).buffer;
            using var rsaEk = RSA.Create();
            rsaEk.ImportParameters(new RSAParameters
            { Modulus = ekModulus, Exponent = [0x01, 0x00, 0x01] });
            byte[] ekDer = rsaEk.ExportSubjectPublicKeyInfo();

            // ── 2. SRK ───────────────────────────────────────────────────────
            Console.WriteLine("[*] AKVerify: 创建 SRK...");
            var srkHandle = CreateSrk(tpm);

            // ── 3. AK（受限签名密钥，Create + Load under SRK）───────────────
            Console.WriteLine("[*] AKVerify: 创建 AK...");
            var (akHandle, akPub, akName) = CreateAk(tpm, srkHandle);
            Console.WriteLine($"    AK Name : {Convert.ToHexString(akName)}");

            // 导出 AK 公钥 SubjectPublicKeyInfo DER（发给服务端用于注册和签名验证）
            var akModulus = ((Tpm2bPublicKeyRsa)akPub.unique).buffer;
            using var rsaAk = RSA.Create();
            rsaAk.ImportParameters(new RSAParameters
            { Modulus = akModulus, Exponent = [0x01, 0x00, 0x01] });
            byte[] akDer = rsaAk.ExportSubjectPublicKeyInfo();

            // ── 4. 请求服务端 MakeCredential ─────────────────────────────────
            //       服务端会校验 EK 指纹是否在 valid_eks.txt 中；未注册返回 403
            Console.WriteLine("[*] AKVerify: POST /make_credential...");
            HttpResponseMessage mcResp;
            try
            {
                mcResp = await http.PostAsJsonAsync("/make_credential", new
                {
                    ek_pub = Convert.ToBase64String(ekDer),
                    ak_name = Convert.ToBase64String(akName),
                });
            }
            catch (Exception ex)
            {
                return Fail(tpm, ekHandle, srkHandle, akHandle, ekPersisted,
                            $"HTTP /make_credential: {ex.Message}");
            }

            if (!mcResp.IsSuccessStatusCode)
            {
                // 最常见原因：EK 未注册（403），说明 EKVerify 尚未执行或失败
                string err = await mcResp.Content.ReadAsStringAsync();
                return Fail(tpm, ekHandle, srkHandle, akHandle, ekPersisted,
                            $"/make_credential HTTP {(int)mcResp.StatusCode}: {err}");
            }

            JsonElement mcBody;
            try { mcBody = await mcResp.Content.ReadFromJsonAsync<JsonElement>(); }
            catch (Exception ex) { return Fail(tpm, ekHandle, srkHandle, akHandle, ekPersisted, $"JSON: {ex.Message}"); }

            string sessionId = mcBody.GetProperty("session_id").GetString()!;
            byte[] credBlob = Convert.FromBase64String(mcBody.GetProperty("credential_blob").GetString()!);
            byte[] encSecret = Convert.FromBase64String(mcBody.GetProperty("encrypted_secret").GetString()!);
            Console.WriteLine($"    session_id      : {sessionId[..8]}...");
            Console.WriteLine($"    credential_blob : {credBlob.Length} bytes");
            Console.WriteLine($"    encrypted_secret: {encSecret.Length} bytes");

            // ── 5. TPM2_ActivateCredential（在 TPM 硬件内部执行）────────────
            Console.WriteLine("[*] AKVerify: TPM2_ActivateCredential (TPM 硬件)...");
            byte[] recoveredSecret;
            try
            {
                recoveredSecret = ActivateCredential(tpm, akHandle, ekHandle, credBlob, encSecret);
            }
            catch (Exception ex)
            {
                return Fail(tpm, ekHandle, srkHandle, akHandle, ekPersisted,
                            $"ActivateCredential: {ex.Message}");
            }
            Console.WriteLine($"    恢复的 secret: {Convert.ToHexString(recoveredSecret)}");

            // ── 6. 将 secret + AK 公钥发回服务端验证，服务端注册 AK ──────────
            Console.WriteLine("[*] AKVerify: POST /verify...");
            HttpResponseMessage vResp;
            try
            {
                vResp = await http.PostAsJsonAsync("/verify", new
                {
                    session_id = sessionId,
                    secret = Convert.ToBase64String(recoveredSecret),
                    ak_pub = Convert.ToBase64String(akDer),   // ← 服务端用于注册 AK
                });
            }
            catch (Exception ex)
            {
                return Fail(tpm, ekHandle, srkHandle, akHandle, ekPersisted,
                            $"HTTP /verify: {ex.Message}");
            }

            JsonElement vBody;
            try { vBody = await vResp.Content.ReadFromJsonAsync<JsonElement>(); }
            catch (Exception ex) { return Fail(tpm, ekHandle, srkHandle, akHandle, ekPersisted, $"JSON: {ex.Message}"); }

            string vResult = vBody.TryGetProperty("result", out var rv) ? rv.GetString() ?? "" : "";
            if (vResult != "success")
            {
                string vReason = vBody.TryGetProperty("reason", out var rr) ? rr.GetString() ?? "" : "";
                return Fail(tpm, ekHandle, srkHandle, akHandle, ekPersisted,
                            $"/verify: {vReason}");
            }

            Console.WriteLine("[✔] AKVerify: AK ActivateCredential 成功，已注册至服务端");
            // ★ 不 Flush 句柄，返回给调用方（PCRVerify 需要用）
            return new AKVerifyResult
            {
                Success = true,
                AkHandle = akHandle,
                SrkHandle = srkHandle,
                EkHandle = ekHandle,
                AkName = akName,
                EkPersisted = ekPersisted,
            };
        }

        // ── 私有辅助 ──────────────────────────────────────────────────────────

        static AKVerifyResult Fail(Tpm2 tpm, TpmHandle ek, TpmHandle srk, TpmHandle ak,
                                   bool ekP, string reason)
        {
            tpm._AllowErrors().FlushContext(ak);
            tpm._AllowErrors().FlushContext(srk);
            if (!ekP) tpm._AllowErrors().FlushContext(ek);
            Console.WriteLine($"[✘] AKVerify: {reason}");
            return new AKVerifyResult { Success = false, Reason = reason };
        }

        static (TpmHandle handle, TpmPublic pub, bool persisted) GetOrCreateEk(Tpm2 tpm)
        {
            var persistent = TpmHandle.Persistent(0x81010001);
            var pub = tpm._AllowErrors().ReadPublic(persistent, out _, out _);
            if (tpm._GetLastResponseCode() == TpmRc.Success)
            {
                Console.WriteLine("    使用持久化 EK @ 0x81010001");
                return (persistent, pub, true);
            }
            var t = new TpmPublic(TpmAlgId.Sha256,
                ObjectAttr.FixedTPM | ObjectAttr.FixedParent | ObjectAttr.SensitiveDataOrigin |
                ObjectAttr.AdminWithPolicy | ObjectAttr.Restricted | ObjectAttr.Decrypt,
                EkPolicy,
                new RsaParms(new SymDefObject(TpmAlgId.Aes, 128, TpmAlgId.Cfb),
                             new NullAsymScheme(), 2048, 0),
                new Tpm2bPublicKeyRsa(new byte[256]));
            var h = tpm.CreatePrimary(TpmHandle.RhEndorsement, new SensitiveCreate(), t,
                Array.Empty<byte>(), Array.Empty<PcrSelection>(),
                out TpmPublic ekPub, out _, out _, out _);
            Console.WriteLine("    创建瞬态 EK");
            return (h, ekPub, false);
        }

        static TpmHandle CreateSrk(Tpm2 tpm)
        {
            var t = new TpmPublic(TpmAlgId.Sha256,
                ObjectAttr.Restricted | ObjectAttr.Decrypt | ObjectAttr.FixedTPM |
                ObjectAttr.FixedParent | ObjectAttr.SensitiveDataOrigin | ObjectAttr.UserWithAuth,
                Array.Empty<byte>(),
                new RsaParms(new SymDefObject(TpmAlgId.Aes, 128, TpmAlgId.Cfb),
                             new NullAsymScheme(), 2048, 0),
                new Tpm2bPublicKeyRsa(new byte[256]));
            return tpm.CreatePrimary(TpmHandle.RhOwner, new SensitiveCreate(), t,
                Array.Empty<byte>(), Array.Empty<PcrSelection>(),
                out _, out _, out _, out _);
        }

        static (TpmHandle, TpmPublic, byte[]) CreateAk(Tpm2 tpm, TpmHandle srk)
        {
            var t = new TpmPublic(TpmAlgId.Sha256,
                ObjectAttr.Restricted | ObjectAttr.Sign | ObjectAttr.FixedTPM |
                ObjectAttr.FixedParent | ObjectAttr.SensitiveDataOrigin | ObjectAttr.UserWithAuth,
                Array.Empty<byte>(),
                new RsaParms(new SymDefObject(TpmAlgId.Null, 0, TpmAlgId.Null),
                             new SchemeRsassa(TpmAlgId.Sha256), 2048, 0),
                new Tpm2bPublicKeyRsa(new byte[256]));
            TpmPrivate priv = tpm.Create(srk, new SensitiveCreate(), t,
                Array.Empty<byte>(), Array.Empty<PcrSelection>(),
                out TpmPublic pub, out _, out _, out _);
            var h = tpm.Load(srk, priv, pub);
            tpm.ReadPublic(h, out byte[] name, out _);
            return (h, pub, name);
        }

        static byte[] ActivateCredential(Tpm2 tpm, TpmHandle ak, TpmHandle ek,
                                          byte[] credBlob, byte[] encSecret)
        {
            AuthSession polSess = tpm.StartAuthSessionEx(TpmSe.Policy, TpmAlgId.Sha256);
            try
            {
                tpm.PolicySecret(TpmHandle.RhEndorsement, polSess.Handle,
                    Array.Empty<byte>(), Array.Empty<byte>(), Array.Empty<byte>(), 0, out _);

                ushort hmacLen = (ushort)((credBlob[0] << 8) | credBlob[1]);
                byte[] intg = new byte[hmacLen];
                Array.Copy(credBlob, 2, intg, 0, hmacLen);
                byte[] encId = new byte[credBlob.Length - 2 - hmacLen];
                Array.Copy(credBlob, 2 + hmacLen, encId, 0, encId.Length);

                return tpm[null, polSess]
                    .ActivateCredential(ak, ek, new IdObject(intg, encId), encSecret);
            }
            finally { tpm._AllowErrors().FlushContext(polSess.Handle); }
        }
    }
}