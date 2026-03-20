import os, struct, hmac as hmac_lib, hashlib, secrets, base64, json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional

from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from asn1crypto import x509 as asn1_x509

app = Flask(__name__)

# 会话字典（内存）
_mc_sessions: dict[str, dict]    = {}   # make_credential 会话
_quote_sessions: dict[str, dict] = {}   # PCR quote nonce 会话

# 配置
TRUSTED_ROOT_DIR = Path(os.environ.get("TRUSTED_ROOT_DIR",r"C:\Users\32630\Desktop\TrustTPMCA"))
VALID_EKS_FILE   = Path(os.environ.get("VALID_EKS_FILE",  "valid_eks.txt"))
VALID_AKS_FILE   = Path(os.environ.get("VALID_AKS_FILE",  "valid_aks.txt"))


# ═══════════════════════════════════════════════════════════════════════════════
# 一、EK / AK 本地存储（JSON Lines）
# ═══════════════════════════════════════════════════════════════════════════════

def _load_records(path: Path) -> list[dict]:
    if not path.exists():
        return []
    records = []
    for ln in path.read_text("utf-8").splitlines():
        ln = ln.strip()
        if ln:
            try:
                records.append(json.loads(ln))
            except Exception:
                pass
    return records


def _append_record(path: Path, rec: dict) -> None:
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def _ek_fingerprint(spki_der: bytes) -> str:
    """EK 指纹 = SHA-256(SubjectPublicKeyInfo DER) hex"""
    return hashlib.sha256(spki_der).hexdigest()


def is_ek_registered(fp: str) -> bool:
    return any(r.get("fingerprint") == fp for r in _load_records(VALID_EKS_FILE))


def get_ak_record(ak_name_hex: str) -> Optional[dict]:
    for r in _load_records(VALID_AKS_FILE):
        if r.get("ak_name") == ak_name_hex:
            return r
    return None


def store_ek(fp: str, subject: str) -> None:
    if is_ek_registered(fp):
        return
    _append_record(VALID_EKS_FILE, {
        "fingerprint": fp,
        "subject":     subject,
        "ts":          datetime.now(timezone.utc).isoformat(),
    })
    print(f"[+] EK 已注册: {fp[:16]}... ({subject[:60]})")


def store_ak(ak_name_hex: str, ak_pub_b64: str, ek_fp: str) -> None:
    if get_ak_record(ak_name_hex):
        print(f"[*] AK 已存在: {ak_name_hex[:16]}...")
        return
    _append_record(VALID_AKS_FILE, {
        "ak_name":        ak_name_hex,
        "ak_pub":         ak_pub_b64,
        "ek_fingerprint": ek_fp,
        "ts":             datetime.now(timezone.utc).isoformat(),
    })
    print(f"[+] AK 已注册: {ak_name_hex[:16]}...")


# ═══════════════════════════════════════════════════════════════════════════════
# 二、TPM2 KDFa + 软件 MakeCredential（原有，保持不变）
# ═══════════════════════════════════════════════════════════════════════════════

def kdfa(key: bytes, label: str, ctx_u: bytes, ctx_v: bytes, bits: int) -> bytes:
    label_b = label.encode() + b"\x00"
    bits_b  = struct.pack(">I", bits)
    out, i  = b"", 1
    while len(out) * 8 < bits:
        msg = struct.pack(">I", i) + label_b + ctx_u + ctx_v + bits_b
        out += hmac_lib.new(key, msg, hashlib.sha256).digest()
        i   += 1
    return out[:bits // 8]


def make_credential(ek_pub, ak_name: bytes, credential: bytes) -> tuple[bytes, bytes]:
    seed = secrets.token_bytes(32)
    encrypted_secret = ek_pub.encrypt(
        seed,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=b"IDENTITY\x00"))
    sym_key      = kdfa(seed, "STORAGE",   ak_name, b"", 128)
    plaintext    = struct.pack(">H", len(credential)) + credential
    enc_obj      = Cipher(algorithms.AES(sym_key), modes.CFB(bytes(16))).encryptor()
    enc_identity = enc_obj.update(plaintext) + enc_obj.finalize()
    hmac_key     = kdfa(seed, "INTEGRITY", b"", b"", 256)
    integrity    = hmac_lib.new(hmac_key, enc_identity + ak_name, hashlib.sha256).digest()
    credential_blob = struct.pack(">H", len(integrity)) + integrity + enc_identity
    return credential_blob, encrypted_secret


# ═══════════════════════════════════════════════════════════════════════════════
# 三、证书链验证辅助（原有，保持不变）
# ═══════════════════════════════════════════════════════════════════════════════

def _load_der_lenient(der: bytes) -> Optional[asn1_x509.Certificate]:
    try:
        return asn1_x509.Certificate.load(der)
    except Exception as e:
        print(f"[-] 证书解析失败: {e}")
        return None


def _cert_names(cert: asn1_x509.Certificate) -> tuple[bytes, bytes, str]:
    tbs  = cert["tbs_certificate"]
    subj = tbs["subject"].dump()
    iss  = tbs["issuer"].dump()
    return subj, iss, cert.subject.human_friendly


def _cert_spki(cert: asn1_x509.Certificate) -> bytes:
    return cert["tbs_certificate"]["subject_public_key_info"].dump()


def _load_root_pool() -> list[asn1_x509.Certificate]:
    pool: list[asn1_x509.Certificate] = []
    if not TRUSTED_ROOT_DIR.is_dir():
        return pool
    for fname in TRUSTED_ROOT_DIR.iterdir():
        if fname.suffix.lower() not in (".cer", ".crt", ".pem", ".der"):
            continue
        try:
            data = fname.read_bytes()
            if b"-----BEGIN CERTIFICATE-----" in data:
                data = base64.b64decode(
                    "".join(l for l in data.decode().splitlines()
                            if not l.startswith("-----")))
            c = _load_der_lenient(data)
            if c:
                pool.append(c)
        except Exception:
            pass
    return pool


def build_chain(certs: list[asn1_x509.Certificate],
                extra_pool: list[asn1_x509.Certificate]) -> tuple[bool, list[str], str]:
    all_pool = list(certs[1:]) + extra_pool
    current  = certs[0]
    chain    = []
    for _ in range(20):
        subj, iss, name = _cert_names(current)
        chain.append(name)
        if subj == iss:
            return True, chain, "ok"
        found = next((c for c in all_pool if _cert_names(c)[0] == iss), None)
        if not found:
            return False, chain, f"chain broken: issuer not found for [{name}]"
        current = found
    return False, chain, "chain too deep (> 20)"


# ═══════════════════════════════════════════════════════════════════════════════
# 四、TCG2 事件日志解析 + PCR Replay
# ═══════════════════════════════════════════════════════════════════════════════

ALG_META: dict[int, tuple[str, int]] = {
    0x0004: ("sha1",   20),
    0x000B: ("sha256", 32),
    0x000C: ("sha384", 48),
    0x000D: ("sha512", 64),
}
EV_NO_ACTION    = 0x00000003
EV_SEPARATOR    = 0x00000004
EV_EFI_VAR_CFG  = 0x80000001
EV_EFI_VAR_BOOT = 0x80000002
EV_EFI_GPT_EVENT = 0x80000006
EV_EFI_BLOB     = 0x80000008
EV_EFI_HANDOFF  = 0x80000009
EV_EFI_BLOB2    = 0x8000000A
EV_EFI_HANDOFF2 = 0x8000000B
EV_EFI_VAR_AUTH = 0x800000E0
EV_EFI_SPDM_FIRMWARE_BLOB = 0x800000E1
EV_EFI_SPDM_FIRMWARE_CONFIG = 0x800000E2
EV_EFI_SPDM_DEVICE_POLICY = 0x800000E3
EV_EFI_SPDM_DEVICE_AUTHORITY = 0x800000E4
EV_COMPACT_HASH = 0x0000000C

EFI_GLOBAL_GUID = (0x8BE4DF61, 0x93CA, 0x11D2,
                   bytes([0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C]))


@dataclass
class _EvRec:
    index: int; pcr: int; etype: int
    digests: dict[int, bytes]; data: bytes


@dataclass
class _ParseResult:
    alg_ids: list[int]; dsizes: dict[int, int]
    events: list[_EvRec]; errors: list[str] = field(default_factory=list)


class _WBCLParser:
    SPEC_SIG = b"Spec ID Event03\x00"

    def parse(self, raw: bytes) -> _ParseResult:
        if len(raw) < 32:
            raise ValueError("数据太短")
        pos = 0
        _, etype = struct.unpack_from("<II", raw, pos); pos += 8
        pos += 20
        esz, = struct.unpack_from("<I", raw, pos); pos += 4
        spec = raw[pos:pos + esz]; pos += esz
        if etype != EV_NO_ACTION:
            raise ValueError(f"首事件非 EV_NO_ACTION: 0x{etype:08X}")
        alg_ids, dsizes = self._spec(spec)
        events, errors, idx = [], [], 0
        while pos < len(raw):
            if pos + 8 > len(raw):
                break
            try:
                rec, pos = self._ev2(raw, pos, idx, alg_ids, dsizes)
                events.append(rec); idx += 1
            except Exception as e:
                errors.append(f"0x{pos:X}: {e}"); break
        return _ParseResult(alg_ids, dsizes, events, errors)

    def _spec(self, raw: bytes):
        if raw[:16] != self.SPEC_SIG:
            raise ValueError("SPEC_ID 签名不匹配")
        pos = 24
        num, = struct.unpack_from("<I", raw, pos); pos += 4
        alg_ids, dsizes = [], {}
        for _ in range(num):
            aid, dsz = struct.unpack_from("<HH", raw, pos); pos += 4
            alg_ids.append(aid); dsizes[aid] = dsz
        return alg_ids, dsizes

    def _ev2(self, raw, pos, idx, alg_ids, dsizes):
        pcr, etype = struct.unpack_from("<II", raw, pos); pos += 8
        cnt, = struct.unpack_from("<I", raw, pos); pos += 4
        digests = {}
        for _ in range(cnt):
            aid, = struct.unpack_from("<H", raw, pos); pos += 2
            dsz = dsizes.get(aid)
            if dsz is None:
                raise ValueError(f"未知算法 0x{aid:04X}")
            digests[aid] = raw[pos:pos + dsz]; pos += dsz
        esz, = struct.unpack_from("<I", raw, pos); pos += 4
        edata = raw[pos:pos + esz]; pos += esz
        return _EvRec(idx, pcr, etype, digests, edata), pos


class _PCRBank:
    def __init__(self, alg_id: int):
        name, dsz = ALG_META.get(alg_id, (f"alg_{alg_id:04x}", 32))
        self.alg_id = alg_id; self.name = name; self.dsz = dsz
        self.pcrs = [bytes(dsz)] * 24
        try:
            hashlib.new(name); self.ok = True
        except ValueError:
            self.ok = False

    def extend(self, pcr: int, digest: bytes) -> None:
        if not self.ok:
            return
        h = hashlib.new(self.name)
        h.update(self.pcrs[pcr]); h.update(digest)
        self.pcrs[pcr] = h.digest()


def _replay(pr: _ParseResult) -> dict[int, _PCRBank]:
    banks = {a: _PCRBank(a) for a in pr.alg_ids}
    for ev in pr.events:
        if ev.etype == EV_NO_ACTION:
            continue
        for aid, digest in ev.digests.items():
            if aid in banks:
                banks[aid].extend(ev.pcr, digest)
    return banks


def _compute_pcr_digest(banks: dict[int, _PCRBank],
                        selections: list[dict]) -> Optional[bytes]:
    """
    根据 TPM Quote 中的 PCR selection 计算服务端预期的 pcrDigest。
    pcrDigest = Hash( PCR[i0] || PCR[i1] || ... )
    """
    if not selections:
        return None
    sel    = selections[0]
    alg_id = sel["hash_alg"]
    bank   = banks.get(alg_id)
    if bank is None or not bank.ok:
        return None
    concat   = b"".join(bank.pcrs[i] for i in sorted(sel["pcr_indices"]))
    alg_name = ALG_META.get(alg_id, (f"alg_{alg_id:04x}", 32))[0]
    return hashlib.new(alg_name, concat).digest()


# ═══════════════════════════════════════════════════════════════════════════════
# 五、SIPAEVENT 解析（PCR 12/13/14 内嵌 Windows WBCL TLV）
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class _SipaEv:
    eid: int; data: bytes; pcr: int; idx: int

    @property
    def u8(self):  return self.data[0] if self.data else 0
    @property
    def u32(self): return struct.unpack_from("<I", self.data)[0] if len(self.data) >= 4 else self.u8
    @property
    def u64(self): return struct.unpack_from("<Q", self.data)[0] if len(self.data) >= 8 else self.u32


def _sipa_tlvs(raw: bytes, pcr: int, idx: int) -> list[_SipaEv]:
    out, pos = [], 0
    while pos + 8 <= len(raw):
        eid, dsz = struct.unpack_from("<II", raw, pos); pos += 8
        payload = raw[pos:pos + dsz]; pos += dsz
        out.append(_SipaEv(eid, payload, pcr, idx))
        if eid == 0x40010001:           # Win11 V2 aggregation container
            out.extend(_sipa_tlvs(payload, pcr, idx))
    return out


def _parse_sipa(pr: _ParseResult) -> list[_SipaEv]:
    out = []
    for ev in pr.events:
        if ev.pcr in (12, 13, 14) and len(ev.data) >= 8:
            out.extend(_sipa_tlvs(ev.data, ev.pcr, ev.index))
    return out


def _s1(sipa, *ids): return next((e for e in sipa if e.eid in ids), None)
def _sall(sipa, *ids): return [e for e in sipa if e.eid in ids]


# ═══════════════════════════════════════════════════════════════════════════════
# 六、EFI 变量解析辅助
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class _EfiVar:
    guid: tuple; name: str; data: bytes

    @property
    def is_global(self): return self.guid == EFI_GLOBAL_GUID


def _parse_efi_var(raw: bytes) -> Optional[_EfiVar]:
    if not raw or len(raw) < 32:
        return None
    try:
        d1, d2, d3 = struct.unpack_from("<IHH", raw, 0)
        d4 = bytes(raw[8:16])
        nl, dl = struct.unpack_from("<QQ", raw, 16)
        nb = int(nl) * 2
        if 32 + nb > len(raw):
            return None
        name = raw[32:32 + nb].decode("utf-16-le").rstrip("\x00")
        do = 32 + nb
        return _EfiVar((d1, d2, d3, d4), name, raw[do:min(do + int(dl), len(raw))])
    except Exception:
        return None


def _blob2_name(raw: bytes) -> str:
    if not raw or len(raw) < 2:
        return ""
    nl = raw[0]
    return raw[1:1 + nl].decode("utf-8", errors="replace").rstrip("\x00") \
        if nl and nl + 1 <= len(raw) else ""


def _blob_name(raw: bytes) -> str:
    """解析 EV_EFI_PLATFORM_FIRMWARE_BLOB (旧版 0x80000008)"""
    if not raw or len(raw) < 16:
        return ""
    try:
        blob_base = struct.unpack_from("<Q", raw, 0)[0]
        blob_len = struct.unpack_from("<Q", raw, 8)[0]
        return f"Base=0x{blob_base:016X} Length=0x{blob_len:016X}"
    except Exception:
        return f"len={len(raw)}"


def _gpt_info(raw: bytes) -> str:
    """解析 EV_EFI_GPT_EVENT (0x80000006)"""
    if len(raw) < 92:
        return f"len={len(raw)}"
    try:
        sig = raw[:8]
        if sig != b"EFI PART":
            return f"sig={sig}"
        # DiskGUID at offset 56
        disk_guid = raw[56:72]
        d1 = struct.unpack_from("<I", raw, 56)[0]
        d2 = struct.unpack_from("<H", raw, 60)[0]
        d3 = struct.unpack_from("<H", raw, 62)[0]
        d4 = raw[64:72]
        guid = (d1, d2, d3, bytes(d4))
        first_lba = struct.unpack_from("<Q", raw, 72)[0]
        last_lba = struct.unpack_from("<Q", raw, 80)[0]
        part_lba = struct.unpack_from("<Q", raw, 88)[0]
        result = f"DiskGUID={guid} FirstLBA={first_lba} LastLBA={last_lba} PartitionsLBA={part_lba}"
        if len(raw) >= 104:
            num_parts = struct.unpack_from("<I", raw, 96)[0]
            part_size = struct.unpack_from("<I", raw, 100)[0]
            result += f" NumPartitions={num_parts} PartSize={part_size}"
        return result
    except Exception as e:
        return f"error: {e}"


def _spdm_info(raw: bytes) -> str:
    """解析 EV_EFI_SPDM_* 系列事件"""
    if len(raw) < 16:
        return f"len={len(raw)}"
    try:
        sig = raw[:16].rstrip(b'\x00')
        sig_str = sig.decode('utf-8', errors='replace')
        if sig_str.startswith("SPDM Device Sec"):
            result = f"Signature=\"{sig_str}\""
            if len(raw) >= 18:
                version = struct.unpack_from("<H", raw, 16)[0]
                result += f" Version={version}"
            if len(raw) >= 19:
                auth_state = raw[18]
                auth_str = {0: "SUCCESS", 1: "NO_AUTH", 2: "NO_BINDING",
                            3: "FAIL_NO_SIG", 4: "FAIL_INVALID", 0xFF: "NO_SPDM"}.get(auth_state, f"0x{auth_state:02X}")
                result += f" AuthState={auth_str}"
            if len(raw) >= 24:
                total_len = struct.unpack_from("<I", raw, 20)[0]
                result += f" TotalLength={total_len}"
            if len(raw) >= 28:
                device_type = struct.unpack_from("<I", raw, 24)[0]
                dev_str = {0: "NULL", 1: "PCI", 2: "USB"}.get(device_type, f"UNKNOWN({device_type})")
                result += f" DeviceType={dev_str}"
            return result
        else:
            return f"Signature=0x{raw[:16].hex()}"
    except Exception as e:
        return f"error: {e}"


def _find_efi_var(events: list[_EvRec], pcr=None,
                  exact=None, kw=None, need_global=False):
    for ev in events:
        if ev.etype not in (EV_EFI_VAR_CFG, EV_EFI_VAR_BOOT, EV_EFI_VAR_AUTH):
            continue
        if pcr is not None and ev.pcr != pcr:
            continue
        v = _parse_efi_var(ev.data)
        if v is None:
            continue
        if exact and v.name != exact:
            continue
        if kw and not any(k.lower() in v.name.lower() for k in kw):
            continue
        if need_global and not v.is_global:
            continue
        return ev, v
    return None


# ═══════════════════════════════════════════════════════════════════════════════
# 七、安全特性分析（7 项）
# ═══════════════════════════════════════════════════════════════════════════════

class _FS(Enum):
    ENABLED = "Enabled"; DISABLED = "Disabled"
    UNKNOWN = "Unknown"; NOT_MEASURED = "Not Measured"


@dataclass
class _Feat:
    name: str; status: _FS = _FS.NOT_MEASURED
    evidence: str = ""; detail: str = ""

    def to_dict(self):
        return {"name": self.name, "status": self.status.value,
                "evidence": self.evidence, "detail": self.detail}


def _feat_secure_boot(ev, s):
    f = _Feat("Secure Boot")
    r = _find_efi_var(ev, pcr=7, exact="SecureBoot", need_global=True)
    if not r:
        f.evidence = "SecureBoot variable not found in PCR7"; return f
    evt, v = r
    f.status = _FS.ENABLED if (v.data and v.data[0] == 1) else _FS.DISABLED
    f.evidence = f"Event #{evt.index} PCR7 SecureBoot=0x{v.data[0]:02X}" if v.data else f"Event #{evt.index} empty"
    details = []
    for vn in ("PK", "KEK", "db", "dbx"):
        r2 = _find_efi_var(ev, pcr=7, exact=vn)
        if r2:
            _, v2 = r2; details.append(f"{vn}(len={len(v2.data)})")
    f.detail = ", ".join(details); return f


def _feat_virt(ev, s):
    f = _Feat("CPU Virtualization (VT-x / AMD-V)")
    r = _find_efi_var(ev, kw=["Virt", "VMX", "SVM"])
    if r:
        evt, v = r; f.status = _FS.ENABLED if (v.data and v.data[0] != 0) else _FS.DISABLED
        f.evidence = f"EFI var '{v.name}' Event #{evt.index}"; return f
    for e in ev:
        if e.pcr == 0 and e.etype == EV_EFI_BLOB2:
            bn = _blob2_name(e.data).upper()
            if any(k in bn for k in ("VMX", "CPUINIT", "VTD")):
                f.status = _FS.ENABLED; f.evidence = f"PCR0 BLOB2 '{bn}' #{e.index}"; return f
    p11 = [e for e in ev if e.pcr == 11]
    if p11:
        hv = next((e for e in p11 if e.etype == EV_COMPACT_HASH
                   and len(e.data) == 4
                   and struct.unpack_from("<I", e.data)[0] == 0x10), None)
        f.status = _FS.ENABLED
        f.evidence = (f"PCR11 Hyper-V launch marker #{hv.index}" if hv
                      else f"PCR11 has {len(p11)} WBCL events → VBS active, VT-x required"); return f
    blobs = [e for e in ev if e.pcr == 0 and e.etype == EV_EFI_BLOB2]
    if blobs:
        f.status = _FS.UNKNOWN; f.evidence = f"{len(blobs)} PCR0 FW blobs, no direct VT-x marker"; return f
    f.evidence = "No virtualization measurements"; return f


def _feat_iommu(ev, s):
    f = _Feat("IOMMU (VT-d / AMD-Vi)")
    r = _find_efi_var(ev, kw=["Iommu", "VTd", "DMAR", "DMA"])
    if r:
        evt, v = r; f.status = _FS.ENABLED if (v.data and v.data[0] != 0) else _FS.DISABLED
        f.evidence = f"EFI var '{v.name}' #{evt.index}"; return f
    for e in ev:
        if e.pcr == 0 and e.etype == EV_EFI_BLOB2:
            bn = _blob2_name(e.data).upper()
            if any(k in bn for k in ("VTD", "DMAR", "IOMMU")):
                f.status = _FS.ENABLED; f.evidence = f"PCR0 BLOB2 '{bn}' #{e.index}"; return f
    for e in ev:
        if e.pcr == 1 and e.etype == EV_EFI_HANDOFF:
            if b"DMAR" in e.data:
                f.status = _FS.ENABLED; f.evidence = f"DMAR ACPI HANDOFF_TABLES2 #{e.index}"
                f.detail = "Intel VT-d measured"; return f
            if b"IVRS" in e.data:
                f.status = _FS.ENABLED; f.evidence = f"IVRS ACPI HANDOFF_TABLES2 #{e.index}"
                f.detail = "AMD-Vi measured"; return f
    e = _s1(s, 0x00090001)
    if e:
        active = bool(struct.unpack_from("<I", e.data)[0] & 1) if len(e.data) >= 4 else bool(e.u8)
        f.status = _FS.ENABLED if active else _FS.DISABLED
        f.evidence = f"SIPAEVENT_IOMMU_DMA_PROTECTION [PCR{e.pcr}]"
        f.detail = f"flags=0x{e.u32:08X}"; return f
    e = _s1(s, 0x00150001)
    if e:
        req = e.data and e.data[0] != 0
        f.status = _FS.ENABLED if req else _FS.UNKNOWN
        f.evidence = f"SIPAEVENT_VBS_IOMMU_REQUIRED={req} [PCR{e.pcr}]"; return f
    for e in _sall(s, 0x00050010, 0x00050011, 0x00050014):
        if e.data and e.data[0] == 1:
            f.status = _FS.ENABLED; f.evidence = f"Win11 V2 DMA tag 0x{e.eid:08X}=1 [PCR{e.pcr}]"
            f.detail = "Kernel DMA Protection active"; return f
    f.evidence = "IOMMU_DMA_PROTECTION not found"; return f


def _feat_hvci(ev, s):
    f = _Feat("HVCI / VBS"); evid = []; detected = False
    e1 = _s1(s, 0x00080001, 0x00020008)
    if e1:
        lt = e1.u32
        desc = {0: "not launched", 1: "launched (VT-x occupied)", 2: "launched w/ virt-ext"}.get(lt, f"unknown={lt}")
        evid.append(f"Chain1: HV_LAUNCH={lt} ({desc}) [0x{e1.eid:08X} PCR{e1.pcr}]")
        if lt >= 1: detected = True
    else:
        evid.append("Chain1: HypervisorLaunchType not found")
    e2 = _s1(s, 0x000A0001, 0x0005000A)
    if e2:
        fl = e2.u64
        parts = [n for bit, n in ((1, "VBS=ON"), (2, "VBS_REQ"), (4, "HVCI=ON")) if fl & bit]
        if not parts and fl: parts = [f"raw=0x{fl:X}"]
        evid.append(f"Chain2: flags=0x{fl:X} ({','.join(parts) or 'none'}) [PCR{e2.pcr}]")
        if fl & 0x05: detected = True
    else:
        e2b = _s1(s, 0x00050012)
        if e2b:
            evid.append(f"Chain2: VBS_policy_0x00050012=0x{e2b.u64:X} [PCR{e2b.pcr}]")
            if e2b.u64: detected = True
        else:
            evid.append("Chain2: VBS/HVCI flags not found")
    has12 = any(e.pcr == 12 for e in ev)
    evid.append("Chain3: PCR12 present" if has12 else "Chain3: PCR12 absent")
    f.status = _FS.ENABLED if detected else _FS.NOT_MEASURED
    f.evidence = "HVCI/VBS active" if detected else "No HVCI/VBS markers"
    f.detail = " | ".join(evid); return f


def _feat_drvsig(ev, s):
    f = _Feat("Driver Signature Enforcement"); evid = []; enforced = False
    e = _s1(s, 0x00050002)
    if e:
        off = e.u8 == 1
        evid.append(f"TestSigning={'OFF (enforced)' if off else 'ON (⚠weakened)'} [0x00050002=0x{e.u8:02X} PCR{e.pcr}]")
        if off: enforced = True
    e = _s1(s, 0x0005000E)
    if e:
        act = e.u32 != 0
        evid.append(f"CI_Enforcement={'Active' if act else 'Inactive'} [0x0005000E=0x{e.u32:X} PCR{e.pcr}]")
        if act: enforced = True
    e = _s1(s, 0x00040002)
    if e:
        kd_off = e.u8 == 0
        evid.append(f"KernelDebug={'Disabled(good)' if kd_off else '⚠Enabled'} [PCR{e.pcr}]")
    e = _s1(s, 0x00070001)
    if e:
        evid.append(f"Legacy CI=0x{e.u8:02X} [0x00070001 PCR{e.pcr}]")
        if e.u8: enforced = True
    f.status = _FS.ENABLED if enforced else (_FS.UNKNOWN if evid else _FS.NOT_MEASURED)
    f.evidence = "Driver signing enforced" if enforced else ("Tags found, status unclear" if evid else "No CI tags")
    f.detail = " | ".join(evid); return f


def _feat_blocklist(ev, s):
    f = _Feat("Vulnerable Driver Blocklist"); evid = []; enabled = False
    e = _s1(s, 0x00050021)
    if e:
        en = e.u8 == 1
        evid.append(f"VulnDriverBlocklist={'Enabled' if en else 'Disabled'} [0x00050021=0x{e.u8:02X} PCR{e.pcr}]")
        if en: enabled = True
    revoc = _sall(s, 0x00040001)
    if revoc:
        evid.append(f"BootRevocationList={len(revoc)} entries [PCR{revoc[0].pcr}]")
    e = _s1(s, 0x00050003)
    if e:
        evid.append(f"BootRevocationPolicy=0x{e.u8:02X} [PCR{e.pcr}]")
    f.status = _FS.ENABLED if (enabled or bool(revoc)) else (_FS.UNKNOWN if evid else _FS.NOT_MEASURED)
    f.evidence = ("Blocklist active" if enabled else
                  "Revocation list present" if revoc else
                  "Tags found" if evid else "No blocklist tags")
    f.detail = " | ".join(evid); return f


def _feat_boot_integrity(ev, s):
    f = _Feat("Boot Log Integrity")
    seps = sum(1 for e in ev if e.etype == EV_SEPARATOR)
    has_term = any(e.etype == EV_SEPARATOR and e.pcr in (12, 13, 14) and e.data == b"WBCL" for e in ev)
    f.status = _FS.ENABLED if seps >= 7 else _FS.UNKNOWN
    f.evidence = f"Separators={seps}" + (", WBCL terminator present" if has_term else "")
    f.detail = "Well-formed" if seps >= 7 and has_term else ("Partial" if seps >= 7 else "Incomplete")
    return f


def analyze_security_features(pr: _ParseResult) -> list[_Feat]:
    sipa = _parse_sipa(pr)
    ev   = pr.events
    return [
        _feat_secure_boot(ev, sipa),
        _feat_virt(ev, sipa),
        _feat_iommu(ev, sipa),
        _feat_hvci(ev, sipa),
        _feat_drvsig(ev, sipa),
        _feat_blocklist(ev, sipa),
        _feat_boot_integrity(ev, sipa),
    ]


# ═══════════════════════════════════════════════════════════════════════════════
# 八、TPMS_ATTEST 解析（TPM 大端序 Marshal）
# ═══════════════════════════════════════════════════════════════════════════════

TPM_GENERATED_MAGIC = 0xFF544347   # "FF TCG" — 只有 TPM 内部能写
TPM_ST_ATTEST_QUOTE = 0x8018


def parse_tpms_attest(data: bytes) -> dict:
    """
    解析 TPM marshalled TPMS_ATTEST（big-endian）。
    返回 {magic, type, qualified_signer, extra_data, firmware_version,
          pcr_selections:[{hash_alg, pcr_indices}], pcr_digest}
    """
    pos = 0
    magic,  = struct.unpack_from(">I", data, pos); pos += 4
    atype,  = struct.unpack_from(">H", data, pos); pos += 2
    # qualifiedSigner (TPM2B)
    qs_sz,  = struct.unpack_from(">H", data, pos); pos += 2
    qualified_signer = data[pos:pos + qs_sz]; pos += qs_sz
    # extraData (TPM2B)
    ed_sz,  = struct.unpack_from(">H", data, pos); pos += 2
    extra_data = data[pos:pos + ed_sz]; pos += ed_sz
    # TPMS_CLOCK_INFO: clock(8)+resetCount(4)+restartCount(4)+safe(1) = 17 bytes
    pos += 17
    fw, = struct.unpack_from(">Q", data, pos); pos += 8
    # TPMS_QUOTE_INFO → TPML_PCR_SELECTION
    sel_cnt, = struct.unpack_from(">I", data, pos); pos += 4
    selections = []
    for _ in range(sel_cnt):
        hash_alg, = struct.unpack_from(">H", data, pos); pos += 2
        sos = data[pos]; pos += 1
        pcr_sel = data[pos:pos + sos]; pos += sos
        pcr_indices = [bi * 8 + bit
                       for bi, bv in enumerate(pcr_sel)
                       for bit in range(8) if bv & (1 << bit)]
        selections.append({"hash_alg": hash_alg, "pcr_indices": pcr_indices})
    # pcrDigest (TPM2B)
    pd_sz, = struct.unpack_from(">H", data, pos); pos += 2
    pcr_digest = data[pos:pos + pd_sz]
    return {
        "magic":            magic,
        "type":             atype,
        "qualified_signer": qualified_signer,
        "extra_data":       extra_data,
        "firmware_version": fw,
        "pcr_selections":   selections,
        "pcr_digest":       pcr_digest,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# 九、AK 签名验证
# ═══════════════════════════════════════════════════════════════════════════════

def verify_ak_sig(spki_der: bytes, message: bytes, signature: bytes) -> bool:
    """验证 AK RSA-PKCS1v15-SHA256 签名"""
    try:
        pub = serialization.load_der_public_key(spki_der)
        pub.verify(signature, message,
                   padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception as e:
        print(f"[-] AK 签名验证失败: {e}")
        return False


# ═══════════════════════════════════════════════════════════════════════════════
# 十、Flask 路由
# ═══════════════════════════════════════════════════════════════════════════════

# ── /verify_chain（原有，扩展：成功时存 EK 指纹）─────────────────────────────
@app.route("/verify_chain", methods=["POST"])
def route_verify_chain():
    body = request.get_json(silent=True)
    if not body or "certs" not in body or not isinstance(body["certs"], list):
        return jsonify({"result": "fail", "reason": "missing or invalid 'certs' field"}), 400

    raw_list: list[bytes] = []
    for i, b64 in enumerate(body["certs"]):
        try:
            raw_list.append(base64.b64decode(b64))
        except Exception:
            return jsonify({"result": "fail", "reason": f"base64 decode error at index {i}"}), 400

    parsed = []
    for i, der in enumerate(raw_list):
        cert = _load_der_lenient(der)
        if cert is None:
            return jsonify({"result": "fail", "reason": f"cannot parse cert at index {i}"}), 400
        parsed.append(cert)

    print(f"[*] /verify_chain  收到 {len(parsed)} 张证书")
    root_pool = _load_root_pool()
    print(f"[*] 可信根池: {len(root_pool)} 张")

    success, chain, reason = build_chain(parsed, root_pool)

    ek_fingerprint = None
    if success:
        spki = _cert_spki(parsed[0])
        ek_fingerprint = _ek_fingerprint(spki)
        _, _, subj = _cert_names(parsed[0])
        store_ek(ek_fingerprint, subj)          # ← 写入 valid_eks.txt

    status = "success" if success else "fail"
    print(f"[{'✔' if success else '✘'}] /verify_chain: {reason}")
    for d, n in enumerate(chain):
        print(f"     [{d}] {n}")

    return jsonify({
        "result":         status,
        "chain":          chain,
        "reason":         reason,
        "ek_fingerprint": ek_fingerprint,
    })


# ── /make_credential（原有，扩展：检查 EK 指纹是否已注册）──────────────────────
@app.route("/make_credential", methods=["POST"])
def route_make_credential():
    body    = request.get_json()
    ek_der  = base64.b64decode(body["ek_pub"])
    ak_name = base64.b64decode(body["ak_name"])

    # ▶ 新增：EK 必须已通过 /verify_chain 注册
    fp = _ek_fingerprint(ek_der)
    if not is_ek_registered(fp):
        print(f"[✘] /make_credential: EK 未注册 {fp[:16]}...")
        return jsonify({"error": "EK not registered; call /verify_chain first"}), 403

    ek_pub = serialization.load_der_public_key(ek_der)
    secret = secrets.token_bytes(32)
    sid    = secrets.token_hex(16)
    _mc_sessions[sid] = {"secret": secret, "ak_name": ak_name.hex(), "ek_fp": fp}

    cred_blob, enc_secret = make_credential(ek_pub, ak_name, secret)
    print(f"[+] /make_credential session={sid[:8]}...  EK={fp[:16]}...")
    return jsonify({
        "session_id":       sid,
        "credential_blob":  base64.b64encode(cred_blob).decode(),
        "encrypted_secret": base64.b64encode(enc_secret).decode(),
    })


# ── /verify（原有，扩展：成功时存 AK 公钥）──────────────────────────────────────
@app.route("/verify", methods=["POST"])
def route_verify():
    body      = request.get_json()
    sid       = body["session_id"]
    received  = base64.b64decode(body["secret"])
    ak_pub_b64 = body.get("ak_pub")          # ← 新增：客户端随 secret 一起上传

    sess = _mc_sessions.pop(sid, None)
    if sess is None:
        return jsonify({"result": "fail", "reason": "unknown session"})

    if not secrets.compare_digest(received, sess["secret"]):
        print(f"[✘] /verify session={sid[:8]}... secret 不匹配")
        return jsonify({"result": "fail", "reason": "secret mismatch"})

    print(f"[✔] /verify session={sid[:8]}... ActivateCredential 成功")

    # ▶ 新增：注册 AK
    if ak_pub_b64:
        store_ak(sess["ak_name"], ak_pub_b64, sess["ek_fp"])   # 写入 valid_aks.txt

    return jsonify({"result": "success"})


# ── /request_nonce（新增）─────────────────────────────────────────────────────
@app.route("/request_nonce", methods=["POST"])
def route_request_nonce():
    """
    为 PCR Quote 分配挑战 nonce。要求 AK 已通过 /verify 注册。

    请求: { "ak_name": "<base64 AK Name>" }
    响应: { "quote_sid": "...", "nonce": "<base64 32B>" }
    """
    body    = request.get_json(silent=True)
    if not body or "ak_name" not in body:
        return jsonify({"error": "missing ak_name"}), 400

    ak_name_hex = base64.b64decode(body["ak_name"]).hex()

    # ▶ AK 必须已注册
    if not get_ak_record(ak_name_hex):
        print(f"[✘] /request_nonce: AK 未注册 {ak_name_hex[:16]}...")
        return jsonify({"error": "AK not registered; complete MakeCredential first"}), 403

    nonce = secrets.token_bytes(32)
    qsid  = secrets.token_hex(16)
    _quote_sessions[qsid] = {"nonce": nonce, "ak_name": ak_name_hex}

    print(f"[+] /request_nonce qsid={qsid[:8]}...  AK={ak_name_hex[:16]}...")
    return jsonify({
        "quote_sid": qsid,
        "nonce":     base64.b64encode(nonce).decode(),
    })


# ── /verify_quote ─────────────────────────────────────────────────────
@app.route("/verify_quote", methods=["POST"])
def route_verify_quote():
    """
    验证 TPM2_Quote 响应 + WBCL Replay。

    请求体:
    {
      "quote_sid": "<str>",
      "attest":    "<base64 TPMS_ATTEST marshalled bytes>",
      "sig":       "<base64 RSA signature bytes>",
      "wbcl":      "<base64 raw WBCL bytes>"
    }

    响应体:
    {
      "result":            "success" | "fail",
      "sig_valid":         bool,
      "magic_ok":          bool,
      "nonce_ok":          bool,
      "pcr_match":         bool,
      "security_features": [ {name, status, evidence, detail}, ... ],
      "reason":            str
    }
    """
    body = request.get_json(silent=True)
    if not body:
        return jsonify({"result": "fail", "reason": "empty body"}), 400

    qsid = body.get("quote_sid", "")
    sess = _quote_sessions.pop(qsid, None)
    if sess is None:
        return jsonify({"result": "fail", "reason": "unknown quote_sid"}), 400

    # 取 AK 公钥
    ak_rec = get_ak_record(sess["ak_name"])
    if ak_rec is None:
        return jsonify({"result": "fail", "reason": "AK not found in storage"}), 403
    ak_pub_der = base64.b64decode(ak_rec["ak_pub"])

    # 解码输入
    try:
        attest_bytes = base64.b64decode(body["attest"])
        sig_bytes    = base64.b64decode(body["sig"])
        wbcl_bytes   = base64.b64decode(body["wbcl"])
    except Exception as e:
        return jsonify({"result": "fail", "reason": f"decode error: {e}"}), 400

    out = {
        "sig_valid": False, "magic_ok": False,
        "nonce_ok":  False, "pcr_match": False,
        "security_features": [], "reason": "",
    }

    # ① AK 签名验证
    out["sig_valid"] = verify_ak_sig(ak_pub_der, attest_bytes, sig_bytes)
    if not out["sig_valid"]:
        out["reason"] = "AK signature invalid"; out["result"] = "fail"
        print(f"[✘] /verify_quote {qsid[:8]}: AK sig invalid")
        return jsonify(out)

    # 解析 TPMS_ATTEST
    try:
        attest = parse_tpms_attest(attest_bytes)
    except Exception as e:
        out["reason"] = f"attest parse: {e}"; out["result"] = "fail"
        return jsonify(out)

    # ② magic 检查
    out["magic_ok"] = (attest["magic"] == TPM_GENERATED_MAGIC)
    if not out["magic_ok"]:
        out["reason"] = f"bad magic 0x{attest['magic']:08X}"
        out["result"] = "fail"
        print(f"[✘] /verify_quote {qsid[:8]}: bad magic")
        return jsonify(out)

    # ③ nonce 检查（防重放）
    out["nonce_ok"] = secrets.compare_digest(attest["extra_data"], sess["nonce"])
    if not out["nonce_ok"]:
        out["reason"] = "nonce mismatch (possible replay attack)"
        out["result"] = "fail"
        print(f"[✘] /verify_quote {qsid[:8]}: nonce mismatch")
        return jsonify(out)

    # ④ WBCL Replay → pcrDigest 比对
    try:
        pr       = _WBCLParser().parse(wbcl_bytes)
        banks    = _replay(pr)
        expected = _compute_pcr_digest(banks, attest["pcr_selections"])

        if expected is None:
            out["reason"] = "cannot compute pcrDigest (unsupported alg)"
            out["result"] = "fail"
            return jsonify(out)

        out["pcr_match"] = secrets.compare_digest(expected, attest["pcr_digest"])
        if out["pcr_match"]:
            out["reason"] = "ok"; out["result"] = "success"
            print(f"[✔] /verify_quote {qsid[:8]}: ALL CHECKS PASSED")
        else:
            out["reason"] = (
                f"pcrDigest mismatch  "
                f"expected={expected.hex()[:16]}...  "
                f"attest={attest['pcr_digest'].hex()[:16]}...")
            out["result"] = "fail"
            print(f"[✘] /verify_quote {qsid[:8]}: pcrDigest mismatch")

        # 无论 pcr_match 结果，都附上安全特性分析
        out["security_features"] = [f.to_dict() for f in analyze_security_features(pr)]

    except Exception as e:
        out["reason"] = f"WBCL replay error: {e}"; out["result"] = "fail"

    return jsonify(out)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)