# SEWindows 

![主界面截图](https://www.cloudyou.top/images/ui.png)

本项目是一款基于 TPM（可信平台模块）的系统安全状态验证工具，主要用于检测并验证本机是否真实开启了以下安全防御特性：
- CPU 虚拟化 (CPU Virtualization)
- IOMMU (输入输出内存管理单元)
- 安全启动 (Secure Boot)
- VBS / HVCI (基于虚拟化的安全与内存完整性)
- 驱动强制签名 (Driver Signature Enforcement)
- 易受攻击的驱动阻止列表 (Vulnerable Driver Blocklist)

通过解析和校验底层硬件度量数据，本项目提供**本地验证**和基于 C/S 架构的**远程验证**（C# 客户端 + Python Flask 服务端），确保查询到的系统安全状态未被恶意软件篡改或伪造。

---

## 验证原理详解

### 1. 本地验证 (Local Verification)

本地验证的核心在于比对 TPM 芯片中受硬件保护的 PCR（平台配置寄存器）值与 Windows 的 TCG 度量启动日志（Measured Boot Log）。


**验证流程：**
1. **获取 PCR 真实值：** 客户端直接向主板上的 TPM 硬件发送指令，读取各个 PCR 的当前值（例如 PCR[7] 负责记录安全启动相关策略，PCR[11] 记录 Windows 引导环境等）。
2. **提取并解析 Event Log：** 读取 Windows 维护的 `tcglog`。该日志依次记录了系统从加电开始到操作系统加载完毕期间，所有被度量的代码和配置事件及其哈希值。
3. **哈希重放 (Replay)：** 验证器按照 Event Log 中的记录顺序，逐个进行哈希运算（公式为 `新PCR = Hash(旧PCR || 传入数据的Hash)`），计算出预期的 PCR 最终值。
4. **状态确认：** 将重放计算得到的 PCR 预期值与步骤 1 中从 TPM 硬件读取到的真实 PCR 值进行比对。如果两者一致，说明日志未被篡改，此时可以放心地解析日志内的详细事件（如 `SIPolicy` 配置），从而准确判断出 VBS、安全启动等安全功能是否处于开启状态。

### 2. 远程验证 (Remote Attestation)

虽然本地验证能防范普通层面的伪造，但在内核完全沦陷（如 Rootkit 劫持了获取 PCR 的系统 API 或 TPM 驱动）的情况下，攻击者可以直接伪造 PCR 返回值和日志。因此需要引入远程验证机制。


**验证流程：**
1. **身份认证密钥：** 依赖 TPM 固化在硬件内的 EK（Endorsement Key，背书密钥，即 TPM 的身份证）以及由此派生的 AK（Attestation Key，证明密钥）。
2. **服务器质询 (Challenge)：** 远程服务器（Server 目录下的 Flask 应用）生成一个高强度的随机数（Nonce），发送给客户端。
3. **硬件签名 (Quote)：** 客户端将该 Nonce 及需要验证的 PCR 索引提交给 TPM 硬件。TPM 使用私有的 AK 对当前的 PCR 值及 Nonce 进行密码学签名，生成 Quote（引用）。随后客户端将 Quote、AK 公钥以及 Event Log 发送回服务器。
4. **服务器校验：**
   - 服务器首先通过受信任的 EK 证书链验证 AK 的合法性。
   - 服务器使用 AK 公钥解密并校验 Quote 的签名，确认 Nonce 匹配（防重放攻击），提取出绝对真实的 PCR 值。
   - 服务器重放客户端传来的 Event Log，确保其最终哈希与 Quote 中的硬件 PCR 值一致，最后由服务器解析日志事件，得出最终的安全状态结论。

---

## 证书管理与信任链说明

在进行远程验证时，服务端必须能够建立对客户端 TPM 硬件的信任链，这就要求必须导入并信任各个 TPM 厂商的根证书。

### 受信任的 TPM 根证书下载
为了验证各大厂商的 TPM EK 证书的合法性，你可以直接下载由微软官方维护的 TPM 根证书包。该包内包含了市面上主流 TPM 厂商的根证书：
🔗 **下载地址：** [Guarded fabric - Install trusted TPM root certificates](https://learn.microsoft.com/en-us/windows-server/security/guarded-fabric-shielded-vm/guarded-fabric-install-trusted-tpm-root-certificates)

### 为什么要导出所有的证书（嵌入式中间证书 EICA）？
通常情况我们不仅需要根证书和终端证书，还必须从设备的 NV (非易失性) 存储区中完整提取并导出所有中间证书。这对于使用 Intel 处理器内置的 Intel PTT (Platform Trust Technology) 的现代设备尤为重要。

根据 Intel 工程师的[官方社区答复](https://community.intel.com/t5/Mobile-and-Desktop-Processors/How-to-verify-an-Intel-PTT-endorsement-key-certificate/m-p/1610198/highlight/true)披露：
> 从第 11 代酷睿处理器开始，Intel PTT 的背书密钥 (Endorsement Keys, EK) 改为使用 **Intel ODCA (On Die Certificate Authority)** 进行设备内认证，而不再通过之前的联网服务器 EKOP (EK Online Provisioning server) 来下发。
> 
> 为了成功构建证书信任路径，你必须获取嵌入式中间证书 (Embedded Intermediate CAs, EICA)。这在 TCG 组织的 EK Credential Profile 规范第 2.2.1.5.2 节 "Handle Values for EK Certificate Chains" 中有详细规定。
>
> 具体的签名信任链结构如下：
> 1. PTT 的 EK 证书由 PTT EICA（例如显示为 `CSME ADL PTT 01SVN`）签名。
> 2. PTT CA 由 CSME Kernel EICA 签名。
> 3. Kernel EICA 由 CSME ROM EICA 签名。
> 4. 最后，ROM EICA 中才会包含一个指向其最终颁发者（Issuer）的 AIA URL 供你继续追溯。

根据 TCG 规范，PTT、Kernel 以及 ROM 的 EICA 都存放在 TPM 专门分配给 EK 链的 NV 存储范围内。因此，**提取并导出这一完整的嵌套证书链是远程验证过程能够正确校验 Intel 11 代及更新 CPU 硬件身份的先决条件。**