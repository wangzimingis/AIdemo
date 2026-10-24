# SEV-SNP 证明链与度量机制简明说明

> 本文面向课程读者，只讲清楚本 Demo 用到的机制；完整规范见
> AMD《SEV-SNP Firmware ABIs Specification》（公开下载）与
> AMD Memory Encryption 白皮书。

## 1. SEV-SNP 是什么

SEV-SNP（Secure Encrypted Virtualization – Secure Nested Paging）是
AMD EPYC 7003/9004 系列（Milan/Genoa）起提供的机密计算能力：

- **内存加密（SME-BASE / AS）**：每个 VM 的内存用 AES-256（内存加密
  引擎，每个 VM 独立密钥）加密，宿主机 hypervisor 与云管理员无法
  读取 guest 内存。
- **完整性保护（SNP 的增量）**：相比前代 SEV/SEV-ES 只防"读"，
  SNP 通过嵌套页表反向映射（RMP）防"改"——hypervisor 对 guest 内存的
  任何越权写入会被固件拒绝，从而 guest 可以信任自己的运行环境。

## 2. 信任根与启动度量

SEV-SNP 的信任根是 PSP（Platform Security Processor，固件内的独立
安全处理器）。VM 启动时，PSP 对被加载组件做**哈希链**式度量：

```
measurement = SHA-384( ... SHA-384(每个启动组件按序串接) ... )
```

覆盖固件、BIOS 配置、内核镜像、initrd 等。度量值烧录在 guest 的
launch context 中，任何组件变化（内核参数被篡改、initrd 被替换）
都会导致度量值不同——这就是"证明运行时未被篡改"的物理基础。

本 Demo 的简化模型（mock 模式与 `measure-runtime.sh` 使用同一组合）：

```
measurement = SHA-384( SHA-384(kernel) || SHA-384(initrd) || SHA-384(gate) )
```

真实硬件上这个值由 PSP 生成，不可伪造。

## 3. 证明报告（Attestation Report）

Guest 内任何组件可通过 `/dev/sev-guest` 的 `SNP_GET_REPORT` ioctl 向
PSP 请求一份 4096 字节的证明报告，关键字段（完整布局见
`common/snp_layout.py`，与规范 Table 22 对应）：

| 偏移 | 字段 | 含义 |
|---|---|---|
| 0x00 | VERSION | 报告版本（=2） |
| 0x08 | POLICY | guest 策略位域（ABI 版本、SMT 等） |
| 0x38 | CURRENT_TCB | 固件 TCB 版本（build.minor.major） |
| 0x90 | MEASUREMENT | 48 字节启动度量 ← **KRS 比对的核心** |
| 0xC0 | HOST_DATA | hypervisor 注入的数据（用于标识宿主） |
| 0x140 | REPORT_DATA | 调用者提供的 64 字节 ← **nonce 绑定在这里** |
| 0x2A0 | SIGNATURE | VCEK 对报告前 0x2A0 字节的 ECDSA-P384/SHA-384 签名 |

**防重放**：KRS 先通过 `/challenge` 下发随机 nonce，guest 将其放入
REPORT_DATA 请求报告。验签时 KRS 检查 REPORT_DATA == nonce，并保证
nonce 一次性、60 秒过期。报告因此是"为本次会话现生成"的，无法重放。

## 4. 证书链：VCEK → ASK → ARK

报告签名密钥 VCEK（Versioned Chip Endorsement Key）是每颗芯片唯一、
随 TCB 版本派生的 P-384 密钥，不出芯片。验证签名需要三级证书链：

```
ARK  (AMD Root Key，自签名根，AMD 官网公示)
 └─ ASK  (AMD SEV Signing Key，由 ARK 签发)
     └─ VCEK (芯片背书密钥，由 ASK 签发；从 AMD KDS 在线获取)
```

VCEK 可通过 AMD Key Distribution Service 按芯片 ID + TCB 版本获取：

```
GET https://kdsintf.amd.com/vcek/v1/{milan|genoa}/{chip_id}?specver=2&...
```

工程要点（本 Demo 踩过的坑）：

1. VCEK 与 TCB 版本绑定——固件升级后必须重新拉取，否则验签失败；
2. KDS 返回 DER 格式，需转 PEM；
3. `snpguest fetch vcek` 一条命令搞定证书拉取，推荐而非手搓 HTTP。

## 5. 本 Demo 的验证流水线（krs/verifier.py）

```
原始报告(0x1000B)
  ├─ 1. 结构校验（版本、签名算法、长度）
  ├─ 2. 证书链：ARK 自签 → ASK ← ARK → VCEK ← ASK
  ├─ 3. VCEK 签名验签（report[0x00:0x2A0]，ECDSA-P384/SHA-384）
  ├─ 4. 新鲜度：REPORT_DATA == 本会话 nonce（一次性、60s TTL）
  ├─ 5. 度量比对：MEASUREMENT == 注册基线
  ├─ 6. 防回滚：CURRENT_TCB 各分量 ≥ 基线 TCB
  └─ 7. 策略检查：ABI major ≥ 基线要求
        ↓ 全部通过
      释放模型解密密钥
```

与 RAI (Remote Attestation for Inference) 等研究项目的差异：本项目
不追求新协议，而是把"最小可信链"在真实可复购的云端硬件 + 开源栈上
端到端打通，并明确标注度量边界（见 threat-model.md）。
