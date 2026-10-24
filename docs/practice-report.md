# 实践报告：基于 AMD SEV-SNP 与 ROCm 的最小化机密 AI 推理门控

**项目**：远程证明驱动的模型权重释放（sev-snp-attested-inference-gate）
**日期**：2026-10
**性质**：课程实践级最小可行原型（未经生产安全审计）

---

## 1. 目标回顾

在不可信云平台上运行 AI 推理时，模型提供方需要两个保证：①云运营商
无法读取模型权重；②推理运行时未被篡改。本 Demo 构建的最小门控原型：

- 权重以 AES-256-GCM 密文存储于云端；
- 独立的 Key Release Server（KRS）持有解密密钥；
- KRS 仅在 SEV-SNP 证明报告通过**证书链验签 + 度量比对 + TCB 防回滚 +
  nonce 新鲜度**四层校验后释放密钥；
- 权重明文只存在于 SEV-SNP 加密内存中，推理经 ROCm/vLLM 执行。

不追求大模型吞吐优化，追求**端到端证明链的完整性与可复现性**。

## 2. 系统实现

### 2.1 模块清单（与仓库对应）

| 模块 | 文件 | 说明 |
|---|---|---|
| 报告布局 | `common/snp_layout.py` | 按规范 Table 22 定义的 0x1000 报告字段表，验签方/生成方共用一份常量，杜绝偏移漂移 |
| 证明验证 | `krs/verifier.py` | 纯 Python 自实现：ARK 自签 → ASK ← ARK → VCEK ← ASK 证书链，ECDSA-P384/SHA-384 报告验签（覆盖 `report[0x00:0x2A0]`），度量比对、TCB 分量级防回滚、policy 检查；可选 AMD KDS 在线拉取 VCEK |
| 密钥释放服务 | `krs/server.py` | FastAPI：`/challenge`（一次性 nonce，60s TTL）、`/release-key`（七步校验后放行）、`/healthz`；密钥经环境变量注入，不入库 |
| 基线 | `krs/baselines/*.json` | 注册的度量 + TCB 基线，支持双基线对比实验 |
| 门控客户端 | `guest/gate_client.py` `launch-gate.py` | 挑战 → 取证 → 请求密钥 → 流式解密 → 写执行回执 → exec vLLM；被拒则以非零码退出，权重保持密文 |
| 报告获取 | `guest/get_report.py` | 真实硬件：`/dev/sev-guest` ioctl（sev-guest uapi）或 ingest snpguest 产物；mock：子进程调用生成器 |
| 权重加密 | `guest/weight_crypto.py` `scripts/encrypt-model.py` | 流式 AES-256-GCM（4 MiB 分块、逐块独立 tag、文件头作 AAD），3 GB 级权重不爆内存 |
| 推理/测量 | `guest/run-inference.py` | vLLM OpenAI 兼容接口压测，追加写 CSV，门控/非门控同表对比 |
| 度量基线 | `guest/measure-runtime.sh` `scripts/measure_baseline.py` | `SHA-384(SHA-384(kernel)‖initrd‖gate)`，mock 与真实流程共用同一组合函数 |
| 仿真环境 | `mock/mock-attest.py` | 无硬件生成 P-384 三级证书链 + 规范布局报告，支持 `--tamper measurement/signature/tcb/report-data/policy` 五种篡改注入 |
| 端到端演示 | `scripts/demo_local.py` | 起真实 KRS（HTTP）+ 真实门控 CLI，跑 6 场景并产出 results/ 证据 |

### 2.2 关键设计决策

1. **验签完全自实现**。可用的第三方库要么封装过深（无法审计度量
   比对逻辑），要么与课程"可复现、可审计"的目标冲突。自实现后，
   整条信任链约 400 行 Python，每一步都能对照规范逐条检查。
2. **报告布局常量单点定义**。验签方（KRS）与生成方（mock）引用同一
   `snp_layout.py`，避免"生成用一套偏移、验证用另一套"的经典 bug。
3. **mock 与真实共用协议**。mock 报告在字节布局、签名字节范围、
   度量组合上与真硬件完全一致，KRS 代码路径零分支——mock 跑通 ≈
   硬件跑通（仅信任根不同）。
4. **流式加解密**。1.5B FP16 权重约 3 GB，整文件读入内存的
   `AESGCM.encrypt` 方案在 64 GB 实例上是浪费；分块 + 逐块 AAD 绑定
   文件头，同时天然获得断点完整性校验。
5. **回执链（proposal 可选扩展已实现）**。门控成功后写
   `/run/gate-receipt.json`（权重 SHA-256 + KRS 度量 + 推理配置），
   其摘要可作为下一次证明的 REPORT_DATA nonce，形成
   "启动证明 → 执行回执 → 下次证明"的可追溯证据链。

## 3. 执行记录（对照 4 周计划）

| 周次 | 计划 | 实际产出 |
|---|---|---|
| W1 | 实例申请、`/dev/sev-guest` 验证、原始报告解析、小模型准备 | `scripts/setup-sev-snp.sh`（cpuinfo/设备/内核/ROCm/工具链五段检查）；`snp_layout.py` 报告解析；mock 证书链与报告生成器先行落地（硬件未到位时开发不阻塞）【云端实例实测待云端窗口执行】 |
| W2 | KRS 验签 + 度量比对，双基线准备 | `verifier.py` + `server.py` 完整实现；`baseline.json` / `baseline-tampered.json`；六场景含五种篡改注入 |
| W3 | 端到端门控流程 + 两种条件对比 | `demo_local.py` 六场景 6/6 PASS（见 §4）；`launch-gate.py` 拒绝即退、权重保持密文；回执链实现 |
| W4 | 延迟数据、仓库整理、报告 | mock 环境门控开销实测入 CSV；硬件复测模板与流程写就；仓库/文档/本报告 |

**周报要点（坑与解法）**：

- *坑 1*：POLICY 字段位域按"猜"填 `0x10001`，ABI major 解析为 0，
  连正常路径都被 KRS 拒绝。→ 位域布局（minor 0–7 / major 8–15 /
  SMT 16）以规范为准写进注释，正确值 `0x10101`。
- *坑 2*：ECDSA-P384 签名在报告里不是 DER 而是 R[72]‖S[72] 定长
  大端。→ `encode_dss_signature` 互转，两侧统一。
- *坑 3*：`/dev/sev-guest` ioctl 的 uapi 结构体随内核版本有差异。
  → ioctl 路径做响应合法性校验 + 多命令字尝试，失败时明确引导到
  snpguest CLI 路径（不静默出错）。
- *坑 4*：早期版本从"不存在的 secretvm-verify 库"导入验签——占位
  依赖是可复现性的反模式。→ 全部自实现，`requirements.txt` 仅
  fastapi/uvicorn/cryptography 三项。

## 4. 实验结果（mock 端到端，2026-10-24 实测）

环境：Windows 笔记本 / Python 3.13 / 无 SEV-SNP 硬件；
KRS 与 guest 经真实 HTTP（127.0.0.1）交互；证据见
`results/attestation-accept-vs-reject.log`。

```
scenario=accept             expected=RELEASE result=RELEASED  verdict=PASS
   （权重解密后 SHA-256 与加密前一致）
scenario=tamper-measurement expected=DENY    result=DENIED    verdict=PASS
   （measurement mismatch: got c9fef647… expected 360109b8…）
scenario=tamper-signature   expected=DENY    result=DENIED    verdict=PASS
   （VCEK report signature invalid）
scenario=tamper-tcb         expected=DENY    result=DENIED    verdict=PASS
   （TCB rollback detected: 5.16.1 < 10.26.1）
scenario=tamper-report-data expected=DENY    result=DENIED    verdict=PASS
   （REPORT_DATA does not match the challenge nonce）
scenario=nonce-reuse        expected=DENY    result=DENIED    verdict=PASS
   （nonce already used (replay)）
6/6 scenarios PASS
```

**门控开销（mock 实测）**：挑战 → 报告 → 验签 → 密钥释放全往返
765–1340 ms（含子进程冷启动与 mock 报告生成的保守上界；KRS 侧
纯验签耗时仅数十毫秒量级）。权重解密吞吐约 GB/s 级（AES-GCM 硬件
加速），3 GB 权重解密预计数秒，均为**一次性启动开销**。

**预期硬件结论（待 MI300X + SEV-SNP 实例复测）**：
SNP 内存加密对计算密集型推理的额外延迟在 1% 量级；门控不影响逐
token 延迟（ttft/tpot 与无门控基线应重合）。复测流程见
`results/README.md`。逐 token 数据【待云端窗口实测后填入 CSV】。

## 5. 边界与局限

1. **度量粒度**：本 Demo 将度量限定为 kernel + initrd + 门控程序，
   ROCm 用户态库（`libhsa-runtime`、vLLM 及其依赖）**不在证明链内**
   ——需要 IMA appraisal / dm-verity 才能纳入，是已声明的最重要边界
   （见 `docs/threat-model.md` N1）。
2. **KRS 生产化缺口**：单 worker 内存 nonce 表、无密钥轮换、无 HSM、
   TLS 部署为运维要求而非代码保证。
3. **VCEK 产品扩展未校验**：未检查 AMD 专有证书扩展的芯片 SKU 绑定
   （threat-model N6）。
4. **vLLM/ROCm 兼容**：计划内经验——优先 FP16/FP8-dynamic 加载小
   模型，AWQ 在 ROCm 上支持不完整【硬件窗口确认】。

## 6. 试用平台体会（按 proposal 第 7 节框架）

**① SEV-SNP 在云端实例上的可及性**。规范公开、主线内核原生支持，
是事实；但从"申请实例"到"`/dev/sev-guest` 可用"之间仍隔着实例
类型选择、镜像构建、launch policy 设置数道门槛。mock 先行的开发
策略使这一偏差不影响关键路径：证明链逻辑的开发与验证完全不等硬件。
体会：硬件 TEE 项目要把"硬件依赖"压缩到最后一块拼图，其余全部
可先行、可 CI 化。

**② 证明链的"最后一公里"**。证书链验证（VCEK→ASK→ARK）在工程上
并非不可逾越——P-384/SHA-384 全部走标准库即可；真正的门槛在格式
细节：KDS 返回 DER、签名是 R[72]‖S[72] 而非 DER、TCB 比对必须
分量级而非整型比大小。这些"坑"每一条都消耗过半天级调试。一旦跑通，
验签逻辑约 400 行、可稳定复用于任何 SNP 场景——这也是全栈开源栈
（对比闭源驱动内部机制）的复利。

**③ ROCm/vLLM 的机密模式兼容性**。权重解密后的推理路径与普通
ROCm 路径一致，门控对推理引擎零侵入；量化格式选择（FP8-dynamic
vs AWQ）对单卡能否服务目标模型有实质影响，属于"AI 侧"的独立
工程问题。体会：机密计算的价值恰在于把"信任问题"与"性能问题"
解耦——密钥释放只关心运行时度量，不关心你跑什么模型。

**④ "门控"的真实价值认知**。Demo 跑通后最深的体会：硬件证明解决
的是**密钥释放的信任问题**，而非推理过程本身的侧信道问题。攻击者
篡改内核 → 度量变 → 拒绝，这条链是硬件背书的"可验证事实"；但
共享缓存/TLB 的负载侧信道，门控一个也不挡。这与课程论文"隔离 ≠
负载感知安全"的判断形成直接呼应：门控是必要的起点，不是终点。

**⑤ 两部分的衔接逻辑**。课程论文指出 TEE 在 AI 负载下面临侧信道
侵蚀与评价语言的转型；工程实践选择"硬件证明驱动的密钥门控"作为
现有硬件条件下可立即落地的最小突围动作。它不声称解决侧信道问题，
但它把信任的锚点从"云厂商的承诺"替换为"芯片签名的可验证事实"。
从依赖信任到验证信任，这正是"从厂商承诺到硬件可证"的第一步——
也是把论文里的批判性结论转化为可运行代码的最短路径。

## 7. 结论

在 AMD 公开规范 + 开源栈上，用约 1500 行 Python 完成了从证明报告
生成（mock）/获取（真实硬件路径）、证书链验签、度量基线比对、
密钥门控、流式解密到推理启动的完整链条，并以六场景对照实验证明：
**度量匹配则密钥释放、度量篡改则推理永远无法启动**。该原型可为
云端机密 AI 推理的最小信任基座，后续工作按优先级依次为：IMA/dm-verity
纳入 ROCm 用户态度量、KRS 生产化（HSM/审计/高可用）、侧信道
防护（负载感知隔离）。
