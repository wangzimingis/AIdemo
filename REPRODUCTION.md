# REPRODUCTION.md — 复现步骤

> 本仓库的三条复现路径，按投入成本从低到高：
> **A. 无硬件端到端（笔记本，约 5 分钟）→ B. 真实 SEV-SNP 云实例（约 1–2 天）→ C. 完整延迟实验（叠加在 B 上，约半天）**
> 所有复现均在 Windows / Linux / macOS 命令行完成，无 GUI 依赖。

---

## A. 无硬件端到端复现（mock 模式，约 5 分钟）

mock 模式生成的证明报告与真实硬件在**字节布局、签名覆盖范围（`report[0x00:0x2A0]`）、
证书链结构、度量组合公式**上完全一致；KRS 的验证代码路径**零分支**。
因此 mock 跑通 ≈ 硬件跑通（仅信任根不同：mock 用本地生成的 P-384 密钥）。

### A.1 环境准备

- Python ≥ 3.10（3.13 已验证）
- 网络可访问 PyPI

```bash
git clone <your-repo-url> sev-snp-attested-inference-gate
cd sev-snp-attested-inference-gate

python -m venv .venv
# Windows:
.venv\Scripts\pip install -r requirements.txt
# Linux / macOS:
.venv/bin/pip install -r requirements.txt
```

依赖仅三项：`fastapi`、`uvicorn`、`cryptography`（无任何闭源/占位依赖）。

### A.2 一键端到端演示（六场景）

```bash
# Windows:
.venv\Scripts\python scripts/demo_local.py --fresh
# Linux / macOS:
.venv/bin/python scripts/demo_local.py --fresh
```

该脚本会自动完成：

1. 生成 mock 度量工件（`mock/artifacts/`）与仿真 ARK→ASK→VCEK 证书链（`mock/keys/`）；
2. 用随机 32 字节密钥流式加密一份 32 MiB 仿真权重（真实 `weight_crypto.py` 代码路径）；
3. 以真实 HTTP 起动 KRS（`uvicorn`，`krs/verifier.py` 全量校验）；
4. 以子进程方式运行真实门控 CLI（`guest/launch-gate.py`）跑六个场景：
   - `accept`：基线匹配 → 密钥释放 → 解密 → SHA-256 校验一致；
   - `tamper-measurement / signature / tcb / report-data`：四种篡改各应被拒；
   - `nonce-reuse`：重放已用 nonce 应被拒；
5. 写入证据文件 `results/attestation-accept-vs-reject.log` 与
   `results/latency-gate-vs-nogate.csv`。

### A.3 期望输出

```
scenario=accept              expected=RELEASE result=RELEASED  verdict=PASS
scenario=tamper-measurement  expected=DENY    result=DENIED    verdict=PASS
scenario=tamper-report-data  expected=DENY    result=DENIED    verdict=PASS
scenario=tamper-signature    expected=DENY    result=DENIED    verdict=PASS
scenario=tamper-tcb          expected=DENY    result=DENIED    verdict=PASS
scenario=nonce-reuse         expected=DENY    result=DENIED    verdict=PASS
==== run summary: 6/6 scenarios PASS (all good) ====
```

（我们 2026-10-24 实测日志见 `results/attestation-accept-vs-reject.log`，
每条拒绝记录均带 KRS 返回的具体 403 原因。）

### A.4 手动分步复现（可选，理解协议）

```bash
# 1. 生成 mock 材料与证书链
python mock/mock-attest.py make-artifacts
python mock/mock-attest.py init

# 2. 生成基线（与报告同一度量组合公式）
python scripts/measure_baseline.py --mock-artifacts \
    --out krs/baselines/baseline.json

# 3. 生成演示密钥并加密一份权重
python scripts/encrypt-model.py genkey --out .env.modelkey
python scripts/encrypt-model.py encrypt \
    --key-hex $(grep MODEL_KEY .env.modelkey | cut -d= -f2) \
    --in <任意文件> --out model.bin.enc

# 4. 起动 KRS（密钥与基线只经环境变量注入）
MODEL_KEY=$(grep MODEL_KEY .env.modelkey | cut -d= -f2) \
KRS_BASELINE=krs/baselines/baseline.json \
    uvicorn krs.server:app --port 8443

# 5. 另一终端跑门控（放行路径）
python guest/launch-gate.py --krs http://127.0.0.1:8443 --mode mock \
    --enc-model model.bin.enc --model-out model.dec

# 6. 拒绝路径：加入 --tamper measurement 重复步骤 5，期望 exit=2 且无 .dec 产出
```

---

## B. 真实 SEV-SNP 云实例复现（AMD Developer Cloud / MI300X）

### B.0 前置条件

- 一台支持 SEV-SNP 的 EPYC 实例（7003/8004/9004 系列），且实例类型
  明确支持机密 VM（SEV-SNP policy 启动）；
- Ubuntu 22.04/24.04，内核 ≥ 6.x（sev-guest 主线支持 ≥ 5.19）；
- ROCm 6.x（宿主或容器内），MI210/MI250/MI300X 任一。

### B.1 环境自检（第 1 周）

在（候选）机密 VM 内执行：

```bash
bash scripts/setup-sev-snp.sh
```

脚本检查五项：CPUID 是否声明 `sev_snp`、`/dev/sev-guest` 是否存在、
内核版本、ROCm 可用性、取证工具链（snpguest/sevctl）。任何一项
`[FAIL]` 都会在退出码 1 中体现。

### B.2 注册基线（第 2 周）

在**已知良好**的 VM 镜像构建中（内核/initrd/门控程序确定后）：

```bash
bash guest/measure-runtime.sh /boot/vmlinuz-6.8-sev /boot/initrd.img /opt/gate
# 打印的 96 位 hex 即度量基线
python scripts/measure_baseline.py \
    --kernel /boot/vmlinuz-6.8-sev --initrd /boot/initrd.img --gate /opt/gate \
    --name "mi300x-baseline-v1" --out krs/baselines/baseline.json
```

> 负测试对照：`krs/baselines/baseline-tampered.json` 为互补度量，
> KRS 换用该基线即可演示"篡改运行时 → 拒绝"。

### B.3 取证与门控（第 3 周）

KRS 侧（模型提供方可信环境）：

```bash
MODEL_KEY=$MODEL_KEY KRS_BASELINE=krs/baselines/baseline.json \
    uvicorn krs.server:app --host 0.0.0.0 --port 8443 \
    --ssl-keyfile krs.key --ssl-certfile krs.crt   # 生产必用 TLS
```

机密 VM 内：

```bash
# 1) 从 KRS 取挑战 nonce
NONCE=$(curl -s -X POST https://<krs>:8443/challenge | python -c \
    'import sys,json;print(json.load(sys.stdin)["nonce"])')

# 2) 用 snpguest 取证明报告（nonce 绑定进 REPORT_DATA）+ AMD KDS 证书
bash scripts/get-attestation.sh $NONCE

# 3) 门控：验证 → 密钥 → 流式解密 → 回执 → 拉起 vLLM
python guest/launch-gate.py --krs https://<krs>:8443 \
    --report-file /tmp/sev/report.bin --certs-dir /tmp/sev/certs \
    --enc-model /models/model.safetensors.enc \
    --model-out /run/model/model --launch-vllm
```

对照实验（录屏素材）：重复 3)，但在 KRS 侧改用
`baseline-tampered.json`，或对报告/运行时做篡改，记录 403 拒绝原因。

### B.4 延迟实验（第 4 周）

```bash
# 门控启动开销（VM 内一次）
/usr/bin/time -v python guest/launch-gate.py --krs https://<krs>:8443 ... 2> gate-time.txt

# 门控/非门控推理对照（同一 CSV 追加）
python guest/run-inference.py --url http://127.0.0.1:8000 \
    --scenario gated   --gate-ms <实测ms> --env mi300x-snp \
    --csv results/latency-gate-vs-nogate.csv
python guest/run-inference.py --url http://127.0.0.1:8000 \
    --scenario ungated --env mi300x-snp \
    --csv results/latency-gate-vs-nogate.csv
```

预期：门控成本集中在启动（证明+验签，秒级一次性）；逐 token 延迟
（ttft/tpot）两组应基本一致（SNP 内存加密 TCB 开销 ~1% 量级）。

---

## C. 故障排查速查

| 症状 | 原因 | 解法 |
|---|---|---|
| `accept` 场景也被拒：`ABI major 0 < required 1` | 报告 POLICY 位域填错（major 在 bit 8–15） | 用默认值 `0x10101`，参考 `snp_layout.py` 注释 |
| `VCEK report signature invalid` | 验签覆盖区/签名编码不对 | 签名区固定 `report[0x00:0x2A0]`；R[72]‖S[72] 定长大端，需 `encode_dss_signature` 转 DER |
| KRS 起动失败：`MODEL_KEY must be 32 bytes hex` | 环境变量未注入或长度不对 | `python scripts/encrypt-model.py genkey` 重新生成，64 个 hex 字符 |
| 真机取证 `ioctl failed: EINVAL` | 内核 uapi 结构差异 | 改走 snpguest CLI 路径（`scripts/get-attestation.sh`），脚本已自动兜底 |
| 真机验签失败但报告合法 | VCEK 与 TCB 版本绑定，固件升级后证书过期 | 重新 `snpguest fetch vcek`；KDS 按 chip_id+TCB 发证 |
| `nonce expired` | 挑战超 60s 才取证 | 先 `/challenge` 后立即取证；可调 `NONCE_TTL_SECONDS` |
| 解密抛 `InvalidTag` | 密钥不对或密文被改动 | 这正是门控生效的表现：检查 KRS 释放的密钥与加密侧是否一致 |

更多背景见 `docs/sev-snp-primer.md`（证明链原理）与
`docs/threat-model.md`（覆盖/不覆盖的威胁边界）。
