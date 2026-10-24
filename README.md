# sev-snp-attested-inference-gate

**基于 AMD SEV-SNP 与 ROCm 的最小化机密 AI 推理门控：远程证明驱动的模型权重释放**

模型权重密文上云；独立的 Key Release Server（KRS）持有密钥；只有当
SEV-SNP 证明报告通过**证书链验签（VCEK→ASK→ARK）+ 启动度量基线比对 +
TCB 防回滚 + nonce 新鲜度**校验后，密钥才被释放；推理仅在密钥释放后的
机密 VM 内经 ROCm/vLLM 执行，权重明文始终处于 SEV-SNP 加密内存中。

> 课程实践级最小实现，**未经生产安全审计**。威胁覆盖与边界见
> [docs/threat-model.md](docs/threat-model.md)。
>
> 📋 完整复现步骤（mock 五分钟 → 真实硬件 → 故障排查）见
> [REPRODUCTION.md](REPRODUCTION.md)。
> ☁️ AUP Learning Cloud（AMD ROCm 学习云）部署指南见
> [docs/deploy-aup-cloud.md](docs/deploy-aup-cloud.md)。

## 架构

```
┌─────────────────────────────┐
│   Key Release Server (KRS)   │
│  持有：模型加密密钥           │
│        允许的运行时度量基线   │
└──────────────┬──────────────┘
               │ ① /challenge 下发一次性 nonce
               │ ② guest 经 /dev/sev-guest 取证明报告（nonce 写入 REPORT_DATA）
               │ ③ KRS：证书链验签→签名→度量→TCB→策略，全过才 /release-key
               ▼
┌─────────────────────────────┐
│   AMD SEV-SNP 机密 VM        │
│   kernel+initrd+gate 被度量  │
│   ④ 流式解密权重（tmpfs）    │
│   ⑤ vLLM/ROCm 推理           │
│   内存受 SNP 加密，宿主不可读 │
└─────────────────────────────┘
   （拒绝时权重保持密文，推理无法启动）
```

## 五分钟跑通端到端门控（无需任何硬件）

mock 模式生成与规范同构的证明报告与 P-384 证书链，KRS 的验证代码
路径与真实硬件完全一致——六个场景覆盖一条基线放行 + 五种篡改拒绝：

```bash
python -m venv .venv && .venv/Scripts/pip install -r requirements.txt   # Linux: source .venv/bin/activate
python scripts/demo_local.py --fresh
```

期望输出（实测，2026-10-24）：

```
accept              expected=RELEASE result=RELEASED  PASS   （解密后 SHA-256 校验一致）
tamper-measurement  expected=DENY    result=DENIED    PASS   （measurement mismatch）
tamper-signature    expected=DENY    result=DENIED    PASS   （VCEK signature invalid）
tamper-tcb          expected=DENY    result=DENIED    PASS   （TCB rollback detected）
tamper-report-data  expected=DENY    result=DENIED    PASS   （nonce mismatch）
nonce-reuse         expected=DENY    result=DENIED    PASS   （replay）
6/6 scenarios PASS
```

证据落在 `results/attestation-accept-vs-reject.log` 与
`results/latency-gate-vs-nogate.csv`。

## 真实硬件流程（SEV-SNP 云实例，如 AMD Developer Cloud MI300X）

```bash
# W1: 环境验证（cpuinfo / /dev/sev-guest / 内核 / ROCm / 工具链）
bash scripts/setup-sev-snp.sh

# W2: 基线注册（在已知良好镜像内执行；度量=SHA-384(kernel‖initrd‖gate)）
bash guest/measure-runtime.sh /boot/vmlinuz /boot/initrd.img /opt/gate
python scripts/measure_baseline.py --kernel ... --initrd ... --gate ... \
    --out krs/baselines/baseline.json

# 模型侧（可信环境）加密权重
python scripts/encrypt-model.py genkey --out .env.modelkey
python scripts/encrypt-model.py encrypt --key-hex $MODEL_KEY \
    --in model.safetensors --out /models/model.safetensors.enc

# 启动 KRS（密钥与基线仅经环境变量注入）
MODEL_KEY=$MODEL_KEY KRS_BASELINE=krs/baselines/baseline.json \
    uvicorn krs.server:app --host 0.0.0.0 --port 8443 --ssl-keyfile ... --ssl-certfile ...

# W3: VM 内取证（challenge nonce 绑定进 REPORT_DATA）
bash scripts/get-attestation.sh $NONCE_HEX          # snpguest 路径
# 门控启动：请求密钥→解密→回执→拉起 vLLM
python guest/launch-gate.py --krs https://krs:8443 --launch-vllm \
    --enc-model /models/model.safetensors.enc --model-out /run/model/model

# W4: 延迟对比
python guest/run-inference.py --scenario gated   --gate-ms <实测> --env mi300x-snp
python guest/run-inference.py --scenario ungated --env mi300x-snp
```

## 仓库结构

```
├── README.md                  # 本文件
├── docs/
│   ├── sev-snp-primer.md      # SEV-SNP 证明链与度量机制简明说明
│   ├── threat-model.md        # 威胁模型与度量边界（覆盖 T1–T7 / 不覆盖 N1–N6）
│   └── practice-report.md     # 实践报告（含试用平台体会）
├── common/snp_layout.py       # 规范 Table 22 报告布局，验签/生成共用
├── krs/
│   ├── server.py              # /challenge + /release-key（七步校验）
│   ├── verifier.py            # 自实现：证书链 + ECDSA-P384 验签 + 度量/TCB/策略
│   └── baselines/             # 正常基线 + 篡改基线（负测试）
├── guest/
│   ├── launch-gate.py         # 门控入口：挑战→取证→密钥→解密→回执→vLLM
│   ├── gate_client.py / get_report.py   # KRS 协议客户端 / 报告获取(ioctl|snpguest|mock)
│   ├── decrypt_and_serve.py / weight_crypto.py  # 流式 AES-256-GCM 解密与启动
│   ├── run-inference.py       # 推理压测 + 延迟 CSV
│   └── measure-runtime.sh     # 度量基线采集
├── mock/
│   ├── mock-attest.py         # 仿真 ARK/ASK/VCEK + 规范布局报告 + 篡改注入
│   └── mock_attest_helpers.py # 度量组合（与 measure-runtime.sh 同一公式）
├── scripts/
│   ├── setup-sev-snp.sh       # W1 环境自检
│   ├── get-attestation.sh     # W3 snpguest 取证（nonce 绑定）
│   ├── encrypt-model.py       # 模型侧权重加密
│   ├── measure_baseline.py    # 基线生成/刷新
│   └── demo_local.py          # 无硬件端到端演示（六场景）
└── results/                   # 门控放行/拒绝日志 + 延迟数据
```

## 与 RAI 等研究项目的差异

不提出新证明协议，而是把"最小可信链"（报告→证书链→度量→密钥）在
可公开复购的 AMD 云硬件 + 全开源栈（主线内核 sev-guest、ROCm、vLLM）
上端到端打通，并**明确标注度量边界**（ROCm 用户态库不在启动度量内，
需 IMA/dm-verity 作为后续工作）。硬件证明解决的是密钥释放的信任问题，
不声称解决侧信道问题。

## 开源声明

- 核心代码（验签、门控、度量收集）全部开源（MIT，见 LICENSE）；
- 模型建议使用公开小模型（Qwen2.5-1.5B / TinyLlama），FP16 或
  FP8-dynamic 加载（ROCm 上 AWQ 支持不完整）；
- KRS 密钥材料仅以环境变量注入（`.env.example`），仓库不含任何真实
  密钥；mock 生成的密钥仅用于本地演示，标记 `Mock`；
- 本 Demo 为课程实践级最小实现，未经过生产安全审计。

## 参考

- AMD SEV-SNP Firmware ABIs Specification（公开）
- AMD Memory Encryption 白皮书；AMD KDS（VCEK 分发服务）
- Linux `include/uapi/linux/sev-guest.h`（主线 ≥5.19）
- virtee/snpguest、virtee/sevctl（取证工具）
- ROCm / vLLM（ROCm build）
