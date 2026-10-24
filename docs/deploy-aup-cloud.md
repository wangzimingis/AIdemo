# AUP Learning Cloud 部署指南（tpe.aupcloud.io）

> AUP Learning Cloud 是 AMD 大学合作部（AUP）提供的 JupyterHub 学习云：
> GitHub 授权登录、浏览器版 VSCode（Code Server）、AMD GPU + ROCm 环境。
> 本指南把本仓库部署上去，跑通 **mock 门控 + 真实 AMD GPU 推理**。

## 0. 先明确这个平台能跑到哪一步（诚实边界）

| 环节 | 在 AUP 上 | 说明 |
|---|---|---|
| 门控协议（挑战/证明/验签/密钥释放） | ✅ 完整可跑 | 用 mock SEV-SNP 报告；KRS 验签代码路径与真硬件零分支 |
| 权重加密/解密 + 逐文件校验 + 回执 | ✅ 完整可跑 | 真实 AES-256-GCM 代码路径 |
| 真实 GPU 推理（解密后跑 Qwen） | ✅ 完整可跑 | ROCm + transformers（vLLM 可选） |
| **真实 SEV-SNP 证明** | ❌ **不可能** | AUP 给的是**容器**（K8s pod），没有 `/dev/sev-guest`；SEV-SNP 需要专用 SNP-policy 虚拟机（EPYC 服务器硬件）。此环节仍走 mock，或另申请 AMD Developer Cloud cSP 实例 |

> 报告/录屏建议明确标注："门控与 GPU 推理在 AUP 真实 AMD 硬件上执行；
> TEE 证明环节因平台为容器形态，采用与规范同构的 mock 证明链"。

## 1. 启动环境

1. 浏览器打开 `https://tpe.aupcloud.io` → **Use GitHub Login** 授权；
2. 在 spawn 页面选择 **Code Server GPU Environment**（即 `?resource=code-gpu`）；
3. 选硬件（如 AMD Radeon 8060S / PRO 7900D）与运行时长 → Launch Server；
4. 浏览器打开 Code Server（VSCode 界面），`` Ctrl+` `` 呼出终端。

⚠️ **持久化**：默认工作目录会被重置；**必须把一切要保留的东西放在
`/home/jovyan`（20GB 持久盘）**。平台额度有限（初始约 10 小时），
做完一组实验就 Stop my server。

## 2. 取代码 + 装依赖（终端里执行）

推荐先把仓库推到你自己的 GitHub（课程交付也需要），然后：

```bash
cd /home/jovyan
git clone https://github.com/<你的用户名>/sev-snp-attested-inference-gate.git
cd sev-snp-attested-inference-gate
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

（没有 GitHub 仓库时：把本地项目打包成 zip，用 Code Server 的
资源管理器拖拽上传到 `/home/jovyan`，再 `unzip`。）

## 3. 第一关：六场景门控演示（约 2 分钟）

```bash
bash scripts/setup-sev-snp.sh   # 环境自检：会如实报告容器内无 SEV-SNP（预期）
python scripts/demo_local.py --fresh   # 六场景 6/6 PASS
```

`setup-sev-snp.sh` 的 FAIL 输出本身就是"平台为容器形态、无 SNP 设备"
的证据，截图留档；`rocminfo` 段会显示 GPU 可用。

## 4. 第二关：真实模型 + 真实 GPU（核心增量）

### 4.1 下载模型（国内网络用 ModelScope）

```bash
pip install modelscope
modelscope download --model Qwen/Qwen2.5-1.5B-Instruct \
    --local_dir /home/jovyan/models/qwen2.5-1.5b-instruct
```

### 4.2 模型提供方视角：整目录加密

```bash
python scripts/encrypt-model.py genkey --out .env.modelkey
export MODEL_KEY=$(grep MODEL_KEY .env.modelkey | cut -d= -f2)
python scripts/encrypt-model.py encrypt-dir \
    --key-hex $MODEL_KEY \
    --in  /home/jovyan/models/qwen2.5-1.5b-instruct \
    --out /home/jovyan/models/qwen2.5-1.5b-instruct.encd
```

产物是 `<文件名>.enc` 全目录 + `manifest.json`（逐文件 SHA-256）。
明文目录此时可删除，模拟"云端只有密文"。

### 4.3 起 KRS（终端 1）

```bash
export MODEL_KEY=$(grep MODEL_KEY .env.modelkey | cut -d= -f2)
export KRS_BASELINE=krs/baselines/baseline.json
uvicorn krs.server:app --host 127.0.0.1 --port 8443
```

Code Server 会自动做**端口转发**，浏览器可经
`https://tpe.aupcloud.io/user/<你的用户名>/proxy/8443/healthz`
直接看到 KRS 状态——录屏时展示这个 URL 很直观。

### 4.4 门控启动：密钥释放 → 解密 → 真实推理（终端 2）

```bash
pip install torch --index-url https://download.pytorch.org/whl/rocm*  # 按平台 ROCm 版本选
pip install transformers

python guest/launch-gate.py \
    --krs http://127.0.0.1:8443 --mode mock \
    --enc-dir /home/jovyan/models/qwen2.5-1.5b-instruct.encd \
    --model-out /home/jovyan/run/model \
    --receipt-file /home/jovyan/run/receipt.json
```

放行后再跑推理与延迟测量（gated 与 ungated 各一组，进同一 CSV）：

```bash
# 门控路径（刚解密出的模型）
python guest/run-inference.py --engine hf \
    --model-dir /home/jovyan/run/model \
    --scenario gated --gate-ms <上一步日志里的 gate 耗时> \
    --env aup-radeon --csv results/latency-gate-vs-nogate.csv

# 非门控基线（直接加载明文模型，绕过门控）
python guest/run-inference.py --engine hf \
    --model-dir /home/jovyan/models/qwen2.5-1.5b-instruct \
    --scenario ungated \
    --env aup-radeon --csv results/latency-gate-vs-nogate.csv
```

`--engine hf` 直接用 transformers 本地加载（ROCm 下
`torch.cuda.is_available()` 为 True），逐 token 记录 **ttft/tpot**；
预期两组逐 token 延迟一致——门控只是启动期一次性成本。

### 4.5 拒绝路径对照（录屏负例）

```bash
python guest/launch-gate.py --krs http://127.0.0.1:8443 --mode mock \
    --enc-dir /home/jovyan/models/qwen2.5-1.5b-instruct.encd \
    --model-out /home/jovyan/run/model-bad --tamper measurement
# 期望: exit=2, "measurement mismatch", /home/jovyan/run/model-bad 不存在
```

### 4.6 （可选）vLLM-ROCm 高吞吐服务

额度充足且平台镜像带 ROCm 7.x 时可装 vLLM ROCm 构建（或用官方
rocm/vllm 容器），替换 `--engine hf` 为 `--engine vllm --url ...`：
门控命令加 `--launch-vllm`，vLLM 端口经 Code Server 端口转发对外。
装不上不影响交付——hf 路径已足够拿到延迟数据。

## 5. 收尾：把证据带回持久目录并提交

```bash
cp -r results /home/jovyan/sev-snp-attested-inference-gate/
cd /home/jovyan/sev-snp-attested-inference-gate
git add results/ && git commit -m "add AUP cloud (Radeon/ROCm) run evidence"
git push
```

## 6. 常见坑（AUP 特供）

| 症状 | 解法 |
|---|---|
| 会话结束文件全没了 | 忘了放 `/home/jovyan`；重做前先迁移 |
| pip 装 torch 特别慢/失败 | 用平台自带镜像的 Python 环境，或选对 rocm wheel 版本；`pip cache purge` 后重试 |
| `rocminfo` 无 GPU | spawn 时选错了 CPU 环境；Stop my server 后换 Code Server GPU Environment |
| 端口转发没弹通知 | 在 Code Server 的 PORTS 面板手动加端口（8443/8000） |
| 额度用尽 | 实验前把命令写成脚本一次跑完；模型/venv 放 `/home/jovyan` 避免重复下载 |
| KRS 起不来：MODEL_KEY 报错 | 环境变量没 export（`echo $MODEL_KEY` 检查），64 个 hex 字符 |
