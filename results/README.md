# results/ — 实验证据

## attestation-accept-vs-reject.log

由 `python scripts/demo_local.py --fresh` 生成的门控行为日志，覆盖六个场景：

| 场景 | 期望 | KRS 行为 | 触发的校验层 |
|---|---|---|---|
| accept（基线匹配） | RELEASE | 释放密钥，权重解密且 SHA-256 比对通过 | 全链路 |
| tamper-measurement | DENY | 拒绝 | 度量比对 |
| tamper-signature | DENY | 拒绝 | VCEK 报告签名验证 |
| tamper-tcb | DENY | 拒绝 | TCB 防回滚 |
| tamper-report-data | DENY | 拒绝 | nonce 新鲜度（REPORT_DATA） |
| nonce-reuse | DENY | 拒绝 | 一次性 nonce（防重放） |

日志中每条拒绝记录都带 KRS 返回的具体 403 原因，可作为录屏脚本的
对照材料。

## latency-gate-vs-nogate.csv

门控开销测量。当前数据来自 mock 环境（笔记本、无 SEV-SNP 硬件），
`gate_ms` 含子进程启动与 mock 报告生成，因此偏保守（约 0.7–1.3 s）。

在 MI300X + SEV-SNP 实例上复测时，请补充以下行（列已预留）：

```bash
# 门控启动（VM 内执行一次）
/usr/bin/time -v python guest/launch-gate.py --krs https://<krs> \
    --enc-model /models/model.enc --model-out /run/model/model --launch-vllm

# 推理延迟（门控不影响逐 token 延迟，两组对照）
python guest/run-inference.py --scenario gated   --gate-ms <实测值> \
    --env mi300x-snp --csv results/latency-gate-vs-nogate.csv
python guest/run-inference.py --scenario ungated --env mi300x-snp \
    --csv results/latency-gate-vs-nogate.csv
```

预期（依据 SNP 内存加密 TCB 开销约 1% 量级 + 门控为一次性启动开销）：
门控成本集中在启动阶段（证明报告生成 + KRS 验签，秒级），逐 token
延迟（ttft_ms / tpot_ms）两组应基本一致。

> 注：CSV 中带引号字段含逗号，为标准 RFC 4180 格式，可用 pandas
> `read_csv` 直接解析。
