#!/usr/bin/env python3
# guest/run-inference.py
"""
Inference client + latency measurement for the gated vLLM server.

Sends prompts to the vLLM OpenAI-compatible endpoint and records:

    ttft_ms    time-to-first-token (streaming)
    tpot_ms    average time-per-output-token after the first
    e2e_ms     end-to-end completion latency
    gate_ms    (optionally supplied) one-shot gate overhead measured by
               launch-gate.py, so "gated" and "ungated" runs share one CSV.

Results are appended to results/latency-gate-vs-nogate.csv so a single
file accumulates both conditions for the practice report.

Usage:
    python guest/run-inference.py --url http://127.0.0.1:8000 \
        --prompt "Explain SEV-SNP in one sentence." \
        --gate-ms 1234 --scenario "gated/mock" \
        --csv results/latency-gate-vs-nogate.csv
"""

from __future__ import annotations

import argparse
import json
import time
import urllib.request
from pathlib import Path


def openai_style_complete(url: str, prompt: str, max_tokens: int,
                          temperature: float = 0.7,
                          timeout: float = 120.0) -> dict:
    """Non-streaming completion (simple path, measures e2e latency)."""
    payload = {
        "model": "gated-model",
        "prompt": prompt,
        "max_tokens": max_tokens,
        "temperature": temperature,
    }
    req = urllib.request.Request(
        f"{url.rstrip('/')}/v1/completions",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    t0 = time.perf_counter()
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = json.loads(resp.read().decode())
    return {"e2e_ms": (time.perf_counter() - t0) * 1000,
            "text": body["choices"][0].get("text", ""),
            "usage": body.get("usage", {})}


def hf_local_generate(model_dir: str, prompt: str, max_tokens: int,
                      temperature: float = 0.7) -> dict:
    """
    Local HuggingFace transformers inference (no server needed).

    Works on ROCm (torch.cuda.is_available() == True on AMD via HIP),
    CUDA or CPU. Measures ttft/tpot with a streamer hook — this is the
    lightweight fallback when installing vLLM-ROCm is too heavy for a
    limited cloud quota.
    """
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer, TextStreamer

    device = "cuda" if torch.cuda.is_available() else "cpu"
    dtype = torch.float16 if device == "cuda" else torch.float32
    if device == "cuda":
        print(f"[infer] GPU: {torch.cuda.get_device_name(0)} "
              f"({torch.cuda.get_device_properties(0).total_memory / 1e9:.1f} GB)")

    tok = AutoTokenizer.from_pretrained(model_dir)
    model = AutoModelForCausalLM.from_pretrained(
        model_dir, torch_dtype=dtype).to(device)
    model.eval()

    state = {"t0": None, "ttft": None, "ntok": 0}

    class _Timer(TextStreamer):
        def put(self, value):
            if state["ttft"] is None:
                state["ttft"] = time.perf_counter() - state["t0"]
            state["ntok"] += 1
            super().put(value)

    inputs = tok(prompt, return_tensors="pt").to(device)
    state["t0"] = time.perf_counter()
    with torch.inference_mode():
        model.generate(
            **inputs, max_new_tokens=max_tokens, do_sample=temperature > 0,
            temperature=max(temperature, 1e-5),
            streamer=_Timer(tok), pad_token_id=tok.eos_token_id)
    e2e = time.perf_counter() - state["t0"]
    n = max(state["ntok"] - 1, 1)
    return {
        "e2e_ms": e2e * 1000,
        "ttft_ms": (state["ttft"] or 0) * 1000,
        "tpot_ms": ((e2e - (state["ttft"] or 0)) / n) * 1000,
        "output_tokens": state["ntok"],
        "prompt_tokens": int(inputs["input_ids"].shape[1]),
        "text": "",
    }


def append_csv(csv_path: str, row: dict) -> None:
    import csv
    import datetime
    p = Path(csv_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    header = ["timestamp", "scenario", "env", "model", "prompt_tokens",
              "output_tokens", "ttft_ms", "tpot_ms", "e2e_ms",
              "gate_ms", "notes"]
    full = {"timestamp": datetime.datetime.now().isoformat(timespec="seconds"),
            **{k: "" for k in header if k != "timestamp"}, **row}
    new = not p.exists()
    with open(p, "a", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        if new:
            w.writerow(header)
        w.writerow([full[h] for h in header])


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--engine", choices=["vllm", "hf"], default="vllm",
                    help="vllm: HTTP against a running vLLM server; "
                         "hf: local transformers load (no server)")
    ap.add_argument("--url", default="http://127.0.0.1:8000")
    ap.add_argument("--model-dir", default="",
                    help="local decrypted model dir (engine=hf)")
    ap.add_argument("--prompt",
                    default="Explain SEV-SNP remote attestation in one sentence.")
    ap.add_argument("--max-tokens", type=int, default=64)
    ap.add_argument("--scenario", default="gated")
    ap.add_argument("--env", default="mi300x")
    ap.add_argument("--model", default="qwen2.5-1.5b")
    ap.add_argument("--gate-ms", default="", help="gate overhead from launch-gate")
    ap.add_argument("--csv", default="results/latency-gate-vs-nogate.csv")
    ap.add_argument("--repeats", type=int, default=1)
    args = ap.parse_args(argv)

    for _ in range(args.repeats):
        if args.engine == "hf":
            if not args.model_dir:
                ap.error("--model-dir is required with --engine hf")
            out = hf_local_generate(args.model_dir, args.prompt,
                                    args.max_tokens)
            prompt_tokens = out["prompt_tokens"]
            output_tokens = out["output_tokens"]
            append_csv(args.csv, {
                "scenario": args.scenario, "env": args.env, "model": args.model,
                "prompt_tokens": prompt_tokens, "output_tokens": output_tokens,
                "ttft_ms": f"{out['ttft_ms']:.1f}",
                "tpot_ms": f"{out['tpot_ms']:.1f}",
                "e2e_ms": f"{out['e2e_ms']:.1f}", "gate_ms": args.gate_ms,
                "notes": f"hf-transformers device="
                         f"{'gpu' if out['ttft_ms'] else 'cpu'}",
            })
            print(f"[infer] ttft={out['ttft_ms']:.0f}ms "
                  f"tpot={out['tpot_ms']:.0f}ms e2e={out['e2e_ms']:.0f}ms "
                  f"| {output_tokens} tokens")
            continue
        out = openai_style_complete(args.url, args.prompt, args.max_tokens)
        usage = out["usage"]
        prompt_tokens = usage.get("prompt_tokens", "")
        output_tokens = usage.get("completion_tokens", "")
        # single-request estimate: tpot = (e2e - ttft_est) / (n-1); without
        # streaming we record e2e only and note ttft as measured on device.
        append_csv(args.csv, {
            "scenario": args.scenario, "env": args.env, "model": args.model,
            "prompt_tokens": prompt_tokens, "output_tokens": output_tokens,
            "e2e_ms": f"{out['e2e_ms']:.1f}", "gate_ms": args.gate_ms,
            "notes": "non-streaming",
        })
        print(f"[infer] {out['e2e_ms']:.1f} ms | "
              f"{output_tokens} tokens | {out['text'][:80]!r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
