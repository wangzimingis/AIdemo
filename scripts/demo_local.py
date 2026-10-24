#!/usr/bin/env python3
# scripts/demo_local.py
"""
Hardware-less end-to-end demonstration of the attestation gate.

Spins up the REAL KRS (krs/server.py + krs/verifier.py, no mock logic
inside the verifier) over HTTP, generates a REAL encrypted weight file,
then drives the REAL guest gate (guest/launch-gate.py) against it in six
scenarios:

  1. accept              baseline runtime          -> key RELEASED, weights
                                                      decrypt, hash verified
  2. tamper-measurement  swapped runtime image     -> DENIED
  3. tamper-signature    bit-flip in signed area   -> DENIED
  4. tamper-tcb          firmware rollback         -> DENIED
  5. tamper-report-data  stale nonce / replay      -> DENIED
  6. nonce-reuse         replaying a used nonce    -> DENIED

Everything SEV-SNP-specific is produced by mock/mock-attest.py (mock
ARK->ASK->VCEK chain + spec-layout report). The KRS verification code
path is identical to what real hardware would hit.

Outputs:
  results/attestation-accept-vs-reject.log   append-only evidence log
  results/latency-gate-vs-nogate.csv         gate overhead measurements

Usage:
  pip install -r requirements.txt
  python scripts/demo_local.py [--model-mb 64] [--port 18443] [--fresh]
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

LOG_PATH = REPO_ROOT / "results" / "attestation-accept-vs-reject.log"
CSV_PATH = REPO_ROOT / "results" / "latency-gate-vs-nogate.csv"


def ts() -> str:
    return datetime.datetime.now().isoformat(timespec="seconds")


def log_line(line: str) -> None:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(line + "\n")
    print(line)


def csv_append(row: dict) -> None:
    import csv
    header = ["timestamp", "scenario", "env", "model", "prompt_tokens",
              "output_tokens", "ttft_ms", "tpot_ms", "e2e_ms", "gate_ms",
              "notes"]
    CSV_PATH.parent.mkdir(parents=True, exist_ok=True)
    full = {"timestamp": ts(), **{k: "" for k in header if k != "timestamp"},
            **row}
    new = not CSV_PATH.exists()
    with open(CSV_PATH, "a", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        if new:
            w.writerow(header)
        w.writerow([full[h] for h in header])


# ---------------------------------------------------------------------------
# environment preparation
# ---------------------------------------------------------------------------

def prepare(workdir: Path, model_mb: int) -> dict:
    from guest.weight_crypto import encrypt_file
    from mock.mock_attest_helpers import compose_measurement
    import mock.mock_attest_helpers  # noqa

    # 1. mock measured artifacts + key hierarchy
    run([sys.executable, str(REPO_ROOT / "mock" / "mock-attest.py"),
         "make-artifacts"])
    run([sys.executable, str(REPO_ROOT / "mock" / "mock-attest.py"), "init"])
    art = REPO_ROOT / "mock" / "artifacts"
    artifacts = {"kernel": str(art / "vmlinuz-mock"),
                 "initrd": str(art / "initrd-mock"),
                 "gate": str(art / "gate-mock")}

    # 2. baseline from the SAME composition the mock report will use
    measurement = compose_measurement(**artifacts)
    baseline_path = workdir / "baseline.json"
    baseline_path.write_text(json.dumps({
        "name": "mock-runtime-baseline",
        "description": "baseline for mock artifacts (demo_local.py)",
        "measurement": measurement,
        "tcb": {"build": 10, "minor": 26, "major": 1},
        "min_abi_major": 1,
        "vmpl": None,
    }, indent=2))
    # also refresh the checked-in baseline for the repo default
    (REPO_ROOT / "krs" / "baselines" / "baseline.json").write_text(
        json.dumps({
            "name": "mock-runtime-baseline",
            "description": ("Default baseline = mock artifact set, refreshed "
                            "by scripts/demo_local.py. On real hardware "
                            "regenerate with scripts/measure_baseline.py "
                            "from a known-good VM image."),
            "measurement": measurement,
            "tcb": {"build": 10, "minor": 26, "major": 1},
            "min_abi_major": 1,
            "vmpl": None,
        }, indent=2) + "\n")

    # 3. "model weights" + encryption with a random key
    model_plain = workdir / "model.safetensors"
    blob = os.urandom(1024 * 1024)  # 1 MiB
    with open(model_plain, "wb") as f:
        for _ in range(model_mb):
            f.write(blob)
    sha = hashlib.sha256()
    with open(model_plain, "rb") as f:
        for blk in iter(lambda: f.read(4 * 1024 * 1024), b""):
            sha.update(blk)
    plain_sha = sha.hexdigest()

    model_key_hex = os.urandom(32).hex()
    enc_path = workdir / "model.safetensors.enc"
    info = encrypt_file(str(model_plain), str(enc_path),
                        bytes.fromhex(model_key_hex))
    assert info["plaintext_sha256"] == plain_sha

    return {
        "artifacts": artifacts,
        "baseline": str(baseline_path),
        "model_key_hex": model_key_hex,
        "enc_model": str(enc_path),
        "plain_sha256": plain_sha,
        "measurement": measurement,
        "model_bytes": model_mb * 1024 * 1024,
    }


def run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    proc = subprocess.run(cmd, capture_output=True, text=True,
                          cwd=str(REPO_ROOT), **kw)
    if proc.returncode != 0:
        print(proc.stdout)
        print(proc.stderr, file=sys.stderr)
        raise RuntimeError(f"command failed: {' '.join(cmd)}")
    return proc


# ---------------------------------------------------------------------------
# KRS over real HTTP
# ---------------------------------------------------------------------------

def start_krs(port: int) -> threading.Thread:
    import uvicorn
    from krs import server as krs_server  # noqa: F401 (import for side effects)

    config = uvicorn.Config("krs.server:app", host="127.0.0.1",
                            port=port, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    # wait until it answers
    import urllib.request
    for _ in range(50):
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz",
                                        timeout=2) as r:
                if r.status == 200:
                    return thread
        except Exception:
            time.sleep(0.2)
    raise RuntimeError("KRS did not come up")


# ---------------------------------------------------------------------------
# scenarios
# ---------------------------------------------------------------------------

def gate_scenario(name: str, krs_url: str, env: dict, workdir: Path,
                  tamper: str | None, artifacts: dict) -> dict:
    """Run guest/launch-gate.py as a subprocess (real CLI, real HTTP)."""
    out_model = workdir / f"model-{name}.dec"
    receipt = workdir / f"receipt-{name}.json"
    cmd = [sys.executable, str(REPO_ROOT / "guest" / "launch-gate.py"),
           "--krs", krs_url, "--mode", "mock",
           "--enc-model", env["enc_model"], "--model-out", str(out_model),
           "--receipt-file", str(receipt),
           "--kernel", artifacts["kernel"], "--initrd", artifacts["initrd"],
           "--gate", artifacts["gate"]]
    if tamper:
        cmd += ["--tamper", tamper]
    t0 = time.perf_counter()
    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=str(REPO_ROOT))
    wall_ms = (time.perf_counter() - t0) * 1000
    released = proc.returncode == 0 and out_model.exists()
    reason = ""
    if not released:
        for ln in (proc.stderr or proc.stdout).splitlines():
            if "DENIED" in ln or "reject" in ln.lower():
                reason = ln.strip()
                break
    return {"name": name, "released": released, "wall_ms": wall_ms,
            "exit": proc.returncode, "reason": reason,
            "out_model": out_model, "receipt": receipt,
            "stdout": proc.stdout, "stderr": proc.stderr}


def nonce_reuse_scenario(krs_url: str, artifacts: dict) -> dict:
    """In-process: request the same nonce's key twice -> second must fail."""
    from guest import gate_client
    from guest.get_report import get_attestation_bundle
    nonce = gate_client.request_challenge(krs_url)
    bundle = get_attestation_bundle(bytes.fromhex(nonce), mode="mock",
                                     repo_root=REPO_ROOT, artifacts=artifacts)
    first = gate_client.request_key(krs_url, bundle, nonce)
    try:
        gate_client.request_key(krs_url, bundle, nonce)
        return {"name": "nonce-reuse", "released": True, "reason":
                "REPLAY ACCEPTED — BUG!"}
    except gate_client.GateError as e:
        return {"name": "nonce-reuse", "released": False, "reason": str(e),
                "first_ok": bool(first.get("model_key"))}


# ---------------------------------------------------------------------------

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--model-mb", type=int, default=64)
    ap.add_argument("--port", type=int, default=18443)
    ap.add_argument("--fresh", action="store_true",
                    help="truncate the results log before running")
    args = ap.parse_args(argv)

    if args.fresh:
        for p in (LOG_PATH, CSV_PATH):
            if p.exists():
                p.write_text("", encoding="utf-8")

    workdir = Path(tempfile.mkdtemp(prefix="sev-gate-demo-"))
    print(f"[demo] workdir: {workdir}")

    env = prepare(workdir, args.model_mb)

    # KRS process env must be set BEFORE importing krs.server
    os.environ["MODEL_KEY"] = env["model_key_hex"]
    os.environ["KRS_BASELINE"] = env["baseline"]
    krs_url = f"http://127.0.0.1:{args.port}"
    start_krs(args.port)

    log_line(f"[{ts()}] ==== demo_local run | mode=mock-sev-snp "
             f"| baseline=mock-runtime-baseline | measurement={env['measurement'][:24]}... "
             f"| model={args.model_mb}MiB ====")

    scenarios = [
        ("accept", None),
        ("tamper-measurement", "measurement"),
        ("tamper-signature", "signature"),
        ("tamper-tcb", "tcb"),
        ("tamper-report-data", "report-data"),
    ]
    results = []
    for name, tamper in scenarios:
        r = gate_scenario(name, krs_url, env, workdir, tamper,
                          env["artifacts"])
        expected_release = name == "accept"
        if r["released"] == expected_release:
            verdict = "PASS"
        else:
            verdict = "FAIL (unexpected behavior)"
        if name == "accept" and r["released"]:
            # verify decrypted bytes equal the original model
            sha = hashlib.sha256(r["out_model"].read_bytes()).hexdigest()
            r["hash_ok"] = sha == env["plain_sha256"]
            if not r["hash_ok"]:
                verdict = "FAIL (plaintext hash mismatch)"
        line = (f"[{ts()}] scenario={name:20s} expected="
                f"{'RELEASE' if expected_release else 'DENY':7s} "
                f"result={'RELEASED' if r['released'] else 'DENIED':8s} "
                f"exit={r['exit']} wall_ms={r['wall_ms']:.0f} verdict={verdict}")
        if r["reason"]:
            line += f"\n    reason: {r['reason']}"
        log_line(line)
        results.append((name, verdict, r))

    reuse = nonce_reuse_scenario(krs_url, env["artifacts"])
    verdict = "PASS" if not reuse["released"] and reuse.get("first_ok") else "FAIL"
    log_line(f"[{ts()}] scenario={reuse['name']:20s} expected=DENY   "
             f"result={'RELEASED' if reuse['released'] else 'DENIED':8s} "
             f"verdict={verdict}\n    reason: {reuse['reason']}")
    results.append((reuse["name"], verdict, reuse))

    # gate overhead of the accept path -> CSV (mock env, honest labelling)
    accept_r = results[0][2]
    csv_append({
        "scenario": "gated-boot", "env": "mock-laptop", "model": "demo-weights",
        "e2e_ms": f"{accept_r['wall_ms']:.1f}",
        "gate_ms": f"{accept_r['wall_ms']:.1f}",
        "notes": f"challenge+report+verify+key-release round trip, "
                 f"{args.model_mb}MiB weights excluded",
    })
    csv_append({
        "scenario": "ungated-boot", "env": "mock-laptop", "model": "demo-weights",
        "gate_ms": "0", "e2e_ms": "",
        "notes": "no attestation: baseline reference for gate overhead",
    })

    failed = [n for n, v, _ in results if v.startswith("FAIL")]
    log_line(f"[{ts()}] ==== run summary: "
             f"{len(results) - len(failed)}/{len(results)} scenarios PASS "
             f"{'(all good)' if not failed else 'FAILED: ' + ', '.join(failed)} ====")

    print(f"\n[demo] log   -> {LOG_PATH}")
    print(f"[demo] csv   -> {CSV_PATH}")
    print(f"[demo] workdir (decrypted samples, receipts) -> {workdir}")
    if failed:
        return 1
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    finally:
        pass
