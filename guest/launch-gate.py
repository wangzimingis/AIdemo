#!/usr/bin/env python3
# guest/launch-gate.py
"""
Confidential VM boot-time gate (the "door keeper" entrypoint).

Flow (runs INSIDE the SEV-SNP VM at boot, before any inference):

    KRS /challenge   -> nonce
    sev-guest report -> attestation binding the nonce in REPORT_DATA
    KRS /release-key -> model decryption key     (only if baseline matches)
    stream-decrypt   -> weights plaintext stays in SEV-SNP encrypted RAM
    receipt          -> execution evidence for the next attestation
    exec vLLM        -> inference starts

If the KRS refuses (tampered measurement, bad signature, rollback TCB,
stale nonce), the process exits non-zero and the model directory stays
encrypted: inference can never start on an unattested runtime.

Usage (mock mode, no hardware needed):
    python guest/launch-gate.py --krs http://127.0.0.1:8443 --mock \
        --enc-model mock/models/model.safetensors.enc \
        --model-out /tmp/model

Usage (real SEV-SNP VM):
    python guest/launch-gate.py --krs https://krs.example.com:8443 \
        --kernel /boot/vmlinuz --initrd /boot/initrd.img --gate /opt/gate \
        --enc-model /models/model.enc --model-out /run/model/model
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from guest import gate_client  # noqa: E402
from guest.decrypt_and_serve import decrypt_weights, serve_model  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]


def write_receipt(model_out: str, dec_info: dict, krs_info: dict,
                  path: str) -> str:
    """
    Execution receipt (optional extension of the proposal):

    SHA-256 over the inference config + decrypted weight digest, stored
    alongside the KRS verification result. The receipt hash can be fed
    as the REPORT_DATA nonce of a follow-up attestation, chaining
    execution evidence into the hardware-rooted trust chain.
    """
    receipt = {
        "model_sha256": dec_info["plaintext_sha256"],
        "model_bytes": dec_info["bytes"],
        "krs_measurement": krs_info.get("measurement"),
        "krs_tcb": krs_info.get("tcb"),
        "inference": {
            "engine": "vllm",
            "dtype": "float16",
            "device": "AMD Instinct (ROCm/HIP)",
        },
    }
    blob = json.dumps(receipt, sort_keys=True).encode()
    digest = hashlib.sha256(blob).hexdigest()
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(receipt, indent=2))
    return digest


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--krs", default="http://127.0.0.1:8443",
                    help="KRS base URL (use https:// in production)")
    ap.add_argument("--mode", choices=["auto", "real", "mock"], default="auto")
    ap.add_argument("--kernel", help="measured kernel image path")
    ap.add_argument("--initrd", help="measured initrd path")
    ap.add_argument("--gate", help="measured gate program path")
    ap.add_argument("--enc-model", default=None,
                    help="single encrypted weight file (SGW1)")
    ap.add_argument("--enc-dir", default=None,
                    help="encrypted model DIRECTORY (from "
                         "`encrypt-model.py encrypt-dir`, contains "
                         "*.enc + manifest.json)")
    ap.add_argument("--model-out", required=True,
                    help="output file (--enc-model) or directory (--enc-dir)")
    ap.add_argument("--receipt-file", default="/run/gate-receipt.json")
    ap.add_argument("--measurement", default="",
                    help="explicit measurement hex (mock mode convenience)")
    ap.add_argument("--tamper", choices=["measurement", "signature", "tcb",
                                         "report-data", "policy"],
                    help="simulate a tampered runtime (negative test)")
    ap.add_argument("--report-file", help="ingest a raw report fetched by "
                                          "snpguest instead of using ioctl")
    ap.add_argument("--certs-dir", default="/etc/sev/certs")
    ap.add_argument("--launch-vllm", action="store_true",
                    help="actually exec vLLM after a successful gate run")
    ap.add_argument("--port", type=int, default=8000)
    args = ap.parse_args(argv)
    if not args.enc_model and not args.enc_dir:
        ap.error("provide --enc-model <file> or --enc-dir <directory>")

    artifacts = {"kernel": args.kernel, "initrd": args.initrd,
                 "gate": args.gate}
    if args.mode == "mock" and not any(artifacts.values()):
        art_dir = REPO_ROOT / "mock" / "artifacts"
        artifacts = {k: str(art_dir / n) for k, n in
                     (("kernel", "vmlinuz-mock"), ("initrd", "initrd-mock"),
                      ("gate", "gate-mock"))}

    t0 = time.perf_counter()
    print("[gate] requesting challenge from KRS ...")
    try:
        model_key, info = gate_client.run_gate(
            args.krs, mode=args.mode, artifacts=artifacts,
            tamper=args.tamper, measurement_hex=args.measurement,
            report_file=args.report_file, certs_dir=args.certs_dir)
    except gate_client.GateError as e:
        print(f"[gate] ATTENTION: key release DENIED: {e}", file=sys.stderr)
        print("[gate] inference cannot start; weights remain encrypted.",
              file=sys.stderr)
        return 2
    gate_ms = (time.perf_counter() - t0) * 1000
    print(f"[gate] key released (gate round-trip {gate_ms:.0f} ms), "
          f"measurement={info['measurement'][:24]}...")

    print("[gate] decrypting weights ...")
    t1 = time.perf_counter()
    if args.enc_dir:
        from guest.weight_crypto import decrypt_dir, dir_digest, dir_total_bytes
        manifest = decrypt_dir(args.enc_dir, args.model_out, model_key)
        dec_info = {"plaintext_sha256": dir_digest(manifest),
                    "bytes": dir_total_bytes(manifest),
                    "files": len(manifest)}
        print(f"[gate] model dir decrypted: {len(manifest)} files, "
              f"{dec_info['bytes']} bytes, all sha256 verified")
    else:
        dec_info = decrypt_weights(args.enc_model, args.model_out, model_key)
    dec_ms = (time.perf_counter() - t1) * 1000
    print(f"[gate] decrypt took {dec_ms:.0f} ms "
          f"({dec_info['bytes'] / max(dec_ms, 1) * 1000 / 1e6:.2f} MB/s)")

    digest = write_receipt(args.model_out, dec_info, info, args.receipt_file)
    print(f"[gate] receipt written: {args.receipt_file} "
          f"(sha256={digest[:16]}..., echo as next nonce for evidence chaining)")

    if args.launch_vllm:
        serve_model(args.model_out, port=args.port)
    else:
        print("[gate] gate run complete; model ready for serving")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
