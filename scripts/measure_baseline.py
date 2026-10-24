#!/usr/bin/env python3
# scripts/measure_baseline.py
"""
Produce / refresh the KRS baseline file from measured runtime artifacts.

Same measurement composition as guest/measure-runtime.sh and
mock/mock-attest.py:

    measurement = SHA-384( SHA-384(kernel) || SHA-384(initrd) || SHA-384(gate) )

Usage (real hardware image build):
    python scripts/measure_baseline.py \
        --kernel /boot/vmlinuz --initrd /boot/initrd.img \
        --gate /opt/gate --name "mi300x-baseline-v1" \
        --out krs/baselines/baseline.json

Usage (mock artifacts, for the local demo):
    python mock/mock-attest.py make-artifacts
    python scripts/measure_baseline.py --mock-artifacts \
        --out krs/baselines/baseline.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from mock.mock_attest_helpers import compose_measurement  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--kernel"); ap.add_argument("--initrd")
    ap.add_argument("--gate")
    ap.add_argument("--mock-artifacts", action="store_true",
                    help="measure mock/mock-artifacts/vmlinuz-mock etc.")
    ap.add_argument("--name", default="runtime-baseline")
    ap.add_argument("--tcb", default="10.26.1", help="build.minor.major")
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)

    if args.mock_artifacts:
        art = REPO_ROOT / "mock" / "artifacts"
        kernel, initrd, gate = (str(art / "vmlinuz-mock"),
                                str(art / "initrd-mock"),
                                str(art / "gate-mock"))
    else:
        kernel, initrd, gate = args.kernel, args.initrd, args.gate
        for p in (kernel, initrd, gate):
            if not p or not Path(p).exists():
                ap.error(f"artifact not found: {p}")

    measurement = compose_measurement(kernel, initrd, gate)
    build, minor, major = (int(x) for x in args.tcb.split("."))
    baseline = {
        "name": args.name,
        "description": ("Registered runtime baseline. measurement = "
                        "SHA-384(kernel || initrd || gate digests); "
                        "see docs/sev-snp-primer.md for the boundary: "
                        "userspace ROCm libraries are NOT covered "
                        "(needs IMA/dm-verity as future work)."),
        "measurement": measurement,
        "tcb": {"build": build, "minor": minor, "major": major},
        "min_abi_major": 1,
        "vmpl": None,
    }
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(baseline, indent=2) + "\n")
    print(f"baseline written: {args.out}")
    print(f"  measurement = {measurement}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
