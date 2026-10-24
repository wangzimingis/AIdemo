#!/usr/bin/env python3
# scripts/encrypt-model.py
"""
Encrypt model weights with the model key (model-provider side tool).

Run this on the TRUSTED side (model provider), never inside the cloud.
The output *.enc file is safe to upload: AES-256-GCM, chunk-streamed,
per-file random salt, header bound into every chunk as AAD.

    # generate a demo key (do NOT commit real keys)
    python scripts/encrypt-model.py genkey --out .env.modelkey

    # encrypt a checkpoint / safetensors file
    python scripts/encrypt-model.py encrypt \
        --key-hex $(grep MODEL_KEY .env.modelkey | cut -d= -f2) \
        --in  model-00001-of-00002.safetensors \
        --out /models/model-00001-of-00002.safetensors.enc
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from guest.weight_crypto import (  # noqa: E402
    dir_digest, encrypt_dir, encrypt_file,
)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_gen = sub.add_parser("genkey", help="generate a random 32-byte key")
    p_gen.add_argument("--out", default=".env.modelkey")

    p_enc = sub.add_parser("encrypt", help="encrypt a weights file")
    p_enc.add_argument("--key-hex", required=True)
    p_enc.add_argument("--in", dest="in_path", required=True)
    p_enc.add_argument("--out", dest="out_path", required=True)
    p_enc.add_argument("--chunk-size", type=int,
                       default=4 * 1024 * 1024)

    p_dir = sub.add_parser("encrypt-dir",
                           help="encrypt an entire model directory "
                                "(produces <out>/<rel>.enc + manifest.json)")
    p_dir.add_argument("--key-hex", required=True)
    p_dir.add_argument("--in", dest="in_dir", required=True,
                       help="model checkpoint directory "
                            "(config.json, *.safetensors, tokenizer files, ...)")
    p_dir.add_argument("--out", dest="out_dir", required=True)

    args = ap.parse_args(argv)

    if args.cmd == "genkey":
        import os
        key = os.urandom(32).hex()
        Path(args.out).write_text(f"MODEL_KEY={key}\n")
        print(f"key written to {args.out} (do NOT commit; inject as env var)")
        return 0

    key = bytes.fromhex(args.key_hex.strip())

    if args.cmd == "encrypt-dir":
        manifest = encrypt_dir(args.in_dir, args.out_dir, key)
        total = sum(m["bytes"] for m in manifest.values())
        print(f"encrypted {len(manifest)} files ({total} bytes) "
              f"{args.in_dir} -> {args.out_dir}")
        print(json_info({"files": len(manifest), "bytes": total,
                         "digest": dir_digest(manifest)}))
        return 0

    info = encrypt_file(args.in_path, args.out_path, key, args.chunk_size)
    print(f"encrypted {args.in_path} -> {args.out_path}")
    print(json_info(info))
    return 0


def json_info(info: dict) -> str:
    import json
    return json.dumps(info, indent=2)


if __name__ == "__main__":
    raise SystemExit(main())
