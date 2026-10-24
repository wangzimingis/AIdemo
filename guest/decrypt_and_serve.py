# guest/decrypt_and_serve.py
"""
Decrypt gated model weights (streaming AES-256-GCM) and hand off to
vLLM on ROCm. Imported by guest/launch-gate.py; the module name keeps
the original demo layout.

The plaintext weights only ever exist inside the SEV-SNP protected
memory of the VM (write to tmpfs to avoid a plaintext copy on the
encrypted disk image):
    mount -t tmpfs -o size=16G tmpfs /run/model
    --model-out /run/model/qwen2.5-1.5b
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from guest.weight_crypto import decrypt_file  # noqa: E402


def decrypt_weights(enc_path: str, out_path: str, key: bytes) -> dict:
    """
    Stream-decrypt an SGW1 weight file. Raises cryptography InvalidTag if
    the key is wrong or the ciphertext was tampered with.
    """
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    info = decrypt_file(enc_path, str(out), key)
    print(f"[gate] weights decrypted: {enc_path} -> {out} "
          f"({info['bytes']} bytes, sha256={info['plaintext_sha256'][:16]}...)")
    return info


def serve_model(model_dir: str, port: int = 8000,
                dtype: str = "float16") -> None:
    """
    Start vLLM (ROCm build) on the decrypted model directory.

    NOTE (from the 4-week experiment plan): on MI300X prefer FP16 or
    FP8-dynamic; vLLM-on-ROCm AWQ support is incomplete for many
    community checkpoints.
    """
    cmd = [
        "vllm", "serve", model_dir,
        "--port", str(port),
        "--dtype", dtype,
    ]
    print(f"[gate] launching inference server: {' '.join(cmd)}")
    os.execvp(cmd[0], cmd)


if __name__ == "__main__":
    # standalone usage (key must already be available in the VM):
    #   MODEL_KEY_HEX=<hex> MODEL_ENC=/models/model.enc python decrypt_and_serve.py
    key = bytes.fromhex(os.environ["MODEL_KEY_HEX"].strip())
    decrypt_weights(os.environ.get("MODEL_ENC", "/models/model.enc"),
                    os.environ.get("MODEL_OUT", "/run/model/model"), key)
    serve_model(os.environ.get("MODEL_OUT", "/run/model/model"),
                int(os.environ.get("PORT", "8000")),
                os.environ.get("DTYPE", "float16"))
