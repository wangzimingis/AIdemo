# guest/weight_crypto.py
"""
Streaming AES-256-GCM encryption/decryption for model weight files.

Design goals:
- Never load a multi-GB safetensors file fully into RAM: weights are
  processed in fixed-size chunks (default 4 MiB), each authenticated with
  its own GCM tag.
- Format is self-describing so the decryptor in the confidential VM can
  stream straight to a plain file (or later: to memory / tmpfs).

File format ("SGW1")::

    offset  size  field
    0       4     magic  b"SGW1"
    4       1     version (=1)
    5       3     reserved
    8       4     chunk_size (u32 LE)
    12      8     salt (random per file)
    20      4     chunk_count (u32 LE)
    24      ...   chunks:
                  for i in range(chunk_count):
                      nonce = salt(8) || i.to_bytes(4, "big")
                      AESGCM(key).encrypt(nonce, chunk, aad=header(24B))
                      -> ciphertext || tag(16)

A decryption failure of ANY chunk (wrong key, bit-flip, truncation)
raises InvalidTag before the gate proceeds to vLLM startup.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"SGW1"
VERSION = 1
HEADER_SIZE = 24
DEFAULT_CHUNK_SIZE = 4 * 1024 * 1024
TAG_SIZE = 16


@dataclass
class Header:
    chunk_size: int
    salt: bytes
    chunk_count: int

    def pack(self) -> bytes:
        return (
            MAGIC
            + bytes([VERSION])
            + b"\x00" * 3
            + self.chunk_size.to_bytes(4, "little")
            + self.salt
            + self.chunk_count.to_bytes(4, "little")
        )

    @property
    def aad(self) -> bytes:
        # header bytes are bound into every chunk as AAD
        return self.pack()


def _nonce(salt: bytes, index: int) -> bytes:
    return salt + index.to_bytes(4, "big")


def encrypt_file(in_path: str, out_path: str, key: bytes,
                 chunk_size: int = DEFAULT_CHUNK_SIZE) -> dict:
    """Encrypt in_path -> out_path with AES-256-GCM (streaming)."""
    if len(key) != 32:
        raise ValueError("key must be 32 bytes (AES-256)")
    aes = AESGCM(key)
    total = os.path.getsize(in_path)
    chunk_count = (total + chunk_size - 1) // chunk_size
    if chunk_count == 0:  # empty file edge case
        chunk_count = 1
    header = Header(chunk_size, os.urandom(8), chunk_count)

    sha = hashlib.sha256()
    written = 0
    with open(in_path, "rb") as fin, open(out_path, "wb") as fout:
        fout.write(header.pack())
        for i in range(chunk_count):
            chunk = fin.read(chunk_size)
            if not chunk:
                break
            ct = aes.encrypt(_nonce(header.salt, i), chunk, header.aad)
            fout.write(ct)
            sha.update(chunk)
            written += 1
        if written != chunk_count:
            raise RuntimeError(
                f"file changed during encryption ({written}/{chunk_count})")
    return {"chunks": chunk_count, "chunk_size": chunk_size,
            "plaintext_sha256": sha.hexdigest(), "bytes": total}


def decrypt_file(in_path: str, out_path: str, key: bytes) -> dict:
    """Stream-decrypt an SGW1 file. Raises InvalidTag on any tampering."""
    with open(in_path, "rb") as fin:
        raw = fin.read(HEADER_SIZE)
        if raw[:4] != MAGIC:
            raise ValueError("not an SGW1 encrypted weight file")
        if raw[4] != VERSION:
            raise ValueError(f"unsupported version {raw[4]}")
        chunk_size = int.from_bytes(raw[8:12], "little")
        salt = raw[12:20]
        chunk_count = int.from_bytes(raw[20:24], "little")
        header = Header(chunk_size, salt, chunk_count)
        aes = AESGCM(key)
        sha = hashlib.sha256()
        out = 0
        with open(out_path, "wb") as fout:
            for i in range(chunk_count):
                blob = fin.read(chunk_size + TAG_SIZE)
                if len(blob) < TAG_SIZE:
                    raise InvalidTag()  # truncated file
                pt = aes.decrypt(_nonce(salt, i), blob, header.aad)
                fout.write(pt)
                sha.update(pt)
                out += len(pt)
    return {"chunks": chunk_count, "plaintext_sha256": sha.hexdigest(),
            "bytes": out}


def verify_file(in_path: str, expected_sha256: str, key: bytes) -> bool:
    """Decrypt to /dev/null-equivalent and compare plaintext hash."""
    import tempfile, os
    tmp = tempfile.mktemp(suffix=".dec")
    try:
        info = decrypt_file(in_path, tmp, key)
        return info["plaintext_sha256"] == expected_sha256
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


# ---------------------------------------------------------------------------
# directory mode: real model checkpoints are multi-file directories
# ---------------------------------------------------------------------------

def encrypt_dir(in_dir: str, out_dir: str, key: bytes,
                chunk_size: int = DEFAULT_CHUNK_SIZE) -> dict:
    """
    Encrypt every file of a model directory, preserving structure:
    <out_dir>/<relpath>.enc for each file, plus a manifest.json at the
    root recording {relpath: {bytes, plaintext sha256}} so the gate can
    verify every decrypted file after release.

    NOTE (demo boundary): filenames and the manifest are not secret —
    they are metadata; only file CONTENTS are confidentiality-protected.
    """
    src, dst = Path(in_dir), Path(out_dir)
    if not src.is_dir():
        raise ValueError(f"not a directory: {in_dir}")
    manifest = {}
    for p in sorted(src.rglob("*")):
        if not p.is_file():
            continue
        rel = p.relative_to(src).as_posix()
        enc_out = dst / (rel + ".enc")
        enc_out.parent.mkdir(parents=True, exist_ok=True)
        info = encrypt_file(str(p), str(enc_out), key, chunk_size)
        manifest[rel] = {"bytes": info["bytes"],
                         "sha256": info["plaintext_sha256"]}
    (dst / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True))
    return manifest


def decrypt_dir(in_dir: str, out_dir: str, key: bytes,
                verify: bool = True) -> dict:
    """
    Stream-decrypt an encrypted model directory (encrypt_dir's inverse).
    Every file is checked against the manifest sha256; any mismatch or
    InvalidTag aborts the gate before inference.
    """
    src, dst = Path(in_dir), Path(out_dir)
    manifest = json.loads((src / "manifest.json").read_text())
    for rel, meta in manifest.items():
        enc = src / (rel + ".enc")
        outp = dst / rel
        outp.parent.mkdir(parents=True, exist_ok=True)
        info = decrypt_file(str(enc), str(outp), key)
        if verify and info["plaintext_sha256"] != meta["sha256"]:
            raise RuntimeError(f"post-decrypt hash mismatch: {rel}")
    return manifest


def dir_digest(manifest: dict) -> str:
    """Aggregate digest of a whole decrypted model dir (for the receipt)."""
    blob = json.dumps(manifest, sort_keys=True).encode()
    return hashlib.sha256(blob).hexdigest()


def dir_total_bytes(manifest: dict) -> int:
    return sum(m["bytes"] for m in manifest.values())
