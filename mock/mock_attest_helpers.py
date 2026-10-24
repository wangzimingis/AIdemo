# mock/mock_attest_helpers.py
"""
Importable helper for mock/mock-attest.py (the dash in the script name
prevents direct import) and scripts/measure_baseline.py.

Keeps the measurement composition in ONE place so the mock generator,
the baseline tool and guest/measure-runtime.sh can never drift apart.
"""

from __future__ import annotations

import hashlib
from pathlib import Path


def sha384_file(path: str) -> bytes:
    sha = hashlib.sha384()
    with open(path, "rb") as f:
        for blk in iter(lambda: f.read(1024 * 1024), b""):
            sha.update(blk)
    return sha.digest()


def compose_measurement(kernel: str | None, initrd: str | None,
                        gate: str | None) -> str:
    """
    measurement = SHA-384( SHA-384(kernel) || SHA-384(initrd) || SHA-384(gate) )

    Hash chain over the launch components, 48 bytes like the real SNP
    launch measurement. Mirrors (simplified) the firmware measurement
    chain documented in docs/sev-snp-primer.md.
    """
    sha = hashlib.sha384()
    for path in (kernel, initrd, gate):
        if not path or not Path(path).exists():
            sha.update(b"\x00" * 48)
        else:
            sha.update(sha384_file(path))
    return sha.hexdigest()
