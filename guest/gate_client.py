# guest/gate_client.py
"""
HTTP client driving the KRS gate protocol:

    1. POST /challenge      -> one-shot nonce
    2. obtain attestation report binding the nonce (real SNP or mock)
    3. POST /release-key    -> model key, or 403 with the rejection reason

Only the Python standard library is used so the confidential VM image
stays minimal (cryptography is required only for weight decryption).
"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from guest.get_report import get_attestation_bundle  # noqa: E402


class GateError(RuntimeError):
    pass


def _post(url: str, payload: Optional[dict] = None) -> dict:
    data = json.dumps(payload or {}).encode()
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"},
        method="POST")
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode())


def request_challenge(krs_url: str) -> str:
    out = _post(f"{krs_url.rstrip('/')}/challenge")
    return out["nonce"]


def request_key(krs_url: str, bundle: dict, nonce: str) -> dict:
    """POST /release-key. Raises GateError with the KRS rejection reason."""
    payload = {
        "nonce": nonce,
        "report_b64": bundle["report_b64"],
        "vcek_pem": bundle["vcek_pem"],
        "ask_pem": bundle["ask_pem"],
        "ark_pem": bundle["ark_pem"],
    }
    try:
        return _post(f"{krs_url.rstrip('/')}/release-key", payload)
    except urllib.error.HTTPError as e:
        try:
            detail = json.loads(e.read().decode()).get("detail", "")
        except Exception:
            detail = ""
        raise GateError(f"KRS rejected the attestation "
                        f"(HTTP {e.code}): {detail}") from None


def run_gate(krs_url: str,
             mode: str = "auto",
             artifacts: Optional[dict] = None,
             tamper: Optional[str] = None,
             measurement_hex: str = "",
             report_file: Optional[str] = None,
             certs_dir: str = "/etc/sev/certs") -> tuple[bytes, dict]:
    """
    Full challenge -> report -> release round trip.

    Returns (model_key: bytes, verification_info: dict).
    Raises GateError if the KRS refuses to release the key.
    """
    nonce = request_challenge(krs_url)
    bundle = get_attestation_bundle(
        bytes.fromhex(nonce), mode=mode,
        repo_root=Path(__file__).resolve().parents[1],
        artifacts=artifacts, tamper=tamper,
        measurement_hex=measurement_hex,
        report_file=report_file, certs_dir=certs_dir)
    info = request_key(krs_url, bundle, nonce)
    model_key = bytes.fromhex(info["model_key"])
    return model_key, info
