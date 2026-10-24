# krs/server.py
"""
Key Release Server (KRS) — attestation-gated model key release.

The KRS holds the model encryption key and the registered runtime
baselines. It releases the key only to a SEV-SNP confidential VM whose
attestation report (a) carries a valid VCEK/ASK/ARK signature chain,
(b) echoes a fresh KRS-issued nonce and (c) matches the registered
launch measurement with a non-rollback TCB.

Run (development):
    MODEL_KEY=<64 hex> KRS_BASELINE=krs/baselines/baseline.json \
        uvicorn krs.server:app --port 8443 --reload

Configuration (environment variables, see .env.example):
    MODEL_KEY            32-byte AES-256 key, hex-encoded (64 chars)
    KRS_BASELINE        path to the registered baseline JSON (default:
                         krs/baselines/baseline.json)
    ALLOWED_MEASUREMENT  optional measurement hex override (quick tests)
    ALLOWED_TCB          optional TCB override, "build.minor.major"
    NONCE_TTL_SECONDS    challenge nonce lifetime (default 60)

SECURITY NOTE (demo grade):
  - the key travels over the network; use TLS (reverse proxy or
    uvicorn --ssl-keyfile/--ssl-certfile) for anything beyond localhost.
  - the nonces live in process memory (single worker only). Production
    would use a shared store with atomic consume semantics.
  - see docs/threat-model.md for the full boundary of this demo.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, field_validator

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common.snp_layout import parse_tcb, tcb_bytes  # noqa: E402
from krs.verifier import (  # noqa: E402
    VerificationError, verify_attestation,
)

log = logging.getLogger("krs")
logging.basicConfig(
    level=os.environ.get("KRS_LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s %(message)s")

app = FastAPI(title="SEV-SNP Key Release Server", version="0.1.0")

REPO_ROOT = Path(__file__).resolve().parents[1]

# ---------------------------------------------------------------------------
# configuration
# ---------------------------------------------------------------------------

MODEL_KEY = bytes.fromhex(os.environ.get("MODEL_KEY", "").strip())
if len(MODEL_KEY) != 32:
    raise RuntimeError(
        "MODEL_KEY env must be 32 bytes hex (64 chars). "
        "Demo keygen: python -c \"import os;print(os.urandom(32).hex())\"")

NONCE_TTL = int(os.environ.get("NONCE_TTL_SECONDS", "60"))


def _load_baseline() -> dict:
    path = Path(os.environ.get("KRS_BASELINE",
                               REPO_ROOT / "krs" / "baselines" / "baseline.json"))
    with open(path, encoding="utf-8") as f:
        baseline = json.load(f)
    # env overrides for quick experiments
    if os.environ.get("ALLOWED_MEASUREMENT"):
        baseline["measurement"] = os.environ["ALLOWED_MEASUREMENT"]
    if os.environ.get("ALLOWED_TCB"):
        build, minor, major = os.environ["ALLOWED_TCB"].split(".")
        baseline["tcb"] = {"build": int(build), "minor": int(minor),
                           "major": int(major)}
    if "measurement" not in baseline or "tcb" not in baseline:
        raise RuntimeError(f"baseline file {path} must contain "
                           "'measurement' (hex) and 'tcb' (build/minor/major)")
    log.info("KRS baseline loaded from %s (name=%s, measurement=%s...)",
             path, baseline.get("name", "?"), baseline["measurement"][:24])
    return baseline


BASELINE = _load_baseline()


# ---------------------------------------------------------------------------
# challenge nonces (in-memory, one-shot)
# ---------------------------------------------------------------------------

@dataclass
class _Nonce:
    issued_at: float
    consumed: bool = False


_nonces: dict[str, _Nonce] = {}


def _prune_nonces() -> None:
    now = time.time()
    for k in [k for k, v in _nonces.items()
              if now - v.issued_at > 10 * NONCE_TTL]:
        _nonces.pop(k, None)


# ---------------------------------------------------------------------------
# API models
# ---------------------------------------------------------------------------

class ChallengeResponse(BaseModel):
    nonce: str            # 32 bytes hex -> goes into REPORT_DATA
    expires_in: int


class AttestRequest(BaseModel):
    nonce: str
    report_b64: str       # raw 0x1000-byte attestation report, base64
    vcek_pem: str
    ask_pem: str
    ark_pem: str

    @field_validator("nonce")
    @classmethod
    def _nonce_hex(cls, v: str) -> str:
        bytes.fromhex(v)
        return v


class KeyResponse(BaseModel):
    model_key: str        # 32 bytes hex (demo: protect with TLS)
    measurement: str
    tcb: dict
    receipt_hint: str


# ---------------------------------------------------------------------------
# endpoints
# ---------------------------------------------------------------------------

@app.get("/healthz")
def healthz() -> dict:
    return {
        "status": "ok",
        "baseline": BASELINE.get("name", "?"),
        "nonce_ttl": NONCE_TTL,
        "pending_challenges": len(_nonces),
    }


@app.post("/challenge")
def issue_challenge() -> ChallengeResponse:
    _prune_nonces()
    nonce = os.urandom(32).hex()
    _nonces[nonce] = _Nonce(issued_at=time.time())
    log.info("challenge issued nonce=%s...", nonce[:16])
    return ChallengeResponse(nonce=nonce, expires_in=NONCE_TTL)


@app.post("/release-key")
def release_key(req: AttestRequest) -> KeyResponse:
    # 1. nonce must exist, be unexpired and unused (one-shot)
    entry = _nonces.get(req.nonce)
    if entry is None:
        raise HTTPException(403, "unknown nonce: request /challenge first")
    if entry.consumed:
        raise HTTPException(403, "nonce already used (replay)")
    if time.time() - entry.issued_at > NONCE_TTL:
        raise HTTPException(403, "nonce expired")
    entry.consumed = True

    # 2..7. full verification pipeline in krs/verifier.py
    try:
        result = verify_attestation(
            report_b64=req.report_b64,
            vcek_pem=req.vcek_pem,
            ask_pem=req.ask_pem,
            ark_pem=req.ark_pem,
            expected_report_data=bytes.fromhex(req.nonce),
            baseline_measurement_hex=BASELINE["measurement"],
            baseline_tcb=BASELINE["tcb"],
            min_abi_major=int(BASELINE.get("min_abi_major", 1)),
            require_vmpl=BASELINE.get("vmpl"),
        )
    except VerificationError as e:
        log.warning("KEY RELEASE DENIED nonce=%s... reason=%s",
                    req.nonce[:16], e)
        raise HTTPException(403, f"attestation failed: {e}")

    # all checks passed -> release the model key
    log.info("KEY RELEASED nonce=%s... measurement=%s... tcb=%s",
             req.nonce[:16], result.measurement[:16],
             f"{result.tcb['major']}.{result.tcb['minor']}.{result.tcb['build']}")
    return KeyResponse(
        model_key=MODEL_KEY.hex(),
        measurement=result.measurement,
        tcb=result.tcb,
        receipt_hint=(
            "after inference, write SHA-256(inference config + weight "
            "digest) into a receipt file and echo it as the nonce of the "
            "next attestation to build a traceable evidence chain"),
    )
