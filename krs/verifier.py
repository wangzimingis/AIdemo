# krs/verifier.py
"""
Self-implemented SEV-SNP attestation report verifier.

No closed-source or vendor SDK is used: every step below is written
against the public AMD SEV-SNP Firmware ABIs Specification so the whole
chain can be audited line by line.

Verification pipeline (verify_attestation):
  1. structural checks on the raw 0x1000-byte report (version, algo)
  2. certificate chain validation:  ARK (self-signed)
                                    ASK (signed by ARK)
                                    VCEK (signed by ASK)
  3. VCEK signature check over report[0x00:0x2A0]  (ECDSA-P384/SHA-384)
  4. freshness: REPORT_DATA == the nonce issued by the KRS challenge
  5. measurement comparison against the registered baseline
  6. anti-rollback: component-wise CURRENT_TCB >= baseline TCB
  7. guest policy sanity (ABI major, SNP enabled)

Known demo limitations (documented in docs/threat-model.md):
  - AMD-specific X.509 product extensions on VCEK (e.g. which chip SKU
    the key belongs to) are not validated; production code should check
    the amd-sk extension and match it to an allowlist.
"""

from __future__ import annotations

import base64
import sys
from dataclasses import dataclass, field as dc_field
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils
from cryptography.x509.oid import NameOID

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common.snp_layout import (  # noqa: E402
    CURRENT_TCB_OFF, CURRENT_TCB_SZ, FAMILY_ID_OFF, FAMILY_ID_SZ,
    HOST_DATA_OFF, HOST_DATA_SZ, ID_KEY_DIGEST_OFF, ID_KEY_DIGEST_SZ,
    IMAGE_ID_OFF, IMAGE_ID_SZ, MEASUREMENT_OFF, MEASUREMENT_SZ,
    POLICY_OFF, POLICY_SZ, REPORT_DATA_OFF, REPORT_DATA_SZ,
    REPORT_ID_OFF, REPORT_ID_SZ, REPORT_SIZE, REPORT_VERSION,
    RESERVED_2_OFF, RESERVED_2_SZ, RESERVED_3_OFF, RESERVED_3_SZ,
    SIGNATURE_ALGO_OFF, SIGNATURE_ALGO_SZ, SIGNATURE_OFF, SIGNED_SIZE,
    SIGNATURE_SIZE, GUEST_SVN_OFF, GUEST_SVN_SZ, VMPL_OFF, VMPL_SZ,
    AUTHOR_KEY_DIGEST_OFF, AUTHOR_KEY_DIGEST_SZ, REPORT_ID_MA_OFF,
    REPORT_ID_MA_SZ, PLATFORM_INFO_OFF, PLATFORM_INFO_SZ,
    SIG_ALGO_ECDSA_P384,
    parse_tcb, policy_abi_major, tcb_not_older_than,
)


class VerificationError(Exception):
    """Raised when any step of the verification pipeline fails."""


@dataclass
class SnpReport:
    raw: bytes
    version: int = 0
    guest_svn: int = 0
    policy: int = 0
    family_id: bytes = b""
    image_id: bytes = b""
    vmpl: int = 0
    signature_algo: int = 0
    tcb: dict = dc_field(default_factory=dict)
    platform_info: int = 0
    report_id: bytes = b""
    report_id_ma: bytes = b""
    measurement: bytes = b""
    host_data: bytes = b""
    id_key_digest: bytes = b""
    author_key_digest: bytes = b""
    report_data: bytes = b""
    signature_r: bytes = b""
    signature_s: bytes = b""


def parse_report(raw: bytes) -> SnpReport:
    if len(raw) != REPORT_SIZE:
        raise VerificationError(
            f"bad report size: {len(raw)} bytes (expected {REPORT_SIZE})")

    r = SnpReport(raw=raw)
    r.version = int.from_bytes(raw[0:4], "little")
    if r.version != REPORT_VERSION:
        raise VerificationError(f"unsupported report version {r.version}")
    r.guest_svn = int.from_bytes(raw[GUEST_SVN_OFF:GUEST_SVN_OFF + GUEST_SVN_SZ], "little")
    r.policy = int.from_bytes(raw[POLICY_OFF:POLICY_OFF + POLICY_SZ], "little")
    r.family_id = raw[FAMILY_ID_OFF:FAMILY_ID_OFF + FAMILY_ID_SZ]
    r.image_id = raw[IMAGE_ID_OFF:IMAGE_ID_OFF + IMAGE_ID_SZ]
    r.vmpl = int.from_bytes(raw[VMPL_OFF:VMPL_OFF + VMPL_SZ], "little")
    r.signature_algo = int.from_bytes(
        raw[SIGNATURE_ALGO_OFF:SIGNATURE_ALGO_OFF + SIGNATURE_ALGO_SZ], "little")
    if r.signature_algo != SIG_ALGO_ECDSA_P384:
        raise VerificationError(
            f"unsupported signature algo 0x{r.signature_algo:x} "
            "(only ECDSA-P384/SHA-384 is defined by the spec)")
    r.tcb = parse_tcb(raw[CURRENT_TCB_OFF:CURRENT_TCB_OFF + CURRENT_TCB_SZ])
    r.platform_info = int.from_bytes(
        raw[PLATFORM_INFO_OFF:PLATFORM_INFO_OFF + PLATFORM_INFO_SZ], "little")
    r.report_id = raw[REPORT_ID_OFF:REPORT_ID_OFF + REPORT_ID_SZ]
    r.report_id_ma = raw[REPORT_ID_MA_OFF:REPORT_ID_MA_OFF + REPORT_ID_MA_SZ]
    r.measurement = raw[MEASUREMENT_OFF:MEASUREMENT_OFF + MEASUREMENT_SZ]
    r.host_data = raw[HOST_DATA_OFF:HOST_DATA_OFF + HOST_DATA_SZ]
    r.id_key_digest = raw[ID_KEY_DIGEST_OFF:ID_KEY_DIGEST_OFF + ID_KEY_DIGEST_SZ]
    r.author_key_digest = raw[AUTHOR_KEY_DIGEST_OFF:AUTHOR_KEY_DIGEST_OFF + AUTHOR_KEY_DIGEST_SZ]
    r.report_data = raw[REPORT_DATA_OFF:REPORT_DATA_OFF + REPORT_DATA_SZ]
    r.signature_r = raw[SIGNATURE_OFF:SIGNATURE_OFF + 72]
    r.signature_s = raw[SIGNATURE_OFF + 72:SIGNATURE_OFF + 144]
    return r


# --------------------------------------------------------------------------
# Certificate chain: VCEK -> ASK -> ARK
# --------------------------------------------------------------------------

def _verify_signed_by(child: x509.Certificate, parent: x509.Certificate,
                      what: str) -> None:
    """Verify that `child`'s inner signature was produced by `parent`."""
    pub = parent.public_key()
    if not isinstance(pub, ec.EllipticCurvePublicKey):
        raise VerificationError(f"{what}: parent key is not ECDSA")
    try:
        pub.verify(
            child.signature,
            child.tbs_certificate_bytes,
            ec.ECDSA(child.signature_hash_algorithm),
        )
    except Exception as e:
        raise VerificationError(f"{what}: signature invalid ({e})")


def verify_cert_chain(ark_pem: str, ask_pem: str, vcek_pem: str) -> x509.Certificate:
    """
    Validate ARK -> ASK -> VCEK.

    Returns the parsed VCEK certificate (public key used for the report
    signature). For real AMD hardware the ARK/ASK come from AMD's published
    certificate bundles (Milan/Genoa); in mock mode they are generated by
    mock/mock-attest.py with the same structure.
    """
    ark = x509.load_pem_x509_certificate(ark_pem.encode())
    ask = x509.load_pem_x509_certificate(ask_pem.encode())
    vcek = x509.load_pem_x509_certificate(vcek_pem.encode())

    # ARK must be self-signed
    _verify_signed_by(ark, ark, "ARK self-signature")
    # ASK must be signed by ARK
    _verify_signed_by(ask, ark, "ASK signed by ARK")
    # VCEK must be signed by ASK
    _verify_signed_by(vcek, ask, "VCEK signed by ASK")

    for cert, what in ((ark, "ARK"), (ask, "ASK"), (vcek, "VCEK")):
        if isinstance(cert.public_key().curve, ec.SECP384R1) is False:
            raise VerificationError(f"{what}: key is not on P-384")
    return vcek


def verify_report_signature(report: SnpReport,
                            vcek: x509.Certificate) -> None:
    """Verify the VCEK ECDSA-P384/SHA-384 signature over report[0:0x2A0]."""
    signed_blob = report.raw[:SIGNED_SIZE]
    r = int.from_bytes(report.signature_r, "big")   # 72B BE, zero-padded
    s = int.from_bytes(report.signature_s, "big")
    if r == 0 or s == 0:
        raise VerificationError("signature integers are zero")
    der = asym_utils.encode_dss_signature(r, s)
    pub = vcek.public_key()
    try:
        pub.verify(der, signed_blob, ec.ECDSA(hashes.SHA384()))
    except Exception as e:
        raise VerificationError(f"VCEK report signature invalid ({e})")


# --------------------------------------------------------------------------
# Baseline + policy checks
# --------------------------------------------------------------------------

def check_freshness(report: SnpReport, expected_report_data: bytes) -> None:
    """The KRS-issued nonce must be echoed back in REPORT_DATA."""
    if len(expected_report_data) > 64:
        raise VerificationError("nonce longer than REPORT_DATA field")
    expected = expected_report_data.ljust(64, b"\x00")
    if report.report_data != expected:
        raise VerificationError("REPORT_DATA does not match the challenge nonce")


def check_measurement(report: SnpReport, baseline_measurement_hex: str) -> None:
    got = report.measurement.hex()
    if got != baseline_measurement_hex.lower().strip():
        raise VerificationError(
            f"measurement mismatch: got {got[:24]}... "
            f"expected {baseline_measurement_hex[:24]}...")


def check_tcb(report: SnpReport, baseline_tcb: dict) -> None:
    if not tcb_not_older_than(report.tcb, baseline_tcb):
        raise VerificationError(
            f"TCB rollback detected: report {report.tcb} < baseline {baseline_tcb}")


def check_policy(report: SnpReport, min_abi_major: int = 1,
                 require_vmpl: Optional[int] = None) -> None:
    # SNP bit is implied: a report can only exist for an SNP guest.
    if policy_abi_major(report.policy) < min_abi_major:
        raise VerificationError(
            f"guest policy ABI major {policy_abi_major(report.policy)} "
            f"< required {min_abi_major}")
    if require_vmpl is not None and report.vmpl != require_vmpl:
        raise VerificationError(
            f"report requested at VMPL {report.vmpl}, expected {require_vmpl}")


# --------------------------------------------------------------------------
# Top-level entry used by the KRS server
# --------------------------------------------------------------------------

@dataclass
class VerifyResult:
    ok: bool
    measurement: str
    tcb: dict
    policy: int
    vmpl: int
    report_id: str
    reason: Optional[str] = None


def verify_attestation(
    *,
    report_b64: str,
    vcek_pem: str,
    ark_pem: str,
    ask_pem: str,
    expected_report_data: bytes,
    baseline_measurement_hex: str,
    baseline_tcb: dict,
    min_abi_major: int = 1,
    require_vmpl: Optional[int] = None,
) -> VerifyResult:
    """Run the full pipeline. Raises VerificationError on any failure."""
    try:
        raw = base64.b64decode(report_b64, validate=True)
    except Exception as e:
        raise VerificationError(f"report is not valid base64: {e}")

    report = parse_report(raw)
    vcek = verify_cert_chain(ark_pem, ask_pem, vcek_pem)
    verify_report_signature(report, vcek)
    check_freshness(report, expected_report_data)
    check_measurement(report, baseline_measurement_hex)
    check_tcb(report, baseline_tcb)
    check_policy(report, min_abi_major, require_vmpl)

    return VerifyResult(
        ok=True,
        measurement=report.measurement.hex(),
        tcb=report.tcb,
        policy=report.policy,
        vmpl=report.vmpl,
        report_id=report.report_id.hex(),
    )


# --------------------------------------------------------------------------
# Optional: fetch a real VCEK from the AMD Key Distribution Service
# --------------------------------------------------------------------------

def fetch_vcek_from_kds(chip_id_hex: str, product: str = "milan",
                        hwid_params: Optional[dict] = None,
                        cache_dir: Optional[str] = None,
                        timeout: float = 10.0) -> bytes:
    """
    Fetch the VCEK certificate for a chip from AMD KDS and cache it.

    KDS endpoint (SNP spec 4.1):
      GET https://kdsintf.amd.com/vcek/v1/{milan|genoa}/{chip_id}?specver=2
    hwid_params carry the extra TCB values (ucode, snp, tee, boot_loader,
    ...) that KDS uses to select the TCB-specific VCEK.
    """
    import urllib.request

    params = dict(hwid_params or {})
    params.setdefault("specver", "2")
    qs = "&".join(f"{k}={v}" for k, v in params.items())
    url = (f"https://kdsintf.amd.com/vcek/v1/{product}/"
           f"{chip_id_hex}?{qs}")
    cache = None
    if cache_dir:
        Path(cache_dir).mkdir(parents=True, exist_ok=True)
        cache = Path(cache_dir) / f"vcek-{product}-{chip_id_hex}.der"
        if cache.exists():
            return cache.read_bytes()
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        der = resp.read()
    if cache:
        cache.write_bytes(der)
    return der
