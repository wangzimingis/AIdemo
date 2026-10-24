# mock/mock-attest.py
"""
Mock SEV-SNP attestation environment.

Generates, WITHOUT any real hardware, the exact artifact set that a
confidential VM would produce on an SEV-SNP host:

  1. a simulated AMD certificate chain:  ARK (self-signed)
                                         ASK (signed by ARK)
                                         VCEK (signed by ASK)
     - same P-384 / SHA-384 structure as AMD's published certificates,
       but keys generated locally (clearly marked CN="... Mock ...").

  2. a byte-layout-accurate 0x1000 attestation report, ECDSA-P384/SHA-384
     signed by the mock VCEK over report[0x00:0x2A0], exactly like the
     PSP firmware does on real silicon.

This lets the whole KRS verification pipeline (krs/verifier.py) be
exercised end-to-end on a laptop, and lets the demo produce the
"baseline match -> key released" and "tampered -> rejected" evidence.

Usage:
  # one-time: create the mock AMD hierarchy under mock/keys/
  python mock/mock-attest.py init

  # build a report for the measured runtime artifacts
  python mock/mock-attest.py report \
      --report-data <nonce-hex> \
      --kernel mock/artifacts/vmlinuz-mock \
      --initrd mock/artifacts/initrd-mock \
      --gate mock/artifacts/gate-mock \
      --out mock/reports/report.json

  # negative tests: flip exactly one thing the KRS should catch
  ... --tamper measurement|signature|tcb|report-data|policy

The JSON bundle written by `report` is directly POSTable to the KRS
/guest/gate_client.py flow.

MEASUREMENT MODEL (simplified but faithful in spirit):
  measurement = SHA-384( SHA-384(kernel) || SHA-384(initrd) || SHA-384(gate) )
On real hardware the launch measurement is computed by the PSP firmware
as a hash chain over the launched components (see docs/sev-snp-primer.md).
Our guest/measure-runtime.sh uses the same composition for baselines, so
mock and real flows share one baseline format.
"""

from __future__ import annotations

import argparse
import base64
import datetime
import hashlib
import json
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common.snp_layout import (  # noqa: E402
    AUTHOR_KEY_DIGEST_OFF, CURRENT_TCB_OFF, FAMILY_ID_OFF, GUEST_SVN_OFF,
    HOST_DATA_OFF, ID_KEY_DIGEST_OFF, IMAGE_ID_OFF, MEASUREMENT_OFF,
    PLATFORM_INFO_OFF, POLICY_OFF, REPORT_DATA_OFF, REPORT_ID_MA_OFF,
    REPORT_ID_OFF, REPORT_SIZE, REPORT_VERSION, SIGNATURE_ALGO_OFF,
    SIGNATURE_OFF, SIGNATURE_SIZE, SIGNED_SIZE, VMPL_OFF,
    SIG_ALGO_ECDSA_P384, tcb_bytes,
)
from mock.mock_attest_helpers import compose_measurement  # noqa: E402

MOCK_DIR = Path(__file__).resolve().parent
KEYS_DIR = MOCK_DIR / "keys"
ARTIFACTS_DIR = MOCK_DIR / "artifacts"
REPORTS_DIR = MOCK_DIR / "reports"


# ---------------------------------------------------------------------------
# mock AMD key hierarchy: ARK -> ASK -> VCEK
# ---------------------------------------------------------------------------

def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _make_cert(subject_cn: str, subject_key: ec.EllipticCurvePrivateKey,
               issuer_cert: x509.Certificate,
               issuer_key: ec.EllipticCurvePrivateKey,
               serial: int) -> x509.Certificate:
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(subject_cn))
        .issuer_name(issuer_cert.subject)
        .public_key(subject_key.public_key())
        .serial_number(serial)
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None),
                       critical=True)
    )
    return builder.sign(issuer_key, hashes.SHA384())


def init_hierarchy(force: bool = False) -> dict:
    """Create ARK/ASK/VCEK key pairs and certificates (idempotent)."""
    KEYS_DIR.mkdir(parents=True, exist_ok=True)

    def pem_path(name: str) -> Path:
        return KEYS_DIR / f"{name}.pem"

    ark_pem, ask_pem, vcek_pem = (pem_path("ark"), pem_path("ask"),
                                  pem_path("vcek"))
    ark_key_p, ask_key_p, vcek_key_p = (KEYS_DIR / "ark.key",
                                        KEYS_DIR / "ask.key",
                                        KEYS_DIR / "vcek.key")
    if all(p.exists() for p in (ark_pem, ask_pem, vcek_pem)) and not force:
        return {"ark": str(ark_pem), "ask": str(ask_pem),
                "vcek": str(vcek_pem)}

    ark_key = ec.generate_private_key(ec.SECP384R1())
    ask_key = ec.generate_private_key(ec.SECP384R1())
    vcek_key = ec.generate_private_key(ec.SECP384R1())

    ark_cert = (
        x509.CertificateBuilder()
        .subject_name(_name("AMD Root Key (Mock)"))
        .issuer_name(_name("AMD Root Key (Mock)"))
        .public_key(ark_key.public_key())
        .serial_number(0x101)
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc)
                          - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc)
                         + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None),
                       critical=True)
        .sign(ark_key, hashes.SHA384())
    )
    ask_cert = _make_cert("AMD SEV Signing Key (Mock)", ask_key,
                          ark_cert, ark_key, 0x102)
    vcek_cert = _make_cert("AMD SEV-SNP VCEK (Mock)", vcek_key,
                           ask_cert, ask_key, 0x103)

    def _write(path: Path, data: bytes) -> None:
        path.write_bytes(data)

    for cert, path in ((ark_cert, ark_pem), (ask_cert, ask_pem),
                       (vcek_cert, vcek_pem)):
        _write(path, cert.public_bytes(serialization.Encoding.PEM))
    for key, path in ((ark_key, ark_key_p), (ask_key, ask_key_p),
                      (vcek_key, vcek_key_p)):
        _write(path, key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
    print(f"[mock] certificate hierarchy written to {KEYS_DIR}")
    return {"ark": str(ark_pem), "ask": str(ask_pem), "vcek": str(vcek_pem)}


def _load_cert(path: str) -> x509.Certificate:
    return x509.load_pem_x509_certificate(Path(path).read_bytes())


def _load_key(path: str) -> ec.EllipticCurvePrivateKey:
    return serialization.load_pem_private_key(Path(path).read_bytes(),
                                              password=None)


# ---------------------------------------------------------------------------
# measurement composition lives in mock/mock_attest_helpers.py
# (shared with scripts/measure_baseline.py and guest/measure-runtime.sh)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# report construction + signing
# ---------------------------------------------------------------------------

def build_report(args: argparse.Namespace) -> dict:
    certs = init_hierarchy()
    vcek_key = _load_key(str(KEYS_DIR / "vcek.key"))

    # --- measurement -----------------------------------------------------
    if args.measurement:
        measurement = bytes.fromhex(args.measurement)
        if len(measurement) != 48:
            raise SystemExit("--measurement must be 48 bytes hex (96 chars)")
    else:
        measurement = bytes.fromhex(
            compose_measurement(args.kernel, args.initrd, args.gate))
    if args.tamper == "measurement":
        # simulate a tampered runtime: different launch measurement
        measurement = bytes(a ^ 0xFF for a in measurement)

    report_data = bytes.fromhex(args.report_data or "00" * 32).ljust(64, b"\x00")
    if args.tamper == "report-data":
        # simulate a nonce mismatch (replay of an old report)
        report_data = (b"\xde\xad\xbe\xef" + report_data[4:])

    build, minor, major = (int(x) for x in args.tcb.split("."))
    if args.tamper == "tcb":
        # simulate firmware rollback
        build, minor, major = max(build - 5, 0), max(minor - 10, 0), major

    policy = args.policy
    if args.tamper == "policy":
        policy &= ~(0xFF << 8)  # zero the ABI-major field

    # --- assemble the 0x1000 report --------------------------------------
    raw = bytearray(REPORT_SIZE)
    raw[0:4] = REPORT_VERSION.to_bytes(4, "little")
    raw[GUEST_SVN_OFF:GUEST_SVN_OFF + 4] = args.guest_svn.to_bytes(4, "little")
    raw[POLICY_OFF:POLICY_OFF + 8] = policy.to_bytes(8, "little")
    raw[FAMILY_ID_OFF:FAMILY_ID_OFF + 16] = bytes.fromhex(
        args.family_id.ljust(32, "0"))
    raw[IMAGE_ID_OFF:IMAGE_ID_OFF + 16] = bytes.fromhex(
        args.image_id.ljust(32, "0"))
    raw[VMPL_OFF:VMPL_OFF + 4] = args.vmpl.to_bytes(4, "little")
    raw[SIGNATURE_ALGO_OFF:SIGNATURE_ALGO_OFF + 4] = \
        SIG_ALGO_ECDSA_P384.to_bytes(4, "little")
    raw[CURRENT_TCB_OFF:CURRENT_TCB_OFF + 8] = tcb_bytes(build, minor, major)
    raw[PLATFORM_INFO_OFF:PLATFORM_INFO_OFF + 8] = (0).to_bytes(8, "little")
    raw[REPORT_ID_OFF:REPORT_ID_OFF + 32] = \
        hashlib.sha256(b"mock-guest-id").digest()
    raw[REPORT_ID_MA_OFF:REPORT_ID_MA_OFF + 16] = b"\x11" * 16
    raw[MEASUREMENT_OFF:MEASUREMENT_OFF + 48] = measurement
    raw[HOST_DATA_OFF:HOST_DATA_OFF + 32] = bytes.fromhex(
        args.host_data.ljust(64, "0"))
    raw[ID_KEY_DIGEST_OFF:ID_KEY_DIGEST_OFF + 48] = bytes.fromhex(
        args.id_key_digest.ljust(96, "0"))
    raw[AUTHOR_KEY_DIGEST_OFF:AUTHOR_KEY_DIGEST_OFF + 48] = b"\x00" * 48
    raw[REPORT_DATA_OFF:REPORT_DATA_OFF + 64] = report_data

    # --- sign report[0x00:0x2A0] with the mock VCEK ------------------------
    der = vcek_key.sign(bytes(raw[:SIGNED_SIZE]), ec.ECDSA(hashes.SHA384()))
    from cryptography.hazmat.primitives.asymmetric.utils import \
        decode_dss_signature
    r, s = decode_dss_signature(der)
    raw[SIGNATURE_OFF:SIGNATURE_OFF + 72] = r.to_bytes(72, "big")
    raw[SIGNATURE_OFF + 72:SIGNATURE_OFF + 144] = s.to_bytes(72, "big")

    if args.tamper == "signature":
        # flip one byte inside the signed area AFTER signing
        raw[MEASUREMENT_OFF + 47] ^= 0x01

    report_bin = bytes(raw)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    (out_path.parent / (out_path.stem + ".bin")).write_bytes(report_bin)
    bundle = {
        "report_b64": base64.b64encode(report_bin).decode(),
        "vcek_pem": Path(certs["vcek"]).read_text(),
        "ask_pem": Path(certs["ask"]).read_text(),
        "ark_pem": Path(certs["ark"]).read_text(),
        "measurement": measurement.hex(),
        "tcb": {"build": build, "minor": minor, "major": major},
        "policy": policy,
        "tamper": args.tamper or "none",
        "report_data_hex": report_data.hex(),
    }
    out_path.write_text(json.dumps(bundle, indent=2))
    print(f"[mock] report written: {out_path} "
          f"(measurement={measurement.hex()[:24]}..., tamper={args.tamper or 'none'})")
    return bundle


# ---------------------------------------------------------------------------
# convenience: create mock measured artifacts (fake kernel/initrd/gate)
# ---------------------------------------------------------------------------

def make_artifacts() -> dict:
    """Create deterministic mock 'runtime artifacts' to measure."""
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    files = {}
    for name, content in (
        ("vmlinuz-mock", b"MOCK KERNEL 6.8.0-sev-snp amd64 build\n" + b"K" * 2048),
        ("initrd-mock", b"MOCK INITRD: rocm userspace + gate\n" + b"I" * 1024),
        ("gate-mock", b"MOCK GATE PROGRAM: launch-gate.py v0.1\n" + b"G" * 512),
    ):
        p = ARTIFACTS_DIR / name
        p.write_bytes(content)
        files[name] = str(p)
    print(f"[mock] artifacts written to {ARTIFACTS_DIR}")
    return files


# ---------------------------------------------------------------------------

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init", help="create the mock ARK/ASK/VCEK hierarchy")

    p_rep = sub.add_parser("report", help="build a signed mock report")
    p_rep.add_argument("--report-data", default="",
                       help="nonce hex (32 bytes) echoed into REPORT_DATA")
    p_rep.add_argument("--kernel"); p_rep.add_argument("--initrd")
    p_rep.add_argument("--gate")
    p_rep.add_argument("--measurement", default="",
                       help="explicit 48-byte measurement hex (overrides --kernel/...)")
    p_rep.add_argument("--tcb", default="10.26.1", help="build.minor.major")
    # policy default: ABI minor=1, ABI major=1, SMT enabled (bit 16)
    p_rep.add_argument("--policy", type=lambda x: int(x, 0), default=0x10101)
    p_rep.add_argument("--guest-svn", type=lambda x: int(x, 0), default=1)
    p_rep.add_argument("--vmpl", type=int, default=0)
    p_rep.add_argument("--family-id", default="af" * 16, help="hex")
    p_rep.add_argument("--image-id", default="10" * 16, help="hex")
    p_rep.add_argument("--host-data", default="")
    p_rep.add_argument("--id-key-digest", default="")
    p_rep.add_argument("--tamper", choices=["measurement", "signature",
                                            "tcb", "report-data", "policy"])
    p_rep.add_argument("--out", default=str(REPORTS_DIR / "report.json"))

    p_art = sub.add_parser("make-artifacts",
                           help="create mock kernel/initrd/gate artifacts")
    p_meas = sub.add_parser("measure",
                            help="print the composed measurement for artifacts")
    p_meas.add_argument("--kernel"); p_meas.add_argument("--initrd")
    p_meas.add_argument("--gate")

    args = parser.parse_args(argv)
    if args.cmd == "init":
        init_hierarchy()
    elif args.cmd == "make-artifacts":
        make_artifacts()
    elif args.cmd == "measure":
        print(compose_measurement(args.kernel, args.initrd, args.gate))
    else:
        build_report(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
