# guest/get_report.py
"""
Obtain a SEV-SNP attestation report (the 0x1000-byte blob + VCEK chain).

Two sources are supported:

  real  - inside a genuine SEV-SNP confidential VM, via the /dev/sev-guest
          ioctl interface (kernel >= 5.19, CONFIG_SEV_GUEST). A fallback
          path ingests a report previously fetched with snpguest/sevctl.

  mock  - via mock/mock-attest.py, for hardware-less development and the
          end-to-end local demo (scripts/demo_local.py).

get_report() picks the source automatically unless `mode` is forced.
"""

from __future__ import annotations

import os
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common.snp_layout import REPORT_SIZE, SIGNATURE_OFF  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
SEV_GUEST_DEV = "/dev/sev-guest"

# ---------------------------------------------------------------------------
# REAL HARDWARE PATH 1: /dev/sev-guest ioctl
# ---------------------------------------------------------------------------
# uapi: include/uapi/linux/sev-guest.h (mainline >= 5.19)
#
#   struct snp_guest_request_ioctl {   /* 24 bytes */
#       __u8  msg_version;            /* must be >= 1 */
#       __u64 req_data;               /* ptr to snp_report_req  */
#       __u64 resp_data;              /* ptr to snp_report_resp */
#   };
#   struct snp_report_req {           /* 96 bytes */
#       __u8  report_data[64];
#       __u32 vmpl;
#       __u8  rsvd[28];
#   };
#
#   #define SNP_GET_REPORT _IOWR(SEV_GUEST_IOC_TYPE, 0x0,
#                               struct snp_guest_request_ioctl)
#
# EXPERIMENTAL: the ioctl command word below encodes type 'B', nr 0 and
# argsize 24 (0xC0184200). If your kernel disagrees, the call returns
# EINVAL — fall back to the snpguest file path instead.

SNP_GET_REPORT_CMDS = (0xC0184200, 0xC0189300)  # type 'B' / 0x93 variants
MSG_VERSION = 1


def _report_looks_valid(buf: bytes) -> bool:
    if len(buf) < REPORT_SIZE:
        return False
    if int.from_bytes(buf[0:4], "little") != 2:
        return False
    return any(buf[SIGNATURE_OFF:SIGNATURE_OFF + 72])


def get_report_ioctl(report_data: bytes, vmpl: int = 0) -> bytes:
    """Request an attestation report via /dev/sev-guest (Linux only)."""
    import fcntl  # not importable on Windows; keep inside the function

    if not os.path.exists(SEV_GUEST_DEV):
        raise RuntimeError(
            f"{SEV_GUEST_DEV} not found — this host is not a running "
            "SEV-SNP confidential VM (or the sev-guest module is missing)")

    req = report_data.ljust(64, b"\x00") + struct.pack("<I", vmpl) + b"\x00" * 28

    import ctypes
    req_buf = ctypes.create_string_buffer(bytes(req), len(req))
    resp_buf = ctypes.create_string_buffer(REPORT_SIZE + 64)

    fd = os.open(SEV_GUEST_DEV, os.O_RDWR)
    try:
        last_err: Exception = RuntimeError("no ioctl variant attempted")
        for cmd in SNP_GET_REPORT_CMDS:
            # struct snp_guest_request_ioctl { u8 msg_version; pad[7];
            #                                  u64 req_data; u64 resp_data; }
            arg = struct.pack(
                "<B7xQQ", MSG_VERSION,
                ctypes.addressof(req_buf), ctypes.addressof(resp_buf))
            try:
                fcntl.ioctl(fd, cmd, arg)
            except OSError as e:
                last_err = e
                continue
            out = bytes(resp_buf.raw[:REPORT_SIZE])
            if _report_looks_valid(out):
                return out
            last_err = RuntimeError("sev-guest returned a malformed report")
            break
        raise RuntimeError(f"SNP_GET_REPORT ioctl failed: {last_err}. "
                           "Install snpguest (cargo install snpguest) and use "
                           "scripts/get-attestation.sh instead.")
    finally:
        os.close(fd)


# ---------------------------------------------------------------------------
# REAL HARDWARE PATH 2: ingest a report file produced by snpguest / sevctl
# ---------------------------------------------------------------------------

def load_report_file(path: str) -> bytes:
    raw = Path(path).read_bytes()
    if not _report_looks_valid(raw):
        raise RuntimeError(
            f"{path} does not look like a raw 0x1000 SEV-SNP report")
    return raw


def load_certs_pem(certs_dir: str) -> dict:
    """
    Load ARK/ASK/VCEK certificates, DER or PEM, as PEM strings.

    On real hardware produce these with:
        snpguest fetch vcek --save <certs_dir>   (writes vcek.der + chain)
    """
    d = Path(certs_dir)
    out = {}
    for name in ("ark", "ask", "vcek"):
        for cand in (d / f"{name}.pem", d / f"{name}.der", d / f"{name}.crt"):
            if cand.exists():
                blob = cand.read_bytes()
                if b"-----BEGIN" not in blob:
                    blob = x509.load_der_x509_certificate(blob).public_bytes(
                        Encoding.PEM)
                out[f"{name}_pem"] = blob.decode()
                break
    missing = [n for n in ("ark", "ask", "vcek") if f"{n}_pem" not in out]
    if missing:
        raise RuntimeError(
            f"missing certificates in {certs_dir}: {missing}. "
            "Fetch them from the AMD KDS (see scripts/get-attestation.sh).")
    return out


# ---------------------------------------------------------------------------
# MOCK PATH
# ---------------------------------------------------------------------------

def get_report_mock(report_data_hex: str, repo_root: Path,
                    artifacts: Optional[dict] = None,
                    tamper: Optional[str] = None,
                    measurement_hex: str = "") -> dict:
    """Generate a mock attestation bundle by shelling out to mock-attest.py."""
    artifacts = artifacts or {}
    tmp = tempfile.mkdtemp(prefix="snpguest-mock-")
    out = str(Path(tmp) / "report.json")
    cmd = [sys.executable, str(repo_root / "mock" / "mock-attest.py"),
           "report", "--report-data", report_data_hex, "--out", out]
    for key in ("kernel", "initrd", "gate"):
        if artifacts.get(key):
            cmd += [f"--{key}", artifacts[key]]
    if measurement_hex:
        cmd += ["--measurement", measurement_hex]
    if tamper:
        cmd += ["--tamper", tamper]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"mock-attest failed: {proc.stderr}\n{proc.stdout}")
    import json
    return json.loads(Path(out).read_text())


# ---------------------------------------------------------------------------
# top-level dispatcher
# ---------------------------------------------------------------------------

def get_attestation_bundle(report_data: bytes,
                           mode: str = "auto",
                           repo_root: Optional[Path] = None,
                           certs_dir: str = "/etc/sev/certs",
                           report_file: Optional[str] = None,
                           artifacts: Optional[dict] = None,
                           tamper: Optional[str] = None,
                           measurement_hex: str = "") -> dict:
    """
    Returns the dict consumed by gate_client.request_key():
      {report_b64, vcek_pem, ask_pem, ark_pem, ...}
    """
    repo_root = repo_root or REPO_ROOT
    real_available = sys.platform == "linux" and (
        os.path.exists(SEV_GUEST_DEV) or report_file is not None)
    if mode == "auto":
        mode = "real" if real_available else "mock"

    if mode == "real":
        import base64
        if report_file:
            raw = load_report_file(report_file)
        else:
            raw = get_report_ioctl(report_data)
        bundle = {"report_b64": base64.b64encode(raw).decode()}
        bundle.update(load_certs_pem(certs_dir))
        return bundle

    # mock
    return get_report_mock(report_data.hex(), repo_root, artifacts, tamper,
                           measurement_hex)
