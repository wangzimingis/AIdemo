# common/snp_layout.py
"""
SEV-SNP attestation report binary layout constants.

Layout follows the AMD SEV-SNP Firmware ABIs Specification (Table 22,
ATTESTATION_REPORT structure, spec rev >= 1.51 incl. HOST_DATA).

The full report is 0x1000 (4096) bytes. The VCEK signature covers the
first SIGNED_SIZE (0x2A0) bytes of the report. The ECDSA-P384 signature
stores R and S as 72-byte big-endian integers at SIGNATURE_OFFSET.

This module is intentionally dependency-free so that it can be imported
by the KRS verifier, the guest tools and the mock report generator.
"""

from __future__ import annotations

REPORT_SIZE = 0x1000          # total size of an attestation report
SIGNED_SIZE = 0x2A0           # bytes covered by the VCEK signature
SIGNATURE_SIZE = 512          # SIGNATURE field (R[72] || S[72] || reserved[368])

# --- field offsets / sizes -------------------------------------------------
VERSION_OFF, VERSION_SZ = 0x00, 4        # report format version (=2)
GUEST_SVN_OFF, GUEST_SVN_SZ = 0x04, 4    # guest firmware SVN
POLICY_OFF, POLICY_SZ = 0x08, 8          # SNP guest policy bitfield
FAMILY_ID_OFF, FAMILY_ID_SZ = 0x10, 16   # CPU family id
IMAGE_ID_OFF, IMAGE_ID_SZ = 0x20, 16     # CPU image id
VMPL_OFF, VMPL_SZ = 0x30, 4              # VMPL the report was requested at
SIGNATURE_ALGO_OFF, SIGNATURE_ALGO_SZ = 0x34, 4
CURRENT_TCB_OFF, CURRENT_TCB_SZ = 0x38, 8   # TCB version (see parse_tcb)
PLATFORM_INFO_OFF, PLATFORM_INFO_SZ = 0x40, 8
RESERVED_1_OFF, RESERVED_1_SZ = 0x48, 12
REPORT_ID_OFF, REPORT_ID_SZ = 0x54, 32  # unique ID of the guest
REPORT_ID_MA_OFF, REPORT_ID_MA_SZ = 0x74, 16
RESERVED_2_OFF, RESERVED_2_SZ = 0x84, 12
MEASUREMENT_OFF, MEASUREMENT_SZ = 0x90, 48      # SHA-384 launch measurement
HOST_DATA_OFF, HOST_DATA_SZ = 0xC0, 32          # hypervisor-provided data
ID_KEY_DIGEST_OFF, ID_KEY_DIGEST_SZ = 0xE0, 48      # ID block digest
AUTHOR_KEY_DIGEST_OFF, AUTHOR_KEY_DIGEST_SZ = 0x110, 48  # author key digest
REPORT_DATA_OFF, REPORT_DATA_SZ = 0x140, 64     # caller-provided nonce
RESERVED_3_OFF, RESERVED_3_SZ = 0x180, 32
SIGNATURE_OFF = 0x2A0           # R at 0x2A0, S at 0x2E8 (72 bytes each)

SIG_ALGO_ECDSA_P384 = 1          # ECC_P384 with SHA-384
REPORT_VERSION = 2

# --- guest policy bits (POLICY field) ---------------------------------------
# bits [0:8)   ABI minor version
# bits [8:16)  ABI major version
# bit  16      SMT is enabled in the guest
# bit  24      guest migration restricted to a single socket
POLICY_SMT_BIT = 16
POLICY_SINGLE_SOCKET_BIT = 24


def policy_abi_minor(policy: int) -> int:
    return policy & 0xFF


def policy_abi_major(policy: int) -> int:
    return (policy >> 8) & 0xFF


def parse_tcb(tcb_bytes: bytes) -> dict:
    """
    CURRENT_TCB (u64, little-endian):
      byte 0     microcode/firmware build
      byte 1     minor
      bytes 2-3  major (u16 LE)
      bytes 4-7  reserved
    """
    if len(tcb_bytes) != 8:
        raise ValueError("TCB field must be 8 bytes")
    return {
        "build": tcb_bytes[0],
        "minor": tcb_bytes[1],
        "major": int.from_bytes(tcb_bytes[2:4], "little"),
        "raw": int.from_bytes(tcb_bytes, "little"),
    }


def tcb_bytes(build: int, minor: int, major: int) -> bytes:
    return bytes([build, minor]) + major.to_bytes(2, "little") + b"\x00" * 4


def tcb_not_older_than(actual: dict, baseline: dict) -> bool:
    """Anti-rollback: every TCB component must be >= the baseline component."""
    return (
        actual["build"] >= baseline["build"]
        and actual["minor"] >= baseline["minor"]
        and actual["major"] >= baseline["major"]
    )


def field(report: bytes, off: int, size: int) -> bytes:
    if len(report) < off + size:
        raise ValueError(
            f"report too short ({len(report)}B) for field @0x{off:03X}+{size}"
        )
    return report[off:off + size]
