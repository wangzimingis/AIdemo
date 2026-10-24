#!/usr/bin/env bash
# scripts/setup-sev-snp.sh
#
# Week-1 checklist: verify SEV-SNP availability on an AMD cloud instance
# (AMD Developer Cloud / cSP instances, or a bare EPYC 7003/9004 host),
# then install the attestation toolchain.
#
# Run INSIDE the (candidate) confidential VM. Exit code 0 = environment OK.

set -euo pipefail

ok()   { printf '  [ OK ] %s\n' "$*"; }
fail() { printf '  [FAIL] %s\n' "$*"; FAILED=1; }
FAILED=0

echo "== 1. CPU / platform =="
if grep -qw sev_snp /proc/cpuinfo 2>/dev/null; then
    ok "CPUID advertises SEV-SNP"
else
    fail "cpuinfo does not advertise sev_snp (not an SNP-capable EPYC, or the VM was not launched with SNP policy)"
fi
lscpu | grep -E 'Model name|^CPU\(s\)' || true

echo "== 2. kernel + sev-guest device =="
uname -r
KVER=$(uname -r | cut -d. -f1)
if [ "$KVER" -ge 6 ]; then ok "kernel >= 6.x (sev-guest in mainline since 5.19)"; else fail "kernel too old"; fi
if lsmod | grep -q sev_guest; then
    ok "sev_guest module loaded"
elif [ -e /dev/sev-guest ]; then
    ok "/dev/sev-guest present (module builtin)"
else
    if modprobe sev_guest 2>/dev/null && [ -e /dev/sev-guest ]; then
        ok "sev_guest module loaded on demand"
    else
        fail "/dev/sev-guest missing: you are NOT running inside an SNP-encrypted VM"
    fi
fi
[ -e /dev/sev ] && ok "/dev/sev present (host side)" || true
dmesg 2>/dev/null | grep -iE 'sev|snp' | tail -5 || true

echo "== 3. ROCm userspace =="
if command -v rocminfo >/dev/null 2>&1; then
    rocminfo | grep -m2 -E 'Marketing Name|Compute Unit' || true
    ok "rocminfo available"
else
    echo "  [ .. ] rocminfo not found — install ROCm 6.x or use the rocm/rocminfo:6.x container"
fi

echo "== 4. attestation toolchain =="
if command -v snpguest >/dev/null 2>&1; then
    ok "snpguest: $(snpguest --version 2>/dev/null || echo present)"
else
    echo "  [ .. ] snpguest missing. Install with:"
    echo "           cargo install snpguest            # from source (rust)"
    echo "         or download a prebuilt release from github.com/virtee/snpguest"
fi
if command -v sevctl >/dev/null 2>&1; then
    ok "sevctl present"
else
    echo "  [ .. ] sevctl optional (cargo install sevctl)"
fi

echo "== 5. python deps (KRS + guest) =="
python3 - <<'PYEOF' && ok "python deps ready" || echo "  [ .. ] run: pip install -r requirements.txt"
import fastapi, cryptography, uvicorn  # noqa
PYEOF

echo
if [ "$FAILED" -eq 0 ]; then
    echo "ALL CHECKS PASSED — proceed with scripts/get-attestation.sh"
else
    echo "SOME CHECKS FAILED — see marks above; confirm the instance type"
    echo "supports confidential VMs (SEV-SNP policy) before continuing."
    exit 1
fi
