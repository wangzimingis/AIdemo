#!/usr/bin/env bash
# guest/measure-runtime.sh
#
# Compose the runtime measurement baseline used by the KRS.
#
#   measurement = SHA-384( SHA-384(kernel) || SHA-384(initrd) || SHA-384(gate) )
#
# This mirrors (in simplified form) how the SEV-SNP launch measurement is
# built as a hash chain over launched components. Run this INSIDE a
# known-good VM image build, then register the printed value in the KRS
# baseline (krs/baselines/baseline.json, or scripts/measure_baseline.py).
# mock/mock-attest.py uses the exact same composition, so mock and real
# flows share one baseline format.
#
# Usage:
#   ./guest/measure-runtime.sh /boot/vmlinuz-6.8-sev /boot/initrd.img /opt/gate

set -euo pipefail

KERNEL="${1:?usage: measure-runtime.sh <kernel> <initrd> <gate>}"
INITRD="${2:?missing initrd}"
GATE="${3:?missing gate program}"

for f in "$KERNEL" "$INITRD" "$GATE"; do
    [ -f "$f" ] || { echo "not found: $f" >&2; exit 1; }
done

sha384_of() {
    if command -v sha384sum >/dev/null 2>&1; then
        sha384sum "$1" | cut -d' ' -f1
    else
        openssl dgst -sha384 -r "$1" | cut -d' ' -f1
    fi
}

K=$(sha384_of "$KERNEL")
I=$(sha384_of "$INITRD")
G=$(sha384_of "$GATE")

# compose: identical to mock-attest.py compose_measurement()
MEASUREMENT=$(python3 - "$KERNEL" "$INITRD" "$GATE" <<'PYEOF'
import hashlib, sys
d = b"".join(hashlib.sha384(open(p, "rb").read()).digest()
             for p in sys.argv[1:4])
print(hashlib.sha384(d).hexdigest())
PYEOF
)

cat <<EOF
# runtime measurement baseline
kernel  : $KERNEL
  sha384: $K
initrd  : $INITRD
  sha384: $I
gate    : $GATE
  sha384: $G
---
measurement: $MEASUREMENT
EOF
echo "$MEASUREMENT"
