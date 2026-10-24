#!/usr/bin/env bash
# scripts/get-attestation.sh
#
# Fetch a raw SEV-SNP attestation report + the AMD certificate chain from
# inside a running confidential VM. Produces:
#   /tmp/sev/report.bin    raw 0x1000 report
#   /tmp/sev/report.b64    base64 for the KRS JSON protocol
#   /tmp/sev/certs/        vcek.der / ask.der / ark.der (AMD KDS chain)
#
# The nonce (REPORT_DATA) is taken from $1 if provided, otherwise random.
# Feed the KRS challenge nonce here to make the report replay-bound.

set -euo pipefail

NONCE_HEX="${1:-$(od -An -tx1 -N32 /dev/urandom | tr -d ' \n')}"
OUT="${OUT:-/tmp/sev}"
mkdir -p "$OUT/certs"

echo "nonce (REPORT_DATA): $NONCE_HEX"

# --- certificates from AMD KDS ---------------------------------------------
# snpguest fetch vcek writes vcek.der + the ARK/ASK chain
if command -v snpguest >/dev/null 2>&1; then
    snpguest fetch vcek --save "$OUT/certs"
    ok_cert=1
else
    echo "snpguest not found — fetching ARK/ASK from AMD and VCEK from KDS via curl"
    # KDS endpoint (SNP firmware ABI spec 4.1):
    #   GET https://kdsintf.amd.com/vcek/v1/<product>/<chip_id>?specver=2&<TCB fields>
    # chip_id + TCB fields are obtained via the SNP_GET_ID ioctl; snpguest
    # automates all of this, which is why it is the recommended path.
    echo "  chip-id discovery requires snpguest — aborting curl path."
    exit 2
fi

# --- report ----------------------------------------------------------------
if command -v snpguest >/dev/null 2>&1; then
    snpguest fetch report --report-data "$NONCE_HEX" --output "$OUT/report.bin"
    # display for the run log
    snpguest display report --file "$OUT/report.bin" || true
else
    echo "no report tool available"
    exit 3
fi

base64 -w0 "$OUT/report.bin" > "$OUT/report.b64"
echo
echo "report  : $OUT/report.bin ($(stat -c%s "$OUT/report.bin") bytes)"
echo "b64     : $OUT/report.b64"
echo "certs   : $OUT/certs"
echo
echo "next: python guest/launch-gate.py --report-file $OUT/report.bin --certs-dir $OUT/certs --krs https://<krs>:8443 ..."
