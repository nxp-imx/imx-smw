#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2026 NXP
#
# MAC test suite - PSA backend (nxp_psa)
#
# Usage:
#   ./psa_mac.sh
#
# Requires: nxp_psa in PATH

CLI="nxp_psa"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INPUT_FILE=$(mktemp /tmp/psa_mac_input_XXXXXX.bin)

. "$SCRIPT_DIR/lib_mac.sh"

# Prepare shared input file
prepare_input_file "$INPUT_FILE"

# ---------------------------------------------------------------------------
# PSA-specific: persistent key tests
# PSA supports only ONE algorithm per key.
# ---------------------------------------------------------------------------
test_persistent_keys_psa() {
    base_id=7000

    section_header "Persistent key tests (PSA) ───────────────────────────────────────────┐"

    # Each test case: desc|type|size|key_algo|mac_algo|id
    cases="
AES-128 CMAC  persist|AES|128|CMAC|CMAC|$((base_id+1))
AES-256 CMAC  persist|AES|256|CMAC|CMAC|$((base_id+2))
AES-128 CBC-MAC  persist|AES|128|CBC-MAC|CBC-MAC|$((base_id+3))
HMAC-256 SHA256  persist|HMAC|256|SHA256|HMAC-SHA256|$((base_id+4))
HMAC-256 SHA512  persist|HMAC|256|SHA512|HMAC-SHA512|$((base_id+5))
HMAC-128 MD5  persist|HMAC|128|MD5|HMAC-MD5|$((base_id+6))
"

    echo "$cases" | while IFS='|' read -r desc kt sz key_algo mac_algo kid; do
        [ -z "$desc" ] && continue

        # Generate key
        $CLI keygen-sym -t "$kt" -s "$sz" -a "$key_algo" \
            -u sign,verify -i "$kid" 2>/dev/null

        # Compute + verify MAC
        run_mac_test "$desc" "$kid" "$mac_algo" "$INPUT_FILE"

        # Cleanup
        $CLI key-delete -i "$kid" 2>/dev/null
    done

    section_footer
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
echo "╔══════════════════════════════════════════════════════════════════════════╗"
echo "║       NXP PSA CLI — MAC Test Suite                                       ║"
echo "╚══════════════════════════════════════════════════════════════════════════╝"

if ! command -v "$CLI" >/dev/null 2>&1; then
    echo "ERROR: '$CLI' not found in PATH. Aborting."
    rm -f "$INPUT_FILE"
    exit 1
fi

# Use a persistent key for discover_and_test
DISCOVER_KEY_ID=7100
$CLI keygen-sym -t AES -s 256 -a CMAC -u sign,verify \
    -i $DISCOVER_KEY_ID 2>/dev/null

reset_counters

discover_and_test "$DISCOVER_KEY_ID" "$INPUT_FILE"
test_persistent_keys_psa
test_negative_cases "$INPUT_FILE"

$CLI key-delete -i $DISCOVER_KEY_ID 2>/dev/null

print_failure_report
print_summary

# Cleanup
rm -f "$INPUT_FILE"

[ "$FAIL" -eq 0 ]
