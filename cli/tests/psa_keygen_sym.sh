#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2026 NXP
#
# Symmetric key generation test suite - PSA backend (nxp_psa)
#
# Usage:
#   ./test_keygen_sym_psa.sh
#
# Requires: nxp_psa in PATH

set -o pipefail

CLI="nxp_psa"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

source "$SCRIPT_DIR/lib_keygen_sym.sh"

# ---------------------------------------------------------------------------
# PSA-specific: persistent key tests
#   PSA supports only ONE algorithm per key.
# ---------------------------------------------------------------------------
test_persistent_keys_psa() {
    local base_id=6000

    section_header "Persistent key tests (PSA) ───────────────────────────────────────────┐"

    local cases=(
        # desc                              type  size  algo    usage           id
        "AES-256 CBC  encrypt/decrypt  persist"  "AES"  256  "CBC"   "encrypt,decrypt" $((base_id+1))
        "AES-128 GCM  encrypt/decrypt  persist"  "AES"  128  "GCM"   "encrypt,decrypt" $((base_id+2))
        "HMAC-256 SHA256  sign/verify  persist"  "HMAC" 256  "SHA256" "sign,verify"    $((base_id+3))
        "AES-128 CMAC  sign/verify  persist"     "AES"  128  "CMAC"  "sign,verify"    $((base_id+4))
    )

    # Iterate in groups of 6
    local i=0
    while [ $i -lt ${#cases[@]} ]; do
        local desc="${cases[$i]}"
        local kt="${cases[$((i+1))]}"
        local sz="${cases[$((i+2))]}"
        local algo="${cases[$((i+3))]}"
        local usage="${cases[$((i+4))]}"
        local kid="${cases[$((i+5))]}"

        run_keygen_test "$desc" "$kt" "$sz" "$algo" "$usage" "-i $kid"

        # Cleanup on success (key already counted)
        $CLI key-delete -i "$kid" 2>/dev/null

        i=$((i+6))
    done

    section_footer
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
echo "╔══════════════════════════════════════════════════════════════════════════╗"
echo "║       NXP PSA CLI — Symmetric Key Generation Test Suite                  ║"
echo "╚══════════════════════════════════════════════════════════════════════════╝"

if ! command -v "$CLI" &>/dev/null; then
    echo "ERROR: '$CLI' not found in PATH. Aborting."
    exit 1
fi

discover_and_test
test_persistent_keys_psa
test_negative_cases

print_failure_report
print_summary

[ "$FAIL" -eq 0 ]