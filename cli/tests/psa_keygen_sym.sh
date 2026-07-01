#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2026 NXP
#
# Symmetric key generation test suite - PSA backend (nxp_psa)
#
# Usage:
#   ./psa_keygen_sym.sh
#
# Requires: nxp_psa in PATH

CLI="nxp_psa"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

. "$SCRIPT_DIR/lib_keygen_sym.sh"

# ---------------------------------------------------------------------------
# PSA-specific: persistent key tests
#   PSA supports only ONE algorithm per key.
# ---------------------------------------------------------------------------
test_persistent_keys_psa() {
    base_id=6000

    section_header "Persistent key tests (PSA) ───────────────────────────────────────────┐"

    # Each test case: desc|type|size|algo|usage|id
    cases="
AES-256 CBC  encrypt/decrypt  persist|AES|256|CBC|encrypt,decrypt|$((base_id+1))
AES-128 GCM  encrypt/decrypt  persist|AES|128|GCM|encrypt,decrypt|$((base_id+2))
HMAC-256 SHA256  sign/verify  persist|HMAC|256|SHA256|sign,verify|$((base_id+3))
AES-128 CMAC  sign/verify  persist|AES|128|CMAC|sign,verify|$((base_id+4))
"

    echo "$cases" | while IFS='|' read -r desc kt sz algo usage kid; do
        [ -z "$desc" ] && continue
        run_keygen_test "$desc" "$kt" "$sz" "$algo" "$usage" "-i $kid"
        $CLI key-delete -i "$kid" 2>/dev/null
    done

    section_footer
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
echo "╔══════════════════════════════════════════════════════════════════════════╗"
echo "║       NXP PSA CLI — Symmetric Key Generation Test Suite                  ║"
echo "╚══════════════════════════════════════════════════════════════════════════╝"

if ! command -v "$CLI" >/dev/null 2>&1; then
    echo "ERROR: '$CLI' not found in PATH. Aborting."
    exit 1
fi

discover_and_test
test_persistent_keys_psa
test_negative_cases

print_failure_report
print_summary

[ "$FAIL" -eq 0 ]
