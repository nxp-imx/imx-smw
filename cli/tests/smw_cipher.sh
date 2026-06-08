#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2026 NXP
#
# Cipher test suite - SMW backend (nxp_smw)
#
# Usage:
#   ./smw_cipher.sh
#
# Requires: nxp_smw in PATH

CLI="nxp_smw"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INPUT_FILE=$(mktemp /tmp/smw_cipher_input_XXXXXX.bin)

. "$SCRIPT_DIR/lib_cipher.sh"

AES_IV="00112233445566778899aabbccddeeff"
DES3_IV="0011223344556677"
SM4_IV="00112233445566778899aabbccddeeff"

# ---------------------------------------------------------------------------
# SMW-specific: persistent key tests
# ---------------------------------------------------------------------------
test_persistent_keys_smw() {
    base_id=2000

    section_header "Persistent key tests (SMW) ───────────────────────────────────────────┐"

    # Each test case: desc|key_type|key_size|key_algo|cipher_algo|iv|bs|id
    cases="
AES-128 CBC|AES|128|CBC|AES-CBC|$AES_IV|16|$((base_id+1))
AES-128 CTR|AES|128|CTR|AES-CTR|$AES_IV|16|$((base_id+2))
AES-128 ECB|AES|128|ECB|AES-ECB||16|$((base_id+3))
AES-128 CFB|AES|128|CFB|AES-CFB|$AES_IV|16|$((base_id+4))
AES-128 OFB|AES|128|OFB|AES-OFB|$AES_IV|16|$((base_id+5))
AES-256 CBC|AES|256|CBC|AES-CBC|$AES_IV|16|$((base_id+6))
AES-256 CTR|AES|256|CTR|AES-CTR|$AES_IV|16|$((base_id+7))
AES-256 ECB|AES|256|ECB|AES-ECB||16|$((base_id+8))
DES3-192 CBC|DES3|192|CBC|DES3-CBC|$DES3_IV|8|$((base_id+9))
DES3-192 ECB|DES3|192|ECB|DES3-ECB||8|$((base_id+10))
SM4-128 CBC|SM4|128|CBC|SM4-CBC|$SM4_IV|16|$((base_id+11))
SM4-128 CTR|SM4|128|CTR|SM4-CTR|$SM4_IV|16|$((base_id+12))
SM4-128 ECB|SM4|128|ECB|SM4-ECB||16|$((base_id+13))
"

    echo "$cases" | while IFS='|' read -r desc kt sz key_algo cipher_algo iv bs kid; do
        [ -z "$desc" ] && continue

        $CLI keygen-sym -t "$kt" -s "$sz" -a "$key_algo" \
            -u encrypt,decrypt -i "$kid" 2>/dev/null

        run_cipher_test "$desc" "$kid" "$cipher_algo" "$bs" "$iv"

        $CLI key-delete -i "$kid" 2>/dev/null
    done

    section_footer
}

# ---------------------------------------------------------------------------
# SMW-specific: subsystem tests (ELE)
# ---------------------------------------------------------------------------
test_subsystem_smw() {
    base_id=2100
    subsystem="ELE"

    section_header "Subsystem tests ($subsystem) ────────────────────────────────────────────┐"

    cases="
AES-128 CBC ELE|AES|128|CBC|AES-CBC|$AES_IV|16|$((base_id+1))
AES-256 CBC ELE|AES|256|CBC|AES-CBC|$AES_IV|16|$((base_id+2))
AES-128 CTR ELE|AES|128|CTR|AES-CTR|$AES_IV|16|$((base_id+3))
AES-128 ECB ELE|AES|128|ECB|AES-ECB||16|$((base_id+4))
"

    echo "$cases" | while IFS='|' read -r desc kt sz key_algo cipher_algo iv bs kid; do
        [ -z "$desc" ] && continue

        $CLI keygen-sym -t "$kt" -s "$sz" -a "$key_algo" \
            -u encrypt,decrypt -i "$kid" -S "$subsystem" 2>/dev/null

        run_cipher_test "$desc" "$kid" "$cipher_algo" "$bs" "$iv" "-S $subsystem"

        $CLI key-delete -i "$kid" 2>/dev/null
    done

    section_footer
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
echo "╔══════════════════════════════════════════════════════════════════════════╗"
echo "║       NXP SMW CLI — Cipher Algorithm Test Suite                          ║"
echo "╚══════════════════════════════════════════════════════════════════════════╝"

if ! command -v "$CLI" >/dev/null 2>&1; then
    echo "ERROR: '$CLI' not found in PATH. Aborting."
    rm -f "$INPUT_FILE"
    exit 1
fi

reset_counters

test_persistent_keys_smw
test_subsystem_smw
test_negative_cases "$INPUT_FILE"

print_failure_report
print_summary

# Cleanup
rm -f "$INPUT_FILE"

[ "$FAIL" -eq 0 ]
