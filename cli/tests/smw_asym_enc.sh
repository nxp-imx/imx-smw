#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2026 NXP
#
# Asymmetric encryption test suite - SMW backend (nxp_smw)
#
# Usage:
#   ./smw_asym_enc.sh
#
# Requires: nxp_smw in PATH

CLI="nxp_smw"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INPUT_FILE=$(mktemp /tmp/smw_asym_enc_input_XXXXXX.bin)

. "$SCRIPT_DIR/lib_asym_enc.sh"

# ---------------------------------------------------------------------------
# SMW-specific: persistent key tests
# ---------------------------------------------------------------------------
test_persistent_keys_smw() {
    base_id=6000

    section_header "Persistent key tests (SMW) ───────────────────────────────────────────┐"

    # Each test case: desc|key_size|key_algo|enc_algo|salt|input_size|id
    cases="
RSA-2048 OAEP-SHA256 no-salt|2048|OAEP-SHA256|RSA-OAEP-SHA256||64|$((base_id+1))
RSA-2048 OAEP-SHA384 no-salt|2048|OAEP-SHA384|RSA-OAEP-SHA384||64|$((base_id+2))
RSA-2048 OAEP-SHA512 no-salt|2048|OAEP-SHA512|RSA-OAEP-SHA512||64|$((base_id+3))
RSA-2048 OAEP-SHA256 salt|2048|OAEP-SHA256|RSA-OAEP-SHA256|aabbccdd00112233|64|$((base_id+4))
RSA-2048 OAEP-SHA384 salt|2048|OAEP-SHA384|RSA-OAEP-SHA384|aabbccdd00112233|64|$((base_id+5))
RSA-2048 OAEP-SHA512 salt|2048|OAEP-SHA512|RSA-OAEP-SHA512|aabbccdd00112233|64|$((base_id+6))
RSA-4096 OAEP-SHA256 no-salt|4096|OAEP-SHA256|RSA-OAEP-SHA256||128|$((base_id+7))
RSA-4096 OAEP-SHA384 no-salt|4096|OAEP-SHA384|RSA-OAEP-SHA384||128|$((base_id+8))
RSA-4096 OAEP-SHA512 no-salt|4096|OAEP-SHA512|RSA-OAEP-SHA512||128|$((base_id+9))
"

    echo "$cases" | while IFS='|' read -r desc key_size key_algo enc_algo salt input_size kid; do
        [ -z "$desc" ] && continue

        # Generate RSA key pair with encrypt/decrypt usage
        $CLI keygen-asym -t RSA -s "$key_size" -a "$key_algo" \
            -u encrypt,decrypt -i "$kid" 2>/dev/null

        # Encrypt + decrypt round-trip
        run_asym_enc_test "$desc" "$kid" "$enc_algo" "$salt" "$input_size" "$INPUT_FILE"

        # Cleanup
        $CLI key-delete -i "$kid" 2>/dev/null
    done

    section_footer
}

# ---------------------------------------------------------------------------
# SMW-specific: subsystem tests (ELE)
# ---------------------------------------------------------------------------
test_subsystem_smw() {
    base_id=6100
    subsystem="ELE"

    section_header "Subsystem tests ($subsystem) ────────────────────────────────────────────┐"

    cases="
RSA-2048 OAEP-SHA256 ELE|2048|OAEP-SHA256|RSA-OAEP-SHA256||64|$((base_id+1))
RSA-2048 OAEP-SHA512 ELE|2048|OAEP-SHA512|RSA-OAEP-SHA512||64|$((base_id+2))
RSA-4096 OAEP-SHA256 ELE|4096|OAEP-SHA256|RSA-OAEP-SHA256||128|$((base_id+3))
"

    echo "$cases" | while IFS='|' read -r desc key_size key_algo enc_algo salt input_size kid; do
        [ -z "$desc" ] && continue

        $CLI keygen-asym -t RSA -s "$key_size" -a "$key_algo" \
            -u encrypt,decrypt -i "$kid" -S "$subsystem" 2>/dev/null

        run_asym_enc_test "$desc" "$kid" "$enc_algo" "$salt" \
            "$input_size" "$INPUT_FILE" "-S $subsystem"

        $CLI key-delete -i "$kid" 2>/dev/null
    done

    section_footer
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
echo "╔══════════════════════════════════════════════════════════════════════════╗"
echo "║       NXP SMW CLI — Asymmetric Encryption Test Suite                     ║"
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
