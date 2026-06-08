#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2026 NXP
#
# Asymmetric encryption test suite - PSA backend (nxp_psa)
#
# Usage:
#   ./psa_asym_enc.sh
#
# Requires: nxp_psa in PATH

CLI="nxp_psa"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INPUT_FILE=$(mktemp /tmp/psa_asym_enc_input_XXXXXX.bin)

. "$SCRIPT_DIR/lib_asym_enc.sh"

# ---------------------------------------------------------------------------
# PSA-specific: persistent key tests
# PSA supports only ONE algorithm per key.
# ---------------------------------------------------------------------------
test_persistent_keys_psa() {
    base_id=8000

    section_header "Persistent key tests (PSA) ───────────────────────────────────────────┐"

    # Each test case: desc|key_size|key_algo|enc_algo|salt|input_size|id
    cases="
RSA-2048 OAEP-SHA1   no-salt|2048|OAEP-SHA1|RSA-OAEP-SHA1||32|$((base_id+1))
RSA-2048 OAEP-SHA224 no-salt|2048|OAEP-SHA224|RSA-OAEP-SHA224||32|$((base_id+2))
RSA-2048 OAEP-SHA256 no-salt|2048|OAEP-SHA256|RSA-OAEP-SHA256||64|$((base_id+3))
RSA-2048 OAEP-SHA384 no-salt|2048|OAEP-SHA384|RSA-OAEP-SHA384||64|$((base_id+4))
RSA-2048 OAEP-SHA512 no-salt|2048|OAEP-SHA512|RSA-OAEP-SHA512||64|$((base_id+5))
RSA-2048 OAEP-SHA256 salt|2048|OAEP-SHA256|RSA-OAEP-SHA256|aabbccdd00112233|64|$((base_id+6))
RSA-2048 OAEP-SHA384 salt|2048|OAEP-SHA384|RSA-OAEP-SHA384|aabbccdd00112233|64|$((base_id+7))
RSA-2048 OAEP-SHA512 salt|2048|OAEP-SHA512|RSA-OAEP-SHA512|aabbccdd00112233|64|$((base_id+8))
RSA-2048 PKCS1V15|2048|PKCS1V15-CRYPT|RSA-PKCS1V15||64|$((base_id+9))
RSA-3072 OAEP-SHA256 no-salt|3072|OAEP-SHA256|RSA-OAEP-SHA256||128|$((base_id+10))
RSA-3072 OAEP-SHA512 no-salt|3072|OAEP-SHA512|RSA-OAEP-SHA512||128|$((base_id+11))
RSA-4096 OAEP-SHA256 no-salt|4096|OAEP-SHA256|RSA-OAEP-SHA256||128|$((base_id+12))
RSA-4096 OAEP-SHA384 no-salt|4096|OAEP-SHA384|RSA-OAEP-SHA384||128|$((base_id+13))
RSA-4096 OAEP-SHA512 no-salt|4096|OAEP-SHA512|RSA-OAEP-SHA512||128|$((base_id+14))
RSA-4096 PKCS1V15|4096|PKCS1V15-CRYPT|RSA-PKCS1V15||128|$((base_id+15))
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
# Main
# ---------------------------------------------------------------------------
echo "╔══════════════════════════════════════════════════════════════════════════╗"
echo "║       NXP PSA CLI — Asymmetric Encryption Test Suite                     ║"
echo "╚══════════════════════════════════════════════════════════════════════════╝"

if ! command -v "$CLI" >/dev/null 2>&1; then
    echo "ERROR: '$CLI' not found in PATH. Aborting."
    rm -f "$INPUT_FILE"
    exit 1
fi

reset_counters

test_persistent_keys_psa
test_negative_cases "$INPUT_FILE"

print_failure_report
print_summary

# Cleanup
rm -f "$INPUT_FILE"

[ "$FAIL" -eq 0 ]
