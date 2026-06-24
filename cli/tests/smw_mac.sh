#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2026 NXP
#
# MAC test suite - SMW backend (nxp_smw)
#
# Usage:
#   ./smw_mac.sh [--subsystem ELE|TEE|SECO]
#
# Requires: nxp_smw in PATH

CLI="nxp_smw"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SUBSYSTEM=""
INPUT_FILE=$(mktemp /tmp/smw_mac_input_XXXXXX.bin)

# Parse optional --subsystem argument
while [ $# -gt 0 ]; do
    case "$1" in
        --subsystem|-S)
            SUBSYSTEM="$2"; shift 2 ;;
        *)
            echo "Unknown argument: $1"; exit 1 ;;
    esac
done

. "$SCRIPT_DIR/lib_mac.sh"

# Prepare shared input file
prepare_input_file "$INPUT_FILE"

# ---------------------------------------------------------------------------
# SMW extra flags helper
# ---------------------------------------------------------------------------
_smw_extra() {
    flags="${1:-}"
    [ -n "$SUBSYSTEM" ] && flags="$flags -S $SUBSYSTEM"
    echo "$flags"
}

# ---------------------------------------------------------------------------
# SMW-specific: persistent key tests
# ---------------------------------------------------------------------------
test_persistent_keys_smw() {
    base_id=8000

    section_header "Persistent key tests (SMW) ───────────────────────────────────────────┐"

    extra=$(_smw_extra "")

    # Each test case: desc|type|size|key_algo|mac_algo|id
    tmp_cases=$(mktemp)
    cat > "$tmp_cases" << EOF
AES-128 CMAC  persist|AES|128|CMAC|CMAC|$((base_id+1))
AES-256 CMAC  persist|AES|256|CMAC|CMAC|$((base_id+2))
HMAC-256 SHA256  persist|HMAC|256|SHA256|HMAC-SHA256|$((base_id+3))
HMAC-256 SHA512  persist|HMAC|256|SHA512|HMAC-SHA512|$((base_id+4))
EOF

    while IFS='|' read -r desc kt sz key_algo mac_algo kid; do
        [ -z "$desc" ] && continue

        # Generate key
        $CLI keygen-sym -t "$kt" -s "$sz" -a "$key_algo" \
            -u sign,verify -i "$kid" $extra 2>/dev/null

        # Compute + verify MAC
        run_mac_test "$desc" "$kid" "$mac_algo" "$INPUT_FILE" "$extra"

        # Cleanup
        $CLI key-delete -i "$kid" $extra 2>/dev/null
    done < "$tmp_cases"

    rm -f "$tmp_cases"

    section_footer
}

# ---------------------------------------------------------------------------
# SMW-specific: transient key tests
# ---------------------------------------------------------------------------
test_transient_keys_smw() {
    section_header "Transient key tests (SMW) ────────────────────────────────────────────┐"

    extra=$(_smw_extra "--transient")

    # Each test case: desc|type|size|key_algo|mac_algo
    tmp_cases=$(mktemp)
    cat > "$tmp_cases" << EOF
AES-128 CMAC  transient|AES|128|CMAC|CMAC
AES-256 CMAC  transient|AES|256|CMAC|CMAC
HMAC-256 SHA256  transient|HMAC|256|SHA256|HMAC-SHA256
HMAC-256 SHA384  transient|HMAC|256|SHA384|HMAC-SHA384
HMAC-128 SHA256  transient|HMAC|128|SHA256|HMAC-SHA256
EOF

    while IFS='|' read -r desc kt sz key_algo mac_algo; do
        [ -z "$desc" ] && continue

        # Generate transient key and get its ID from output
        keygen_out=$($CLI keygen-sym -t "$kt" -s "$sz" -a "$key_algo" \
            -u sign,verify $extra 2>&1)
        kid=$(echo "$keygen_out" | grep -oE 'ID: 0x[0-9a-fA-F]+' | \
            head -1 | grep -oE '0x[0-9a-fA-F]+')

        if [ -z "$kid" ]; then
            _print_row "$desc"
            echo "FAIL  (keygen failed)"
            _record_fail "$desc (keygen)" \
                "$CLI keygen-sym -t $kt -s $sz -a $key_algo -u sign,verify $extra" \
                "$keygen_out"
            continue
        fi

        run_mac_test "$desc" "$kid" "$mac_algo" "$INPUT_FILE" \
            "$(_smw_extra "")"
    done < "$tmp_cases"

    rm -f "$tmp_cases"

    section_footer
}

# ---------------------------------------------------------------------------
# SMW-specific: multi-algo permitted algorithms
# ---------------------------------------------------------------------------
test_multi_algo_smw() {
    base_id=8100

    section_header "Multi permitted-algo key tests (SMW) ────────────────────────────────┐"

    extra=$(_smw_extra "")

    # Each test case: desc|type|size|key_algo|mac_algo|id
    tmp_cases=$(mktemp)
    cat > "$tmp_cases" << EOF
AES-256 CBC,CMAC  CMAC|AES|256|CBC,CMAC|CMAC|$((base_id+1))
HMAC-256 SHA256,SHA384  SHA256|HMAC|256|SHA256,SHA384|HMAC-SHA256|$((base_id+2))
EOF

    while IFS='|' read -r desc kt sz key_algo mac_algo kid; do
        [ -z "$desc" ] && continue

        $CLI keygen-sym -t "$kt" -s "$sz" -a "$key_algo" \
            -u sign,verify -i "$kid" $extra 2>/dev/null

        run_mac_test "$desc" "$kid" "$mac_algo" "$INPUT_FILE" "$extra"

        $CLI key-delete -i "$kid" $extra 2>/dev/null
    done < "$tmp_cases"

    rm -f "$tmp_cases"

    section_footer
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
echo "╔══════════════════════════════════════════════════════════════════════════╗"
echo "║       NXP SMW CLI — MAC Test Suite                                       ║"
echo "╚══════════════════════════════════════════════════════════════════════════╝"

if ! command -v "$CLI" >/dev/null 2>&1; then
    echo "ERROR: '$CLI' not found in PATH. Aborting."
    rm -f "$INPUT_FILE"
    exit 1
fi

if [ -n "$SUBSYSTEM" ]; then
    subsystems="$SUBSYSTEM"
else
    subsystems="ELE TEE"
fi

GLOBAL_FAIL=0

for SUBSYSTEM in $subsystems; do
    echo ""
    echo "╔══════════════════════════════════════════════════════════════════════════╗"
    printf "║  Subsystem: %-61s║\n" "$SUBSYSTEM"
    echo "╚══════════════════════════════════════════════════════════════════════════╝"

    reset_counters

    # Use a persistent key for discover_and_test
    DISCOVER_KEY_ID=8200
    $CLI keygen-sym -t AES -s 256 -a CMAC -u sign,verify \
        -i $DISCOVER_KEY_ID -S "$SUBSYSTEM" 2>/dev/null

    discover_and_test "$DISCOVER_KEY_ID" "$INPUT_FILE" "-S $SUBSYSTEM"

    $CLI key-delete -i $DISCOVER_KEY_ID 2>/dev/null

    test_transient_keys_smw
    test_persistent_keys_smw
    test_multi_algo_smw

    print_failure_report
    print_summary

    GLOBAL_FAIL=$(( GLOBAL_FAIL + FAIL ))
done

# Negative cases — subsystem-agnostic, run once
echo ""
echo "╔══════════════════════════════════════════════════════════════════════════╗"
echo "║  CLI Argument Validation (subsystem-independent)                         ║"
echo "╚══════════════════════════════════════════════════════════════════════════╝"

reset_counters
SUBSYSTEM=""
test_negative_cases "$INPUT_FILE"
print_failure_report
print_summary

GLOBAL_FAIL=$(( GLOBAL_FAIL + FAIL ))

# Cleanup
rm -f "$INPUT_FILE"

echo ""
echo "╔══════════════════════════════════════════════════════════════════════════╗"
printf "║  Overall result: %s%54s║\n" \
    "$([ $GLOBAL_FAIL -eq 0 ] && echo "ALL PASSED" || echo "$GLOBAL_FAIL FAILURE(S)")" " "
echo "╚══════════════════════════════════════════════════════════════════════════╝"

[ "$GLOBAL_FAIL" -eq 0 ]
