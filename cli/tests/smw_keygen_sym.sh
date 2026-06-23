#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2026 NXP
#
# Symmetric key generation test suite - SMW backend (nxp_smw)
#
# Usage:
#   ./test_keygen_sym_smw.sh [--subsystem ELE|TEE|SECO]
#
# Requires: nxp_smw in PATH

set -o pipefail

CLI="nxp_smw"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SUBSYSTEM=""

# Parse optional --subsystem argument
while [[ $# -gt 0 ]]; do
    case "$1" in
        --subsystem|-S)
            SUBSYSTEM="$2"; shift 2 ;;
        *)
            echo "Unknown argument: $1"; exit 1 ;;
    esac
done

source "$SCRIPT_DIR/lib_keygen_sym.sh"

# SMW extra flags: subsystem + non-sensitive variants
_smw_extra() {
    local flags="${1:-}"
    [ -n "$SUBSYSTEM" ] && flags="$flags -S $SUBSYSTEM"
    echo "$flags"
}

# ---------------------------------------------------------------------------
# SMW-specific: sensitive vs non-sensitive transient tests
# ---------------------------------------------------------------------------
test_sensitive_flags() {
    section_header "Sensitive / non-sensitive flag tests (SMW) ──────────────────────────┐"

    local extra_s
    extra_s=$(_smw_extra "--transient")

    run_keygen_test \
        "AES-256 CBC  encrypt,decrypt  transient  sensitive" \
        "AES" 256 "CBC" "encrypt,decrypt" "$extra_s"

    run_keygen_test \
        "AES-256 CBC  encrypt,decrypt  transient  non-sensitive" \
        "AES" 256 "CBC" "encrypt,decrypt" "$extra_s --non-sensitive"

    run_keygen_test \
        "HMAC-256 SHA256  sign,verify  transient  sensitive" \
        "HMAC" 256 "SHA256" "sign,verify" "$extra_s"

    run_keygen_test \
        "HMAC-256 SHA256  sign,verify  transient  non-sensitive" \
        "HMAC" 256 "SHA256" "sign,verify" "$extra_s --non-sensitive"

    section_footer
}

# ---------------------------------------------------------------------------
# SMW-specific: multi-algo permitted algorithms (SMW supports comma-separated)
# ---------------------------------------------------------------------------
test_multi_algo() {
    section_header "Multi permitted-algo tests (SMW only) ───────────────────────────────┐"

    local extra
    extra=$(_smw_extra "--transient")

    run_keygen_test \
        "AES-256  CBC,CTR  encrypt,decrypt  transient" \
        "AES" 256 "CBC,CTR" "encrypt,decrypt" "$extra"

    run_keygen_test \
        "AES-256  CBC,GCM  encrypt,decrypt  transient" \
        "AES" 256 "CBC,GCM" "encrypt,decrypt" "$extra"

    run_keygen_test \
        "HMAC-256  SHA256,SHA384  sign,verify  transient" \
        "HMAC" 256 "SHA256,SHA384" "sign,verify" "$extra"

    section_footer
}

# ---------------------------------------------------------------------------
# SMW-specific: persistent key tests
# ---------------------------------------------------------------------------
test_persistent_keys_smw() {
    local base_id=7000

    section_header "Persistent key tests (SMW) ───────────────────────────────────────────┐"

    local extra_base
    extra_base=$(_smw_extra "")

    local cases=(
        # desc                                    type  size  algo        usage           id
        "AES-256 CBC  encrypt,decrypt  persist"   "AES"  256  "CBC"       "encrypt,decrypt" $((base_id+1))
        "AES-128 GCM  encrypt,decrypt  persist"   "AES"  128  "GCM"       "encrypt,decrypt" $((base_id+2))
        "HMAC-256 SHA256  sign,verify  persist"   "HMAC" 256  "SHA256"    "sign,verify"     $((base_id+3))
        "AES-256 CBC,CTR  multi-algo  persist"    "AES"  256  "CBC,CTR"   "encrypt,decrypt" $((base_id+4))
    )

    local i=0
    while [ $i -lt ${#cases[@]} ]; do
        local desc="${cases[$i]}"
        local kt="${cases[$((i+1))]}"
        local sz="${cases[$((i+2))]}"
        local algo="${cases[$((i+3))]}"
        local usage="${cases[$((i+4))]}"
        local kid="${cases[$((i+5))]}"

        run_keygen_test "$desc" "$kt" "$sz" "$algo" "$usage" "-i $kid $extra_base"

        $CLI key-delete -i "$kid" 2>/dev/null

        i=$((i+6))
    done

    section_footer
}

# ---------------------------------------------------------------------------
# Override discover_and_test to inject subsystem flag
# ---------------------------------------------------------------------------
_orig_discover_and_test=$(declare -f discover_and_test)

discover_and_test() {
    # Temporarily wrap run_keygen_test to inject subsystem
    local _saved
    _saved=$(declare -f run_keygen_test)

    run_keygen_test() {
        local desc="$1" key_type="$2" key_size="$3"
        local algo="$4" usage="$5" extra="${6:-}"
        [ -n "$SUBSYSTEM" ] && extra="$extra -S $SUBSYSTEM"
        # Call the original via the lib variable
        local cmd="$CLI keygen-sym -t $key_type -s $key_size -a $algo -u $usage $extra"
        _print_row "$desc"
        local out rc
        out=$(eval "$cmd" 2>&1); rc=$?
        if [ $rc -eq 0 ]; then
            echo "PASS"; PASS=$((PASS + 1))
        else
            echo "FAIL"; _record_fail "$desc" "$cmd" "$out"
        fi
    }

    # Call the library implementation
    eval "$_orig_discover_and_test"
    discover_and_test

    # Restore original
    eval "$_saved"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
echo "╔══════════════════════════════════════════════════════════════════════════╗"
echo "║       NXP SMW CLI — Symmetric Key Generation Test Suite                  ║"
echo "╚══════════════════════════════════════════════════════════════════════════╝"

if ! command -v "$CLI" &>/dev/null; then
    echo "ERROR: '$CLI' not found in PATH. Aborting."
    exit 1
fi

# If --subsystem was given test only that one, otherwise test all
if [ -n "$SUBSYSTEM" ]; then
    SUBSYSTEMS=("$SUBSYSTEM")
else
    SUBSYSTEMS=("ELE" "TEE")
fi

GLOBAL_FAIL=0

for SUBSYSTEM in "${SUBSYSTEMS[@]}"; do
    echo ""
    echo "╔══════════════════════════════════════════════════════════════════════════╗"
    printf "║  Subsystem: %-61s║\n" "$SUBSYSTEM"
    echo "╚══════════════════════════════════════════════════════════════════════════╝"

    reset_counters

    discover_and_test
    test_sensitive_flags
    test_multi_algo
    test_persistent_keys_smw

    print_failure_report
    print_summary

    GLOBAL_FAIL=$(( GLOBAL_FAIL + FAIL ))
done

# Negative cases are subsystem-agnostic — run once at the end
echo ""
echo "╔══════════════════════════════════════════════════════════════════════════╗"
echo "║  CLI Argument Validation (subsystem-independent)                         ║"
echo "╚══════════════════════════════════════════════════════════════════════════╝"

reset_counters
SUBSYSTEM=""
test_negative_cases
print_failure_report
print_summary

GLOBAL_FAIL=$(( GLOBAL_FAIL + FAIL ))

echo ""
echo "╔══════════════════════════════════════════════════════════════════════════╗"
printf "║  Overall result: %s%54s║\n" \
    "$([ $GLOBAL_FAIL -eq 0 ] && echo "ALL PASSED" || echo "$GLOBAL_FAIL FAILURE(S)")" " "
echo "╚══════════════════════════════════════════════════════════════════════════╝"

[ "$GLOBAL_FAIL" -eq 0 ]
