#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2026 NXP
#
# Symmetric key generation test suite - SMW backend (nxp_smw)
#
# Usage:
#   ./smw_keygen_sym.sh [--subsystem ELE|TEE|SECO]
#
# Requires: nxp_smw in PATH

CLI="nxp_smw"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SUBSYSTEM=""

# Parse optional --subsystem argument
while [ $# -gt 0 ]; do
    case "$1" in
        --subsystem|-S)
            SUBSYSTEM="$2"; shift 2 ;;
        *)
            echo "Unknown argument: $1"; exit 1 ;;
    esac
done

. "$SCRIPT_DIR/lib_keygen_sym.sh"

# SMW extra flags: subsystem
_smw_extra() {
    flags="${1:-}"
    [ -n "$SUBSYSTEM" ] && flags="$flags -S $SUBSYSTEM"
    echo "$flags"
}

# ---------------------------------------------------------------------------
# SMW-specific: sensitive vs non-sensitive transient tests
# ---------------------------------------------------------------------------
test_sensitive_flags() {
    section_header "Sensitive / non-sensitive flag tests (SMW) ──────────────────────────┐"

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
# SMW-specific: multi-algo permitted algorithms
# ---------------------------------------------------------------------------
test_multi_algo() {
    section_header "Multi permitted-algo tests (SMW only) ───────────────────────────────┐"

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
    base_id=7000

    section_header "Persistent key tests (SMW) ───────────────────────────────────────────┐"

    extra_base=$(_smw_extra "")

    tmp_cases=$(mktemp)
    cat > "$tmp_cases" << EOF
AES-256 CBC  encrypt,decrypt  persist|AES|256|CBC|encrypt,decrypt|$((base_id+1))
AES-128 GCM  encrypt,decrypt  persist|AES|128|GCM|encrypt,decrypt|$((base_id+2))
HMAC-256 SHA256  sign,verify  persist|HMAC|256|SHA256|sign,verify|$((base_id+3))
AES-256 CBC,CTR  multi-algo  persist|AES|256|CBC,CTR|encrypt,decrypt|$((base_id+4))
EOF

    while IFS='|' read -r desc kt sz algo usage kid; do
        [ -z "$desc" ] && continue
        # Delete any leftover key before testing (subsystem-aware)
        $CLI key-delete -i "$kid" $extra_base 2>/dev/null
        run_keygen_test "$desc" "$kt" "$sz" "$algo" "$usage" "-i $kid $extra_base"
        # Cleanup after test (subsystem-aware)
        $CLI key-delete -i "$kid" $extra_base 2>/dev/null
    done < "$tmp_cases"

    rm -f "$tmp_cases"

    section_footer
}

# ---------------------------------------------------------------------------
# discover_and_test with subsystem injection
# ---------------------------------------------------------------------------
discover_and_test() {
    echo ""
    echo "Discovering available types/algos via '$CLI keygen-sym --list' ..."

    list=$($CLI keygen-sym --list 2>/dev/null)

    if [ -z "$list" ]; then
        echo "  ERROR: empty output – is '$CLI' in PATH?"
        return 1
    fi

    OLDIFS="$IFS"

    # ── Cipher (Symmetric Encryption) ────────────────────────────────────────
    cipher_kt=$(echo "$list" | awk \
        '/Keys supporting Symmetric Encryption/{f=1} f && /Key types:/{
            sub(/.*Key types: */,""); gsub(/ /,""); print; exit}')
    cipher_modes=$(echo "$list" | awk \
        '/Keys supporting Symmetric Encryption/{f=1} f && /Modes:/{
            sub(/.*Modes: */,""); gsub(/ /,""); print; exit}')

    if [ -n "$cipher_kt" ] && [ -n "$cipher_modes" ]; then
        section_header "Cipher (encrypt/decrypt) ─────────────────────────────────────────────┐"
        IFS=','
        for kt in $cipher_kt; do
            for mode in $cipher_modes; do
                IFS="$OLDIFS"
                for sz in $(key_sizes_for_type "$kt"); do
                    extra=$(_smw_extra "--transient")
                    run_keygen_test \
                        "$kt ${sz}-bit  $mode  encrypt,decrypt  transient" \
                        "$kt" "$sz" "$mode" "encrypt,decrypt" "$extra"
                done
                IFS=','
            done
        done
        IFS="$OLDIFS"
        section_footer
    fi

    # ── AEAD ─────────────────────────────────────────────────────────────────
    aead_kt=$(echo "$list" | awk \
        '/Keys supporting AEAD/{f=1} f && /Key types:/{
            sub(/.*Key types: */,""); gsub(/ /,""); print; exit}')
    aead_modes=$(echo "$list" | awk \
        '/Keys supporting AEAD/{f=1} f && /Modes:/{
            sub(/.*Modes: */,""); gsub(/ /,""); print; exit}')

    if [ -n "$aead_kt" ] && [ -n "$aead_modes" ]; then
        section_header "AEAD (encrypt/decrypt) ───────────────────────────────────────────────┐"
        IFS=','
        for kt in $aead_kt; do
            for mode in $aead_modes; do
                IFS="$OLDIFS"
                for sz in $(key_sizes_for_type "$kt"); do
                    extra=$(_smw_extra "--transient")
                    run_keygen_test \
                        "$kt ${sz}-bit  $mode  encrypt,decrypt  transient" \
                        "$kt" "$sz" "$mode" "encrypt,decrypt" "$extra"
                done
                IFS=','
            done
        done
        IFS="$OLDIFS"
        section_footer
    fi

    # ── CMAC ─────────────────────────────────────────────────────────────────
    cmac_kt=$(echo "$list" | awk \
        '/CMAC:/{f=1} f && /Key types:/{
            sub(/.*Key types: */,""); gsub(/ /,""); print; exit}')
    cmac_modes=$(echo "$list" | awk \
        '/CMAC:/{f=1} f && /Modes:/{
            sub(/.*Modes: */,""); gsub(/ /,""); print; exit}')

    if [ -n "$cmac_kt" ] && [ -n "$cmac_modes" ]; then
        section_header "CMAC (sign/verify) ───────────────────────────────────────────────────┐"
        IFS=','
        for kt in $cmac_kt; do
            for mode in $cmac_modes; do
                IFS="$OLDIFS"
                for sz in $(key_sizes_for_type "$kt"); do
                    extra=$(_smw_extra "--transient")
                    run_keygen_test \
                        "$kt ${sz}-bit  $mode  sign,verify  transient" \
                        "$kt" "$sz" "$mode" "sign,verify" "$extra"
                done
                IFS=','
            done
        done
        IFS="$OLDIFS"
        section_footer
    fi

    # ── HMAC ─────────────────────────────────────────────────────────────────
    hmac_hashes=$(echo "$list" | awk \
        '/HMAC:/{f=1} f && /Hash:/{
            sub(/.*Hash: */,""); gsub(/ /,""); print; exit}')

    if [ -n "$hmac_hashes" ]; then
        section_header "HMAC (sign/verify) ───────────────────────────────────────────────────┐"
        IFS=','
        for hash in $hmac_hashes; do
            IFS="$OLDIFS"
            for sz in $(key_sizes_for_type "HMAC"); do
                extra=$(_smw_extra "--transient")
                run_keygen_test \
                    "HMAC ${sz}-bit  $hash  sign,verify  transient" \
                    "HMAC" "$sz" "$hash" "sign,verify" "$extra"
            done
            IFS=','
        done
        IFS="$OLDIFS"
        section_footer
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
echo "╔══════════════════════════════════════════════════════════════════════════╗"
echo "║       NXP SMW CLI — Symmetric Key Generation Test Suite                  ║"
echo "╚══════════════════════════════════════════════════════════════════════════╝"

if ! command -v "$CLI" >/dev/null 2>&1; then
    echo "ERROR: '$CLI' not found in PATH. Aborting."
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

    discover_and_test
    test_sensitive_flags
    test_multi_algo
    test_persistent_keys_smw

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
test_negative_cases
print_failure_report
print_summary

GLOBAL_FAIL=$(( GLOBAL_FAIL + FAIL ))

echo ""
echo "╔══════════════════════════════════════════════════════════════════════════╗"
printf "║  Overall result: %s%43s║\n" \
    "$([ $GLOBAL_FAIL -eq 0 ] && echo "ALL PASSED" || echo "$GLOBAL_FAIL FAILURE(S)")" " "
echo "╚══════════════════════════════════════════════════════════════════════════╝"

[ "$GLOBAL_FAIL" -eq 0 ]
