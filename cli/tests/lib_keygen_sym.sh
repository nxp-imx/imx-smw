#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2026 NXP
#
# Shared library for symmetric key generation test suites.

PASS=0
FAIL=0

FAIL_DESCS=()
FAIL_CMDS=()
FAIL_ERRS=()
FAIL_CODES=()

reset_counters() {
    PASS=0
    FAIL=0
    FAIL_DESCS=()
    FAIL_CMDS=()
    FAIL_ERRS=()
    FAIL_CODES=()
}

key_sizes_for_type() {
    case "$1" in
        AES)       echo "128 192 256" ;;
        DES)       echo "56" ;;
        DES3)      echo "112" ;;
        SM4)       echo "128" ;;
        HMAC)      echo "128 256" ;;
        CHACHA20)  echo "256" ;;
        XCHACHA20) echo "256" ;;
        *)         echo "128" ;;
    esac
}

_extract_error_code() {
    local code
    code=$(echo "$1" | grep -oE 'SMW_STATUS_[A-Z_]+|PSA_ERROR_[A-Z_]+' | head -1)
    echo "${code:-UNKNOWN}"
}

_record_fail() {
    local code
    code=$(_extract_error_code "$3")
    FAIL_DESCS+=("$1")
    FAIL_CMDS+=("$2")
    FAIL_ERRS+=("$3")
    FAIL_CODES+=("$code")
    FAIL=$((FAIL + 1))
}

_print_row() {
    printf "  %-60s " "[$1]"
}

run_keygen_test() {
    local desc="$1" key_type="$2" key_size="$3"
    local algo="$4" usage="$5" extra="${6:-}"
    local cmd="$CLI keygen-sym -t $key_type -s $key_size -a $algo -u $usage $extra"

    _print_row "$desc"

    local out rc
    out=$(eval "$cmd" 2>&1)
    rc=$?

    if [ $rc -eq 0 ]; then
        echo "PASS"
        PASS=$((PASS + 1))
    else
        echo "FAIL"
        _record_fail "$desc" "$cmd" "$out"
    fi
}

run_negative_test() {
    local desc="$1"
    local cmd="$2"

    _print_row "$desc"

    local out rc
    out=$(eval "$cmd" 2>&1)
    rc=$?

    if [ $rc -ne 0 ]; then
        echo "PASS  (correctly rejected)"
        PASS=$((PASS + 1))
    else
        echo "FAIL  (should have been rejected)"
        _record_fail "$desc" "$cmd" "$out"
    fi
}

section_header() { echo ""; echo "┌── $1"; }
section_footer() { echo "└$(printf '─%.0s' {1..75})┘"; }

discover_and_test() {
    echo ""
    echo "Discovering available types/algos via '$CLI keygen-sym --list' ..."

    local list
    list=$($CLI keygen-sym --list 2>/dev/null)

    if [ -z "$list" ]; then
        echo "  ERROR: empty output – is '$CLI' in PATH?"
        return 1
    fi

    # ── Cipher ───────────────────────────────────────────────────────────────
    local cipher_kt cipher_modes
    cipher_kt=$(echo "$list" | awk \
        '/Cipher \(encrypt\/decrypt\)/{f=1} f && /Key types:/{
            sub(/.*Key types: */,""); gsub(/ /,""); print; exit}')
    cipher_modes=$(echo "$list" | awk \
        '/Cipher \(encrypt\/decrypt\)/{f=1} f && /Modes:/{
            sub(/.*Modes: */,""); gsub(/ /,""); print; exit}')

    if [ -n "$cipher_kt" ] && [ -n "$cipher_modes" ]; then
        section_header "Cipher (encrypt/decrypt) ─────────────────────────────────────────────┐"
        IFS=',' read -ra KTS   <<< "$cipher_kt"
        IFS=',' read -ra MODES <<< "$cipher_modes"
        for kt in "${KTS[@]}"; do
            for mode in "${MODES[@]}"; do
                for sz in $(key_sizes_for_type "$kt"); do
                    run_keygen_test \
                        "$kt ${sz}-bit  $mode  encrypt,decrypt  transient" \
                        "$kt" "$sz" "$mode" "encrypt,decrypt" "--transient"
                done
            done
        done
        section_footer
    fi

    # ── AEAD ─────────────────────────────────────────────────────────────────
    local aead_kt aead_modes
    aead_kt=$(echo "$list" | awk \
        '/^AEAD:/{f=1} f && /Key types:/{
            sub(/.*Key types: */,""); gsub(/ /,""); print; exit}')
    aead_modes=$(echo "$list" | awk \
        '/^AEAD:/{f=1} f && /Modes:/{
            sub(/.*Modes: */,""); gsub(/ /,""); print; exit}')

    if [ -n "$aead_kt" ] && [ -n "$aead_modes" ]; then
        section_header "AEAD (encrypt/decrypt) ───────────────────────────────────────────────┐"
        IFS=',' read -ra KTS   <<< "$aead_kt"
        IFS=',' read -ra MODES <<< "$aead_modes"
        for kt in "${KTS[@]}"; do
            for mode in "${MODES[@]}"; do
                for sz in $(key_sizes_for_type "$kt"); do
                    run_keygen_test \
                        "$kt ${sz}-bit  $mode  encrypt,decrypt  transient" \
                        "$kt" "$sz" "$mode" "encrypt,decrypt" "--transient"
                done
            done
        done
        section_footer
    fi

    # ── CMAC ─────────────────────────────────────────────────────────────────
    local cmac_kt cmac_modes
    cmac_kt=$(echo "$list" | awk \
        '/  CMAC:/{f=1} f && /Key types:/{
            sub(/.*Key types: */,""); gsub(/ /,""); print; exit}')
    cmac_modes=$(echo "$list" | awk \
        '/  CMAC:/{f=1} f && /Modes:/{
            sub(/.*Modes: */,""); gsub(/ /,""); print; exit}')

    if [ -n "$cmac_kt" ] && [ -n "$cmac_modes" ]; then
        section_header "CMAC (sign/verify) ───────────────────────────────────────────────────┐"
        IFS=',' read -ra KTS   <<< "$cmac_kt"
        IFS=',' read -ra MODES <<< "$cmac_modes"
        for kt in "${KTS[@]}"; do
            for mode in "${MODES[@]}"; do
                for sz in $(key_sizes_for_type "$kt"); do
                    run_keygen_test \
                        "$kt ${sz}-bit  $mode  sign,verify  transient" \
                        "$kt" "$sz" "$mode" "sign,verify" "--transient"
                done
            done
        done
        section_footer
    fi

    # ── HMAC ─────────────────────────────────────────────────────────────────
    local hmac_hashes
    hmac_hashes=$(echo "$list" | awk \
        '/  HMAC:/{f=1} f && /Hash:/{
            sub(/.*Hash: */,""); gsub(/ /,""); print; exit}')

    if [ -n "$hmac_hashes" ]; then
        section_header "HMAC (sign/verify) ───────────────────────────────────────────────────┐"
        IFS=',' read -ra HASHES <<< "$hmac_hashes"
        for hash in "${HASHES[@]}"; do
            for sz in $(key_sizes_for_type "HMAC"); do
                run_keygen_test \
                    "HMAC ${sz}-bit  $hash  sign,verify  transient" \
                    "HMAC" "$sz" "$hash" "sign,verify" "--transient"
            done
        done
        section_footer
    fi
}

test_negative_cases() {
    section_header "Negative / error case tests ──────────────────────────────────────────┐"

    run_negative_test \
        "missing --type  → must be rejected" \
        "$CLI keygen-sym -s 256 -a CBC -u encrypt,decrypt --transient"

    run_negative_test \
        "invalid key type  → must be rejected" \
        "$CLI keygen-sym -t INVALID_TYPE -s 256 -a CBC -u encrypt,decrypt --transient"

    run_negative_test \
        "invalid algo  → must be rejected" \
        "$CLI keygen-sym -t AES -s 256 -a INVALID_MODE -u encrypt,decrypt --transient"

    run_negative_test \
        "missing --size  → must be rejected" \
        "$CLI keygen-sym -t AES -a CBC -u encrypt,decrypt --transient"

    run_negative_test \
        "missing --algo  → must be rejected" \
        "$CLI keygen-sym -t AES -s 256 -u encrypt,decrypt --transient"

    run_negative_test \
        "missing --usage  → must be rejected" \
        "$CLI keygen-sym -t AES -s 256 -a CBC --transient"

    run_negative_test \
        "persistent key without --id  → must be rejected" \
        "$CLI keygen-sym -t AES -s 256 -a CBC -u encrypt,decrypt"

    run_negative_test \
        "transient key with --id  → must be rejected" \
        "$CLI keygen-sym -t AES -s 256 -a CBC -u encrypt,decrypt --transient -i 9999"

    run_negative_test \
        "key id = 0  → must be rejected" \
        "$CLI keygen-sym -t AES -s 256 -a CBC -u encrypt,decrypt -i 0"

    section_footer
}

# ─── generic grouped report ──────────────────────────────────────────────────
_print_grouped_report() {
    local title="$1"
    local -n _descs="$2"
    local -n _cmds="$3"
    local -n _errs="$4"
    local -n _codes="$5"
    local show_commands="$6"   # "yes" → print full commands/output per item

    echo ""
    echo "╔══════════════════════════════════════════════════════════════════════════╗"
    printf "║  %-72s║\n" "  $title"
    echo "╚══════════════════════════════════════════════════════════════════════════╝"

    # ── grouped summary table ────────────────────────────────────────────────
    echo ""
    printf "  %-52s  %6s\n" "Error Code" "Count"
    printf "  %-52s  %6s\n" "$(printf '─%.0s' {1..52})" "$(printf '─%.0s' {1..6})"

    declare -A _cnt
    declare -A _ex

    local i
    for i in "${!_codes[@]}"; do
        local code="${_codes[$i]}"
        _cnt["$code"]=$(( ${_cnt["$code"]:-0} + 1 ))
    done

    # sort by count descending
    local sorted_codes
    sorted_codes=$(for k in "${!_cnt[@]}"; do
                       echo "${_cnt[$k]} $k"
                   done | sort -rn | awk '{print $2}')

    local total=0
    for code in $sorted_codes; do
        printf "  %-52s  %6d\n" "$code" "${_cnt[$code]}"
        echo ""
        total=$(( total + _cnt[$code] ))
    done

    printf "  %-52s  %6s\n" "$(printf '─%.0s' {1..52})" "$(printf '─%.0s' {1..6})"
    printf "  %-52s  %6d\n" "TOTAL" "${#_codes[@]}"

    # ── detailed list (only for FAIL) ────────────────────────────────────────
    if [ "$show_commands" = "yes" ] && [ ${#_cmds[@]} -gt 0 ]; then
        echo ""
        echo "  Detailed list:"
        echo "  $(printf '─%.0s' {1..72})"
        for i in "${!_cmds[@]}"; do
            printf "\n  [%d] %s\n" "$((i + 1))" "${_descs[$i]}"
            printf "      Code    : %s\n" "${_codes[$i]}"
            printf "      Command : %s\n" "${_cmds[$i]}"
            echo   "      Output  :"
            echo "${_errs[$i]}" | sed 's/^/               /'
        done
    fi
}

print_failure_report() {
    if [ ${#FAIL_CODES[@]} -gt 0 ]; then
        _print_grouped_report \
            "FAILURE REPORT" \
            FAIL_DESCS FAIL_CMDS FAIL_ERRS FAIL_CODES \
            "yes"
    fi
}

print_summary() {
    echo ""
    echo "╔══════════════════════════════════════════════════════════════════════════╗"
    printf "║  Results:            %4d PASS  │  %4d FAIL     %23s║\n" \
        "$PASS" "$FAIL" " "
    echo "╚══════════════════════════════════════════════════════════════════════════╝"
}