#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2026 NXP
#
# Shared library for symmetric key generation test suites.

PASS=0
FAIL=0
FAIL_COUNT=0

reset_counters() {
    PASS=0
    FAIL=0
    FAIL_COUNT=0
}

key_sizes_for_type() {
    case "$1" in
        AES)       echo "128 192 256" ;;
        DES)       echo "56" ;;
        DES3)      echo "112" ;;
        SM4)       echo "128" ;;
        HMAC)      echo "128 256" ;;
        *)         echo "128" ;;
    esac
}

_extract_error_code() {
    code=$(echo "$1" | grep -oE 'SMW_STATUS_[A-Z_]+|PSA_ERROR_[A-Z_]+' | head -1)
    echo "${code:-UNKNOWN}"
}

_record_fail() {
    code=$(_extract_error_code "$3")
    idx=$FAIL_COUNT

    eval "FAIL_DESC_${idx}=\"\$1\""
    eval "FAIL_CMD_${idx}=\"\$2\""
    eval "FAIL_ERR_${idx}=\"\$3\""
    eval "FAIL_CODE_${idx}=\"\$code\""

    FAIL_COUNT=$((FAIL_COUNT + 1))
    FAIL=$((FAIL + 1))
}

_print_row() {
    printf "  %-60s " "[$1]"
}

run_keygen_test() {
    desc="$1"
    key_type="$2"
    key_size="$3"
    algo="$4"
    usage="$5"
    extra="${6:-}"
    cmd="$CLI keygen-sym -t $key_type -s $key_size -a $algo -u $usage $extra"

    _print_row "$desc"

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
    desc="$1"
    cmd="$2"

    _print_row "$desc"

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
section_footer() { echo "└─────────────────────────────────────────────────────────────────────────┘"; }

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
                    run_keygen_test \
                        "$kt ${sz}-bit  $mode  encrypt,decrypt  transient" \
                        "$kt" "$sz" "$mode" "encrypt,decrypt" "--transient"
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
                    run_keygen_test \
                        "$kt ${sz}-bit  $mode  encrypt,decrypt  transient" \
                        "$kt" "$sz" "$mode" "encrypt,decrypt" "--transient"
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
                    run_keygen_test \
                        "$kt ${sz}-bit  $mode  sign,verify  transient" \
                        "$kt" "$sz" "$mode" "sign,verify" "--transient"
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
                run_keygen_test \
                    "HMAC ${sz}-bit  $hash  sign,verify  transient" \
                    "HMAC" "$sz" "$hash" "sign,verify" "--transient"
            done
            IFS=','
        done
        IFS="$OLDIFS"
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

# ─── report ──────────────────────────────────────────────────────────────────
_sep_line() {
    i=0; out=""
    while [ $i -lt $1 ]; do out="${out}─"; i=$((i+1)); done
    echo "$out"
}

_print_grouped_report() {
    title="$1"
    show_commands="$2"

    echo ""
    echo "╔══════════════════════════════════════════════════════════════════════════╗"
    printf "║  %-72s║\n" "  $title"
    echo "╚══════════════════════════════════════════════════════════════════════════╝"

    echo ""
    printf "  %-52s  %6s\n" "Error Code" "Count"
    printf "  %-52s  %6s\n" "$(_sep_line 52)" "$(_sep_line 6)"

    tmp_codes=$(mktemp)
    i=0
    while [ $i -lt $FAIL_COUNT ]; do
        eval "printf '%s\n' \"\$FAIL_CODE_${i}\"" >> "$tmp_codes"
        i=$((i + 1))
    done

    sorted_codes=$(sort "$tmp_codes" | uniq -c | sort -rn | awk '{print $2}')
    rm -f "$tmp_codes"

    for code in $sorted_codes; do
        cnt=0
        i=0
        while [ $i -lt $FAIL_COUNT ]; do
            eval "v=\"\$FAIL_CODE_${i}\""
            [ "$v" = "$code" ] && cnt=$((cnt + 1))
            i=$((i + 1))
        done
        printf "  %-52s  %6d\n" "$code" "$cnt"
    done

    printf "  %-52s  %6s\n" "$(_sep_line 52)" "$(_sep_line 6)"
    printf "  %-52s  %6d\n" "TOTAL" "$FAIL_COUNT"

    if [ "$show_commands" = "yes" ] && [ "$FAIL_COUNT" -gt 0 ]; then
        echo ""
        echo "  Detailed list:"
        printf "  %s\n" "$(_sep_line 72)"
        i=0
        while [ $i -lt $FAIL_COUNT ]; do
            eval "desc_i=\"\$FAIL_DESC_${i}\""
            eval "cmd_i=\"\$FAIL_CMD_${i}\""
            eval "err_i=\"\$FAIL_ERR_${i}\""
            eval "code_i=\"\$FAIL_CODE_${i}\""
            printf "\n  [%d] %s\n"        "$((i + 1))" "$desc_i"
            printf "      Code    : %s\n" "$code_i"
            printf "      Command : %s\n" "$cmd_i"
            printf "      Output  :\n"
            echo "$err_i" | sed 's/^/               /'
            i=$((i + 1))
        done
    fi
}

print_failure_report() {
    if [ "$FAIL_COUNT" -gt 0 ]; then
        _print_grouped_report "FAILURE REPORT" "yes"
    fi
}

print_summary() {
    echo ""
    echo "╔══════════════════════════════════════════════════════════════════════════╗"
    printf "║  Results:            %4d PASS  │  %4d FAIL     %23s║\n" \
        "$PASS" "$FAIL" " "
    echo "╚══════════════════════════════════════════════════════════════════════════╝"
}
