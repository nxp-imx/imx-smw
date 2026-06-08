#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2026 NXP
#
# Shared library for asymmetric encryption test suites (encrypt + decrypt).

PASS=0
FAIL=0
FAIL_COUNT=0

reset_counters() {
    PASS=0
    FAIL=0
    FAIL_COUNT=0
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

# ---------------------------------------------------------------------------
# _keygen_asym: generate an asymmetric key pair and return its ID
#
# $1: key type (RSA)
# $2: key size in bits (2048, 3072, 4096)
# $3: permitted algorithm (e.g. OAEP-SHA256, PKCS1V15-CRYPT)
# $4: key ID (optional, if empty a transient key is generated)
# $5: extra flags (e.g. -S ELE)
#
# Prints the key ID on stdout, returns 0 on success, 1 on error.
# ---------------------------------------------------------------------------
_keygen_asym() {
    kt="$1"
    sz="$2"
    key_algo="$3"
    kid="$4"
    extra="${5:-}"
    local_cmd=""
    local_out=""

    if [ -n "$kid" ]; then
        local_cmd="$CLI keygen-asym -t $kt -s $sz -a $key_algo \
            -u encrypt,decrypt -i $kid $extra"
    else
        local_cmd="$CLI keygen-asym -t $kt -s $sz -a $key_algo \
            -u encrypt,decrypt $extra"
    fi

    local_out=$(eval "$local_cmd" 2>&1)
    if [ $? -ne 0 ]; then
        echo ""
        return 1
    fi

    if [ -n "$kid" ]; then
        echo "$kid"
    else
        echo "$local_out" | grep -oE 'ID: 0x[0-9a-fA-F]+' | \
            head -1 | grep -oE '0x[0-9a-fA-F]+'
    fi
}

# ---------------------------------------------------------------------------
# _key_delete: delete a key by ID (best effort, ignore errors)
#
# $1: key ID
# $2: extra flags
# ---------------------------------------------------------------------------
_key_delete() {
    kid="$1"
    extra="${2:-}"
    $CLI key-delete -i "$kid" $extra 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# _prepare_input: create a random input file of given size
#
# $1: output file path
# $2: size in bytes
# ---------------------------------------------------------------------------
_prepare_input() {
    out_file="$1"
    size="$2"
    dd if=/dev/urandom of="$out_file" bs="$size" count=1 2>/dev/null
}

# ---------------------------------------------------------------------------
# run_asym_enc_test: encrypt then decrypt and verify round-trip
#
# $1: description
# $2: key ID
# $3: encryption algorithm (e.g. RSA-OAEP-SHA256, RSA-PKCS1V15)
# $4: salt (hex string, may be empty)
# $5: input size in bytes
# $6: base input file (used as source, a sized copy is made per test)
# $7: extra flags (e.g. -S ELE)
# ---------------------------------------------------------------------------
run_asym_enc_test() {
    desc="$1"
    kid="$2"
    enc_algo="$3"
    salt="$4"
    input_size="$5"
    base_input="$6"
    extra="${7:-}"

    plain_file=$(mktemp /tmp/asym_enc_plain_XXXXXX.bin)
    enc_file=$(mktemp /tmp/asym_enc_cipher_XXXXXX.bin)
    dec_file=$(mktemp /tmp/asym_enc_dec_XXXXXX.bin)

    # Prepare sized input
    _prepare_input "$plain_file" "$input_size"

    # Step 1: encrypt
    if [ -n "$salt" ]; then
        encrypt_cmd="$CLI encrypt -a $enc_algo -k $kid --salt $salt \
            -i $plain_file -o $enc_file $extra"
    else
        encrypt_cmd="$CLI encrypt -a $enc_algo -k $kid \
            -i $plain_file -o $enc_file $extra"
    fi

    _print_row "$desc (encrypt)"

    out=$(eval "$encrypt_cmd" 2>&1)
    rc=$?

    if [ $rc -ne 0 ]; then
        echo "FAIL"
        _record_fail "$desc (encrypt)" "$encrypt_cmd" "$out"
        rm -f "$plain_file" "$enc_file" "$dec_file"
        return
    fi
    echo "PASS"
    PASS=$((PASS + 1))

    # Step 2: decrypt
    if [ -n "$salt" ]; then
        decrypt_cmd="$CLI decrypt -a $enc_algo -k $kid --salt $salt \
            -i $enc_file -o $dec_file $extra"
    else
        decrypt_cmd="$CLI decrypt -a $enc_algo -k $kid \
            -i $enc_file -o $dec_file $extra"
    fi

    _print_row "$desc (decrypt)"

    out=$(eval "$decrypt_cmd" 2>&1)
    rc=$?

    if [ $rc -ne 0 ]; then
        echo "FAIL"
        _record_fail "$desc (decrypt)" "$decrypt_cmd" "$out"
        rm -f "$plain_file" "$enc_file" "$dec_file"
        return
    fi
    echo "PASS"
    PASS=$((PASS + 1))

    # Step 3: verify round-trip
    _print_row "$desc (round-trip)"

    if diff "$plain_file" "$dec_file" > /dev/null 2>&1; then
        echo "PASS"
        PASS=$((PASS + 1))
    else
        echo "FAIL"
        _record_fail "$desc (round-trip)" \
            "diff $plain_file $dec_file" \
            "decrypted output does not match original plaintext"
    fi

    rm -f "$plain_file" "$enc_file" "$dec_file"
}

# ---------------------------------------------------------------------------
# run_negative_test: expect failure
#
# $1: description
# $2: command string
# ---------------------------------------------------------------------------
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

# ---------------------------------------------------------------------------
# test_negative_cases: CLI argument validation (backend-agnostic)
#
# $1: input file
# ---------------------------------------------------------------------------
test_negative_cases() {
    input_file="$1"

    section_header "Negative / error case tests ──────────────────────────────────────────┐"

    run_negative_test \
        "missing --key-id  → must be rejected" \
        "$CLI encrypt -a RSA-OAEP-SHA256 -i $input_file"

    run_negative_test \
        "missing --algo  → must be rejected" \
        "$CLI encrypt -k 1 -i $input_file"

    run_negative_test \
        "missing --input  → must be rejected" \
        "$CLI encrypt -k 1 -a RSA-OAEP-SHA256"

    run_negative_test \
        "missing --output  → must be rejected" \
        "$CLI encrypt -k 1 -a RSA-OAEP-SHA256 -i $input_file"

    run_negative_test \
        "invalid algo  → must be rejected" \
        "$CLI encrypt -k 1 -a INVALID_ALGO -i $input_file -o /dev/null"

    run_negative_test \
        "decrypt missing --key-id  → must be rejected" \
        "$CLI decrypt -a RSA-OAEP-SHA256 -i $input_file -o /dev/null"

    run_negative_test \
        "decrypt missing --algo  → must be rejected" \
        "$CLI decrypt -k 1 -i $input_file -o /dev/null"

    run_negative_test \
        "decrypt missing --input  → must be rejected" \
        "$CLI decrypt -k 1 -a RSA-OAEP-SHA256 -o /dev/null"

    run_negative_test \
        "decrypt missing --output  → must be rejected" \
        "$CLI decrypt -k 1 -a RSA-OAEP-SHA256 -i $input_file"

    run_negative_test \
        "decrypt invalid algo  → must be rejected" \
        "$CLI decrypt -k 1 -a INVALID_ALGO -i $input_file -o /dev/null"

    section_footer
}

# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
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
