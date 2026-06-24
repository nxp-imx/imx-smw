#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2026 NXP
#
# Shared library for MAC test suites (compute + verify).

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
# _keygen: generate a symmetric key and return its ID
#
# $1: key type (AES, HMAC)
# $2: key size in bits
# $3: permitted algorithm (e.g. CMAC, SHA256)
# $4: key ID (optional, if empty a transient key is generated)
# $5: extra flags (e.g. -S ELE)
#
# Prints the key ID on stdout, returns 0 on success, 1 on error.
# ---------------------------------------------------------------------------
_keygen() {
    kt="$1"
    sz="$2"
    key_algo="$3"
    kid="$4"
    extra="${5:-}"
    local_cmd=""
    local_out=""

    if [ -n "$kid" ]; then
        local_cmd="$CLI keygen-sym -t $kt -s $sz -a $key_algo \
            -u sign,verify -i $kid $extra"
    else
        local_cmd="$CLI keygen-sym -t $kt -s $sz -a $key_algo \
            -u sign,verify $extra"
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
# _mac_algo_to_key_params: return key type and algo needed for a MAC algorithm
#
# $1: MAC algorithm string (e.g. "CMAC", "HMAC-SHA256", "CBC-MAC")
#
# Prints: "<key_type> <key_algo>"
# e.g.:   "AES CMAC"
#         "HMAC SHA256"
#         "AES CBC-MAC"
# ---------------------------------------------------------------------------
_mac_algo_to_key_params() {
    mac_algo="$1"

    case "$mac_algo" in
        CMAC|CMAC_TRUNCATED)
            echo "AES CMAC" ;;
        CBC-MAC|CBC-MAC_TRUNCATED)
            echo "AES CBC-MAC" ;;
        HMAC-MD5|HMAC_TRUNCATED-MD5)
            echo "HMAC MD5" ;;
        HMAC-SHA1|HMAC_TRUNCATED-SHA1)
            echo "HMAC SHA1" ;;
        HMAC-SHA224|HMAC_TRUNCATED-SHA224)
            echo "HMAC SHA224" ;;
        HMAC-SHA256|HMAC_TRUNCATED-SHA256)
            echo "HMAC SHA256" ;;
        HMAC-SHA384|HMAC_TRUNCATED-SHA384)
            echo "HMAC SHA384" ;;
        HMAC-SHA512|HMAC_TRUNCATED-SHA512)
            echo "HMAC SHA512" ;;
        HMAC-SM3|HMAC_TRUNCATED-SM3)
            echo "HMAC SM3" ;;
        *)
            echo ""
            return 1 ;;
    esac
}

# ---------------------------------------------------------------------------
# run_mac_test: compute MAC then verify MAC using an existing key
#
# $1: description
# $2: key ID
# $3: MAC algorithm (e.g. CMAC, HMAC-SHA256)
# $4: input file
# $5: extra flags (e.g. -S ELE)
# ---------------------------------------------------------------------------
run_mac_test() {
    desc="$1"
    kid="$2"
    mac_algo="$3"
    input="$4"
    extra="${5:-}"

    mac_file=$(mktemp /tmp/mac_test_XXXXXX.bin)

    # Step 1: compute MAC
    compute_cmd="$CLI mac -k $kid -a $mac_algo -i $input -m $mac_file $extra"
    _print_row "$desc (compute)"

    out=$(eval "$compute_cmd" 2>&1)
    rc=$?

    if [ $rc -ne 0 ]; then
        echo "FAIL"
        _record_fail "$desc (compute)" "$compute_cmd" "$out"
        rm -f "$mac_file"
        return
    fi
    echo "PASS"
    PASS=$((PASS + 1))

    # Step 2: verify MAC
    verify_cmd="$CLI mac-verify -k $kid -a $mac_algo -i $input -m $mac_file $extra"
    _print_row "$desc (verify)"

    out=$(eval "$verify_cmd" 2>&1)
    rc=$?

    if [ $rc -eq 0 ]; then
        echo "PASS"
        PASS=$((PASS + 1))
    else
        echo "FAIL"
        _record_fail "$desc (verify)" "$verify_cmd" "$out"
    fi

    rm -f "$mac_file"
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
# prepare_input_file: create a test input file if it does not exist
#
# $1: path to input file
# ---------------------------------------------------------------------------
prepare_input_file() {
    input_file="$1"

    if [ ! -f "$input_file" ]; then
        dd if=/dev/urandom of="$input_file" bs=64 count=1 2>/dev/null
    fi
}

# ---------------------------------------------------------------------------
# discover_and_test: run compute+verify for all supported algos
#
# Uses a pre-generated key ID passed as argument.
# Uses $CLI mac --list to discover supported algorithms.
#
# $1: key ID to use for testing
# $2: input file
# $3: extra flags (e.g. -S ELE)
# ---------------------------------------------------------------------------
discover_and_test() {
    discover_kid="$1"
    input_file="$2"
    extra="${3:-}"

    echo ""
    echo "Discovering available algorithms via '$CLI mac --list' ..."

    list=$($CLI mac --list 2>/dev/null)

    if [ -z "$list" ]; then
        echo "  ERROR: empty output – is '$CLI' in PATH?"
        return 1
    fi

    OLDIFS="$IFS"

    # ── Cipher-based (CMAC, CMAC_TRUNCATED, CBC-MAC, ...) ────────────────
    cipher_algos=$(echo "$list" | awk \
        '/Cipher-based:/{f=1} f && /Algorithms:/{
            sub(/.*Algorithms: */,""); gsub(/ /,""); print; exit}')

    if [ -n "$cipher_algos" ]; then
        section_header "Cipher-based MAC ─────────────────────────────────────────────────────┐"
        IFS=','
        for algo in $cipher_algos; do
            IFS="$OLDIFS"
            run_mac_test "$algo" "$discover_kid" "$algo" "$input_file" "$extra"
            IFS=','
        done
        IFS="$OLDIFS"
        section_footer
    fi

    # ── HMAC-based ────────────────────────────────────────────────────────
    hmac_hashes=$(echo "$list" | awk \
        '/HMAC-based:/{f=1} f && /Hash:/{
            sub(/.*Hash: */,""); gsub(/ /,""); print; exit}')

    if [ -n "$hmac_hashes" ]; then
        section_header "HMAC-based MAC ───────────────────────────────────────────────────────┐"
        IFS=','
        for hash in $hmac_hashes; do
            IFS="$OLDIFS"
            run_mac_test "HMAC-$hash" "$discover_kid" "HMAC-$hash" \
                "$input_file" "$extra"
            IFS=','
        done
        IFS="$OLDIFS"
        section_footer
    fi
}

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
        "$CLI mac -a CMAC -i $input_file"

    run_negative_test \
        "missing --algo  → must be rejected" \
        "$CLI mac -k 1 -i $input_file"

    run_negative_test \
        "missing --input  → must be rejected" \
        "$CLI mac -k 1 -a CMAC"

    run_negative_test \
        "invalid algo  → must be rejected" \
        "$CLI mac -k 1 -a INVALID_ALGO -i $input_file"

    run_negative_test \
        "HMAC without hash  → must be rejected" \
        "$CLI mac -k 1 -a HMAC -i $input_file"

    run_negative_test \
        "HMAC with invalid hash  → must be rejected" \
        "$CLI mac -k 1 -a HMAC-INVALID -i $input_file"

    run_negative_test \
        "CMAC with hash suffix  → must be rejected" \
        "$CLI mac -k 1 -a CMAC-SHA256 -i $input_file"

    run_negative_test \
        "mac-verify missing --mac  → must be rejected" \
        "$CLI mac-verify -k 1 -a CMAC -i $input_file"

    run_negative_test \
        "mac-verify missing --input  → must be rejected" \
        "$CLI mac-verify -k 1 -a CMAC -m /dev/null"

    run_negative_test \
        "mac-verify missing --algo  → must be rejected" \
        "$CLI mac-verify -k 1 -i $input_file -m /dev/null"

    run_negative_test \
        "mac-verify missing --key-id  → must be rejected" \
        "$CLI mac-verify -a CMAC -i $input_file -m /dev/null"

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
