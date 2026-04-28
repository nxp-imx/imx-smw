#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2026 NXP
#
# Shared library for asymmetric key generation test suites.

PASS=0
FAIL=0

FAIL_DESCS=""
FAIL_CMDS=""
FAIL_ERRS=""
FAIL_CODES=""
FAIL_COUNT=0

reset_counters() {
    PASS=0
    FAIL=0
    FAIL_DESCS=""
    FAIL_CMDS=""
    FAIL_ERRS=""
    FAIL_CODES=""
    FAIL_COUNT=0
}

# ---------------------------------------------------------------------------
# Default key sizes per key type (space-separated)
# ---------------------------------------------------------------------------
key_sizes_for_asym_type() {
    case "$1" in
        RSA)            echo "2048" ;;
        SECP_R1)        echo "256 384 521" ;;
        BRAINPOOL_R1)   echo "256 384 512" ;;
        BRAINPOOL_T1)   echo "256 384 512" ;;
        ED25519)        echo "" ;;
        ED448)          echo "" ;;
        X25519)         echo "" ;;
        X448)           echo "" ;;
        DSA_SM2_FP)     echo "256" ;;
        DH)             echo "2048" ;;
        *)              echo "" ;;
    esac
}

# ---------------------------------------------------------------------------
# hashes_for_ec_size  key_size
# ---------------------------------------------------------------------------
hashes_for_ec_size() {
    case "$1" in
        256)  echo "MD5,SHA1,SHA224,SHA256,SM3" ;;
        384)  echo "SHA384" ;;
        512)  echo "SHA512" ;;
        521)  echo "SHA512" ;;
        *)    echo "SHA256" ;;
    esac
}

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------
_extract_error_code() {
    local code
    code=$(printf '%s' "$1" | grep -oE 'SMW_STATUS_[A-Z_]+|PSA_ERROR_[A-Z_]+' | head -1)
    printf '%s' "${code:-UNKNOWN}"
}

_is_not_supported() {
    printf '%s' "$1" | grep -qiE \
        'not supported|not configured|SMW_STATUS_OPERATION_NOT_SUPPORTED|SMW_STATUS_OPERATION_NOT_PERMITTED|PSA_ERROR_NOT_SUPPORTED'
}

_encode() {
    printf '%s' "$1" | tr '\n' '\034'
}

_decode() {
    printf '%s' "$1" | tr '\034' '\n'
}

_record_fail() {
    local code
    code=$(_extract_error_code "$3")
    FAIL_DESCS="${FAIL_DESCS}$(printf '%s\035' "$(_encode "$1")")"
    FAIL_CMDS="${FAIL_CMDS}$(printf '%s\035' "$(_encode "$2")")"
    FAIL_ERRS="${FAIL_ERRS}$(printf '%s\035' "$(_encode "$3")")"
    FAIL_CODES="${FAIL_CODES}$(printf '%s\035' "$(_encode "$code")")"
    FAIL_COUNT=$((FAIL_COUNT + 1))
    FAIL=$((FAIL + 1))
}

_print_row() {
    printf "  %-60s " "[$1]"
}

# ---------------------------------------------------------------------------
# _parse_list_field  list_output  section_pattern  field_name
# ---------------------------------------------------------------------------
_parse_list_field() {
    local list="$1"
    local section="$2"
    local field="$3"

    printf '%s' "$list" | awk -v sec="$section" -v fld="$field" '
        {
            trimmed = $0
            sub(/^[ \t]+/, "", trimmed)
            if (trimmed == sec) { in_sec=1; next }
        }
        in_sec && /^[^ \t]/ && /:/ { in_sec=0 }
        in_sec {
            if (index($0, fld) != 0) {
                val = $0
                sub(/^[^:]*:[ \t]*/, "", val)
                gsub(/[ \t]/, "", val)
                print val
                in_sec=0
            }
        }
    '
}

# ---------------------------------------------------------------------------
# _parse_tls_kex_field  list_output  field_name
#
# Parses fields from the "Keys supporting TLS Key Derivation (derive):" section.
# This section is NOT indented under a sub-header, so we match the top-level
# section line and stop at the next top-level "Keys supporting" line.
# ---------------------------------------------------------------------------
_parse_tls_kex_field() {
    local list="$1"
    local field="$2"

    printf '%s' "$list" | awk -v fld="$field" '
        /^Keys supporting TLS Key Derivation \(derive\):/ { in_sec=1; next }
        in_sec && /^Keys supporting / { in_sec=0 }
        in_sec {
            if (index($0, fld) != 0) {
                val = $0
                sub(/^[^:]*:[ \t]*/, "", val)
                gsub(/[ \t]/, "", val)
                print val
                in_sec=0
            }
        }
    '
}

# ---------------------------------------------------------------------------
# _hash_supported  hash  comma_separated_hash_list
# ---------------------------------------------------------------------------
_hash_supported() {
    local needle="$1"
    local haystack="$2"
    local OIFS="$IFS"
    IFS=','
    for h in $haystack; do
        if [ "$h" = "$needle" ]; then
            IFS="$OIFS"
            return 0
        fi
    done
    IFS="$OIFS"
    return 1
}

# ---------------------------------------------------------------------------
# run_keygen_test  desc  key_type  key_size  algo  usage  [extra]
# ---------------------------------------------------------------------------
run_keygen_test() {
    local desc="$1" key_type="$2" key_size="$3"
    local algo="$4" usage="$5" extra="${6:-}"

    local size_flag=""
    if [ -n "$key_size" ] && [ "$key_size" != "-" ]; then
        size_flag="-s $key_size"
    fi

    local cmd="$CLI keygen-asym -t $key_type $size_flag -a $algo -u $usage $extra"

    _print_row "$desc"

    local out rc
    out=$(eval "$cmd" 2>&1)
    rc=$?

    if [ $rc -eq 0 ]; then
        echo "PASS"
        PASS=$((PASS + 1))
        return 0
    fi

    if _is_not_supported "$out"; then
        echo "SKIP  (not supported/configured)"
        return 2
    fi

    echo "FAIL"
    _record_fail "$desc" "$cmd" "$out"
    return 1
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
section_footer()  { echo "└$(printf '─%.0s' $(seq 1 75))┘"; }

# ---------------------------------------------------------------------------
# _get_list
# ---------------------------------------------------------------------------
_LIST_CACHE=""
_get_list() {
    if [ -z "$_LIST_CACHE" ]; then
        _LIST_CACHE=$($CLI keygen-asym --list 2>/dev/null)
    fi
    printf '%s' "$_LIST_CACHE"
}

# ---------------------------------------------------------------------------
# discover_and_test [extra]
# ---------------------------------------------------------------------------
discover_and_test() {
    local extra="${1:-}"

    echo ""
    echo "Discovering available types/algos via '$CLI keygen-asym --list' ..."

    local list
    list=$(_get_list)

    if [ -z "$list" ]; then
        echo "  ERROR: empty output – is '$CLI' in PATH?"
        return 1
    fi

    local OIFS="$IFS"

    # ── RSA Signature ────────────────────────────────────────────────────
    local rsa_sig_modes rsa_sig_hashes
    rsa_sig_modes=$(_parse_list_field "$list" "RSA Signature:" "Modes:")
    rsa_sig_hashes=$(_parse_list_field "$list" "RSA Signature:" "Hashes:")

    if [ -n "$rsa_sig_modes" ] && [ -n "$rsa_sig_hashes" ]; then
        section_header "RSA Signature (sign/verify) ──────────────────────────────────────────┐"
        local sz mode hash
        for sz in $(key_sizes_for_asym_type "RSA"); do
            IFS=','
            for mode in $rsa_sig_modes; do
                for hash in $rsa_sig_hashes; do
                    IFS="$OIFS"
                    run_keygen_test \
                        "RSA-${sz}  ${mode}-${hash}  sign,verify" \
                        "RSA" "$sz" "${mode}-${hash}" "sign,verify" "--transient $extra"
                    IFS=','
                done
            done
            IFS="$OIFS"
        done
        section_footer
    fi

    # ── ECDSA Signature ──────────────────────────────────────────────────
    local ecdsa_kts ecdsa_hashes
    ecdsa_kts=$(_parse_list_field "$list" "ECDSA Signature:" "Key types:")
    ecdsa_hashes=$(_parse_list_field "$list" "ECDSA Signature:" "Hashes:")

    if [ -n "$ecdsa_kts" ] && [ -n "$ecdsa_hashes" ]; then
        section_header "ECDSA Signature (sign/verify) ────────────────────────────────────────┐"
        local kt sz hash aligned_hashes
        IFS=','
        for kt in $ecdsa_kts; do
            IFS="$OIFS"
            for sz in $(key_sizes_for_asym_type "$kt"); do
                aligned_hashes=$(hashes_for_ec_size "$sz")
                IFS=','
                for hash in $aligned_hashes; do
                    IFS="$OIFS"
                    if _hash_supported "$hash" "$ecdsa_hashes"; then
                        run_keygen_test \
                            "$kt-${sz}  ECDSA-${hash}  sign,verify" \
                            "$kt" "$sz" "ECDSA-${hash}" "sign,verify" "--transient $extra"
                    fi
                    IFS=','
                done
                IFS="$OIFS"
            done
            IFS=','
        done
        IFS="$OIFS"
        section_footer
    fi

    # ── EdDSA Signature ──────────────────────────────────────────────────
    local eddsa_kts eddsa_variants
    eddsa_kts=$(_parse_list_field "$list" "EdDSA Signature:" "Key types:")
    eddsa_variants=$(_parse_list_field "$list" "EdDSA Signature:" "Variants:")

    if [ -n "$eddsa_kts" ] && [ -n "$eddsa_variants" ]; then
        section_header "EdDSA Signature (sign/verify) ────────────────────────────────────────┐"
        local kt variant
        IFS=','
        for kt in $eddsa_kts; do
            for variant in $eddsa_variants; do
                IFS="$OIFS"
                run_keygen_test \
                    "$kt  EDDSA-${variant}  sign,verify" \
                    "$kt" "" "EDDSA-${variant}" "sign,verify" "--transient $extra"
                IFS=','
            done
        done
        IFS="$OIFS"
        section_footer
    fi

    # ── DSA Signature ────────────────────────────────────────────────────
    local dsa_kts dsa_hashes
    dsa_kts=$(_parse_list_field "$list" "DSA Signature:" "Key types:")
    dsa_hashes=$(_parse_list_field "$list" "DSA Signature:" "Hashes:")

    if [ -n "$dsa_kts" ] && [ -n "$dsa_hashes" ]; then
        section_header "DSA Signature (sign/verify) ──────────────────────────────────────────┐"
        local kt sz hash aligned_hashes
        IFS=','
        for kt in $dsa_kts; do
            IFS="$OIFS"
            for sz in $(key_sizes_for_asym_type "$kt"); do
                aligned_hashes=$(hashes_for_ec_size "$sz")
                IFS=','
                for hash in $aligned_hashes; do
                    IFS="$OIFS"
                    if _hash_supported "$hash" "$dsa_hashes"; then
                        run_keygen_test \
                            "$kt-${sz}  ${hash}  sign,verify" \
                            "$kt" "$sz" "$hash" "sign,verify" "--transient $extra"
                    fi
                    IFS=','
                done
                IFS="$OIFS"
            done
            IFS=','
        done
        IFS="$OIFS"
        section_footer
    fi

    # ── RSA Encryption ───────────────────────────────────────────────────
    local rsa_enc_algos
    rsa_enc_algos=$(_parse_list_field "$list" "RSA Encryption (encrypt/decrypt):" "Algorithms:")

    if [ -n "$rsa_enc_algos" ]; then
        section_header "RSA Encryption (encrypt/decrypt) ─────────────────────────────────────┐"
        local sz algo
        for sz in $(key_sizes_for_asym_type "RSA"); do
            IFS=','
            for algo in $rsa_enc_algos; do
                IFS="$OIFS"
                run_keygen_test \
                    "RSA-${sz}  ${algo}  encrypt,decrypt" \
                    "RSA" "$sz" "$algo" "encrypt,decrypt" "--transient $extra"
                IFS=','
            done
            IFS="$OIFS"
        done
        section_footer
    fi

    # ── TLS Key Derivation ───────────────────────────────────────────────
    # New list format:
    #   Keys supporting TLS Key Derivation (derive):
    #     Key types:  SECP_R1, X25519, X448
    #     Algorithms: {TLS}-{HASH}
    #     TLS Modes:  TLS12, TLS13
    #     Hashes:     MD5, SHA1, SHA224, SHA256, ...
    local tls_kex_kts tls_modes tls_hashes
    tls_kex_kts=$(_parse_tls_kex_field "$list" "Key types:")
    tls_modes=$(_parse_tls_kex_field "$list" "TLS Modes:")
    tls_hashes=$(_parse_tls_kex_field "$list" "Hashes:")

    if [ -n "$tls_kex_kts" ] && [ -n "$tls_modes" ] && [ -n "$tls_hashes" ]; then
        section_header "TLS Key Derivation (derive) ──────────────────────────────────────────┐"

        local kt sz mode hash first_mode first_hash

        # Pick a representative hash (SHA256) if supported, else first available
        if _hash_supported "SHA256" "$tls_hashes"; then
            first_hash="SHA256"
        else
            first_hash=$(printf '%s' "$tls_hashes" | cut -d',' -f1)
        fi

        # Pick first TLS mode
        first_mode=$(printf '%s' "$tls_modes" | cut -d',' -f1)

        # Test every key type with every TLS mode using the representative hash
        IFS=','
        for kt in $tls_kex_kts; do
            IFS="$OIFS"
            sizes=$(key_sizes_for_asym_type "$kt")
            for mode in $(printf '%s' "$tls_modes" | tr ',' ' '); do
                if [ -n "$sizes" ]; then
                    for sz in $sizes; do
                        run_keygen_test \
                            "$kt-${sz}  ${mode}-${first_hash}  derive" \
                            "$kt" "$sz" "${mode}-${first_hash}" "derive" "--transient $extra"
                    done
                else
                    run_keygen_test \
                        "$kt  ${mode}-${first_hash}  derive" \
                        "$kt" "" "${mode}-${first_hash}" "derive" "--transient $extra"
                fi
            done
            IFS=','
        done
        IFS="$OIFS"

        # Test all hashes with the first key type and first TLS mode
        local first_kt first_sz size_flag
        first_kt=$(printf '%s' "$tls_kex_kts" | cut -d',' -f1)
        first_sz=$(key_sizes_for_asym_type "$first_kt" | awk '{print $1}')
        size_flag=""
        [ -n "$first_sz" ] && size_flag="$first_sz"

        IFS=','
        for hash in $tls_hashes; do
            IFS="$OIFS"
            # Skip the representative hash — already tested above
            if [ "$hash" = "$first_hash" ]; then
                IFS=','
                continue
            fi
            run_keygen_test \
                "$first_kt  ${first_mode}-${hash}  derive" \
                "$first_kt" "$size_flag" "${first_mode}-${hash}" "derive" "--transient $extra"
            IFS=','
        done
        IFS="$OIFS"

        section_footer
    fi
}

# ---------------------------------------------------------------------------
# test_sign_hash_usage [extra]
# ---------------------------------------------------------------------------
test_sign_hash_usage() {
    local extra="${1:-}"

    local list
    list=$(_get_list)
    [ -z "$list" ] && return 1

    local OIFS="$IFS"

    # ── RSA sign_hash/verify_hash ─────────────────────────────────────
    local rsa_sig_modes rsa_sig_hashes
    rsa_sig_modes=$(_parse_list_field "$list" "RSA Signature:" "Modes:")
    rsa_sig_hashes=$(_parse_list_field "$list" "RSA Signature:" "Hashes:")

    if [ -n "$rsa_sig_modes" ] && [ -n "$rsa_sig_hashes" ]; then
        section_header "RSA Signature (sign_hash/verify_hash) ───────────────────────────────┐"
        local sz mode hash
        for sz in $(key_sizes_for_asym_type "RSA"); do
            IFS=','
            for mode in $rsa_sig_modes; do
                for hash in $rsa_sig_hashes; do
                    IFS="$OIFS"
                    run_keygen_test \
                        "RSA-${sz}  ${mode}-${hash}  sign_hash,verify_hash" \
                        "RSA" "$sz" "${mode}-${hash}" "sign_hash,verify_hash" "--transient $extra"
                    IFS=','
                done
            done
            IFS="$OIFS"
        done
        section_footer
    fi

    # ── ECDSA sign_hash/verify_hash ───────────────────────────────────
    local ecdsa_kts ecdsa_hashes
    ecdsa_kts=$(_parse_list_field "$list" "ECDSA Signature:" "Key types:")
    ecdsa_hashes=$(_parse_list_field "$list" "ECDSA Signature:" "Hashes:")

    if [ -n "$ecdsa_kts" ] && [ -n "$ecdsa_hashes" ]; then
        section_header "ECDSA Signature (sign_hash/verify_hash) ─────────────────────────────┐"
        local kt sz hash aligned_hashes
        IFS=','
        for kt in $ecdsa_kts; do
            IFS="$OIFS"
            for sz in $(key_sizes_for_asym_type "$kt"); do
                aligned_hashes=$(hashes_for_ec_size "$sz")
                IFS=','
                for hash in $aligned_hashes; do
                    IFS="$OIFS"
                    if _hash_supported "$hash" "$ecdsa_hashes"; then
                        run_keygen_test \
                            "$kt-${sz}  ECDSA-${hash}  sign_hash,verify_hash" \
                            "$kt" "$sz" "ECDSA-${hash}" "sign_hash,verify_hash" "--transient $extra"
                    fi
                    IFS=','
                done
                IFS="$OIFS"
            done
            IFS=','
        done
        IFS="$OIFS"
        section_footer
    fi

    # ── EdDSA sign_hash/verify_hash ───────────────────────────────────
    local eddsa_kts eddsa_variants
    eddsa_kts=$(_parse_list_field "$list" "EdDSA Signature:" "Key types:")
    eddsa_variants=$(_parse_list_field "$list" "EdDSA Signature:" "Variants:")

    if [ -n "$eddsa_kts" ] && [ -n "$eddsa_variants" ]; then
        section_header "EdDSA Signature (sign_hash/verify_hash) ─────────────────────────────┐"
        local kt variant
        IFS=','
        for kt in $eddsa_kts; do
            for variant in $eddsa_variants; do
                IFS="$OIFS"
                run_keygen_test \
                    "$kt  EDDSA-${variant}  sign_hash,verify_hash" \
                    "$kt" "" "EDDSA-${variant}" "sign_hash,verify_hash" "--transient $extra"
                IFS=','
            done
        done
        IFS="$OIFS"
        section_footer
    fi
}

# ---------------------------------------------------------------------------
# test_negative_cases
# ---------------------------------------------------------------------------
test_negative_cases() {
    section_header "Negative / error case tests ──────────────────────────────────────────┐"

    run_negative_test \
        "missing --type  → must be rejected" \
        "$CLI keygen-asym -s 256 -a ECDSA-SHA256 -u sign,verify --transient"

    run_negative_test \
        "invalid key type  → must be rejected" \
        "$CLI keygen-asym -t INVALID_TYPE -s 256 -a ECDSA-SHA256 -u sign,verify --transient"

    run_negative_test \
        "invalid algo  → must be rejected" \
        "$CLI keygen-asym -t SECP_R1 -s 256 -a INVALID_ALGO -u sign,verify --transient"

    run_negative_test \
        "missing --algo  → must be rejected" \
        "$CLI keygen-asym -t SECP_R1 -s 256 -u sign,verify --transient"

    run_negative_test \
        "missing --usage  → must be rejected" \
        "$CLI keygen-asym -t SECP_R1 -s 256 -a ECDSA-SHA256 --transient"

    run_negative_test \
        "persistent key without --id  → must be rejected" \
        "$CLI keygen-asym -t SECP_R1 -s 256 -a ECDSA-SHA256 -u sign,verify"

    run_negative_test \
        "transient key with --id  → must be rejected" \
        "$CLI keygen-asym -t SECP_R1 -s 256 -a ECDSA-SHA256 -u sign,verify --transient -i 9999"

    run_negative_test \
        "key id = 0  → must be rejected" \
        "$CLI keygen-asym -t SECP_R1 -s 256 -a ECDSA-SHA256 -u sign,verify -i 0"

    run_negative_test \
        "RSA size missing  → must be rejected" \
        "$CLI keygen-asym -t RSA -a PKCS1V15-SHA256 -u sign,verify --transient"

    run_negative_test \
        "wrong usage for key type  → must be rejected" \
        "$CLI keygen-asym -t SECP_R1 -s 256 -a ECDSA-SHA256 -u encrypt,decrypt --transient"

    section_footer
}

# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
print_failure_report() {
    if [ "$FAIL_COUNT" -eq 0 ]; then
        return
    fi

    echo ""
    echo "╔══════════════════════════════════════════════════════════════════════════╗"
    printf "║  %-72s║\n" "  FAILURE REPORT"
    echo "╚══════════════════════════════════════════════════════════════════════════╝"

    local tmpfile
    tmpfile=$(mktemp)

    printf '%s' "$FAIL_CODES" | tr '\035' '\n' | grep -v '^$' | sort | uniq -c | \
        sort -rn > "$tmpfile"

    echo ""
    printf "  %-52s  %6s\n" "Error Code" "Count"
    printf "  %-52s  %6s\n" "$(printf '─%.0s' $(seq 1 52))" "$(printf '─%.0s' $(seq 1 6))"

    while read -r cnt code; do
        printf "  %-52s  %6d\n" "$code" "$cnt"
    done < "$tmpfile"

    printf "  %-52s  %6s\n" "$(printf '─%.0s' $(seq 1 52))" "$(printf '─%.0s' $(seq 1 6))"
    printf "  %-52s  %6d\n" "TOTAL" "$FAIL_COUNT"

    rm -f "$tmpfile"

    echo ""
    echo "  Detailed list:"
    echo "  $(printf '─%.0s' $(seq 1 72))"

    local desc_file cmd_file err_file code_file
    desc_file=$(mktemp); cmd_file=$(mktemp)
    err_file=$(mktemp);  code_file=$(mktemp)

    printf '%s' "$FAIL_DESCS" | tr '\035' '\n' | grep -v '^$' > "$desc_file"
    printf '%s' "$FAIL_CMDS"  | tr '\035' '\n' | grep -v '^$' > "$cmd_file"
    printf '%s' "$FAIL_ERRS"  | tr '\035' '\n' | grep -v '^$' > "$err_file"
    printf '%s' "$FAIL_CODES" | tr '\035' '\n' | grep -v '^$' > "$code_file"

    local total_lines i
    total_lines=$(wc -l < "$desc_file")
    i=1

    while [ "$i" -le "$total_lines" ]; do
        local d c e k
        d=$(sed -n "${i}p" "$desc_file" | tr '\034' '\n')
        c=$(sed -n "${i}p" "$cmd_file"  | tr '\034' '\n')
        e=$(sed -n "${i}p" "$err_file"  | tr '\034' '\n')
        k=$(sed -n "${i}p" "$code_file" | tr '\034' '\n')

        printf "\n  [%d] %s\n" "$i" "$d"
        printf "      Code    : %s\n" "$k"
        printf "      Command : %s\n" "$c"
        echo   "      Output  :"
        printf '%s\n' "$e" | sed 's/^/               /'

        i=$((i + 1))
    done

    rm -f "$desc_file" "$cmd_file" "$err_file" "$code_file"
}

print_summary() {
    echo ""
    echo "╔══════════════════════════════════════════════════════════════════════════╗"
    printf "║  Results:            %4d PASS  │  %4d FAIL     %24s║\n" \
        "$PASS" "$FAIL" " "
    echo "╚══════════════════════════════════════════════════════════════════════════╝"
}

