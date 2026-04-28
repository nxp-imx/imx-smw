#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2026 NXP
#
# Asymmetric key generation test suite - SMW backend (nxp_smw)
#
# Usage:
#   ./smw_keygen_asym.sh [--subsystem ELE|TEE|SECO]
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

. "$SCRIPT_DIR/lib_keygen_asym.sh"

# ---------------------------------------------------------------------------
# SMW extra flags helper
# ---------------------------------------------------------------------------
_smw_extra() {
    local flags=""
    [ -n "$SUBSYSTEM" ] && flags="-S $SUBSYSTEM"
    printf '%s' "$flags"
}

# ---------------------------------------------------------------------------
# SMW-specific: sign_hash/verify_hash usage tests
# ---------------------------------------------------------------------------
test_sign_hash_usage_smw() {
    local extra
    extra=$(_smw_extra)
    test_sign_hash_usage "$extra"
}

# ---------------------------------------------------------------------------
# SMW-specific: multi-algo tests
# ---------------------------------------------------------------------------
test_multi_algo() {
    local extra
    extra=$(_smw_extra)

    local list
    list=$(_get_list)
    [ -z "$list" ] && return 1

    # ── RSA multi-algo sign/verify ────────────────────────────────────────
    local rsa_sig_modes rsa_sig_hashes
    rsa_sig_modes=$(printf '%s' "$list" | awk \
        '/^  RSA Signature:/{f=1} f && /Modes:/{sub(/.*Modes: */,""); gsub(/ /,""); print; exit} f && /^  [A-Z]/{f=0}')
    rsa_sig_hashes=$(printf '%s' "$list" | awk \
        '/^  RSA Signature:/{f=1} f && /Hashes:/{sub(/.*Hashes: */,""); gsub(/ /,""); print; exit} f && /^  [A-Z]/{f=0}')

    if [ -n "$rsa_sig_modes" ] && [ -n "$rsa_sig_hashes" ]; then
        section_header "RSA Signature — multi-algo (sign/verify) ────────────────────────────┐"
        # Build combos list as newline-separated file
        local combos_file
        combos_file=$(mktemp)
        local IFS=','
        for mode in $rsa_sig_modes; do
            for hash in $rsa_sig_hashes; do
                printf '%s-%s\n' "$mode" "$hash" >> "$combos_file"
            done
        done

        for sz in $(key_sizes_for_asym_type "RSA"); do
            local total_combos i j
            total_combos=$(wc -l < "$combos_file")
            i=1
            while [ "$i" -le "$total_combos" ]; do
                j=$((i + 1))
                while [ "$j" -le "$total_combos" ]; do
                    local ci cj
                    ci=$(sed -n "${i}p" "$combos_file")
                    cj=$(sed -n "${j}p" "$combos_file")
                    run_keygen_test \
                        "RSA-${sz}  ${ci},${cj}  sign,verify" \
                        "RSA" "$sz" "${ci},${cj}" "sign,verify" "--transient $extra"
                    j=$((j + 1))
                done
                i=$((i + 1))
            done
        done
        section_footer

        section_header "RSA Signature — multi-algo (sign_hash/verify_hash) ──────────────────┐"
        for sz in $(key_sizes_for_asym_type "RSA"); do
            local total_combos i j
            total_combos=$(wc -l < "$combos_file")
            i=1
            while [ "$i" -le "$total_combos" ]; do
                j=$((i + 1))
                while [ "$j" -le "$total_combos" ]; do
                    local ci cj
                    ci=$(sed -n "${i}p" "$combos_file")
                    cj=$(sed -n "${j}p" "$combos_file")
                    run_keygen_test \
                        "RSA-${sz}  ${ci},${cj}  sign_hash,verify_hash" \
                        "RSA" "$sz" "${ci},${cj}" "sign_hash,verify_hash" "--transient $extra"
                    j=$((j + 1))
                done
                i=$((i + 1))
            done
        done
        section_footer

        rm -f "$combos_file"
    fi

    # ── ECDSA multi-algo sign/verify ──────────────────────────────────────
    local ecdsa_kts ecdsa_hashes
    ecdsa_kts=$(printf '%s' "$list" | awk \
        '/^  ECDSA Signature:/{f=1} f && /Key types:/{sub(/.*Key types: */,""); gsub(/ /,""); print; exit} f && /^  [A-Z]/{f=0}')
    ecdsa_hashes=$(printf '%s' "$list" | awk \
        '/^  ECDSA Signature:/{f=1} f && /Hashes:/{sub(/.*Hashes: */,""); gsub(/ /,""); print; exit} f && /^  [A-Z]/{f=0}')

    if [ -n "$ecdsa_kts" ] && [ -n "$ecdsa_hashes" ]; then
        section_header "ECDSA Signature — multi-algo (sign/verify) ──────────────────────────┐"
        local combos_file
        combos_file=$(mktemp)
        local IFS=','
        for hash in $ecdsa_hashes; do
            printf 'ECDSA-%s\n' "$hash" >> "$combos_file"
        done

        for kt in $ecdsa_kts; do
            for sz in $(key_sizes_for_asym_type "$kt"); do
                local total_combos i j
                total_combos=$(wc -l < "$combos_file")
                i=1
                while [ "$i" -le "$total_combos" ]; do
                    j=$((i + 1))
                    while [ "$j" -le "$total_combos" ]; do
                        local ci cj
                        ci=$(sed -n "${i}p" "$combos_file")
                        cj=$(sed -n "${j}p" "$combos_file")
                        run_keygen_test \
                            "$kt-${sz}  ${ci},${cj}  sign,verify" \
                            "$kt" "$sz" "${ci},${cj}" "sign,verify" "--transient $extra"
                        j=$((j + 1))
                    done
                    i=$((i + 1))
                done
            done
        done
        section_footer

        section_header "ECDSA Signature — multi-algo (sign_hash/verify_hash) ────────────────┐"
        for kt in $ecdsa_kts; do
            for sz in $(key_sizes_for_asym_type "$kt"); do
                local total_combos i j
                total_combos=$(wc -l < "$combos_file")
                i=1
                while [ "$i" -le "$total_combos" ]; do
                    j=$((i + 1))
                    while [ "$j" -le "$total_combos" ]; do
                        local ci cj
                        ci=$(sed -n "${i}p" "$combos_file")
                        cj=$(sed -n "${j}p" "$combos_file")
                        run_keygen_test \
                            "$kt-${sz}  ${ci},${cj}  sign_hash,verify_hash" \
                            "$kt" "$sz" "${ci},${cj}" "sign_hash,verify_hash" "--transient $extra"
                        j=$((j + 1))
                    done
                    i=$((i + 1))
                done
            done
        done
        section_footer

        rm -f "$combos_file"
    fi

    # ── RSA OAEP multi-hash encrypt/decrypt ───────────────────────────────
    local rsa_enc_hashes
    rsa_enc_hashes=$(printf '%s' "$list" | awk \
        '/^  RSA Encryption:/{f=1} f && /Hashes:/{sub(/.*Hashes: */,""); gsub(/ /,""); print; exit} f && /^  [A-Z]/{f=0}')

    if [ -n "$rsa_enc_hashes" ]; then
        section_header "RSA OAEP Encryption — multi-algo (encrypt/decrypt) ──────────────────┐"
        local combos_file
        combos_file=$(mktemp)
        local IFS=','
        for hash in $rsa_enc_hashes; do
            printf 'OAEP-%s\n' "$hash" >> "$combos_file"
        done

        for sz in $(key_sizes_for_asym_type "RSA"); do
            local total_combos i j
            total_combos=$(wc -l < "$combos_file")
            i=1
            while [ "$i" -le "$total_combos" ]; do
                j=$((i + 1))
                while [ "$j" -le "$total_combos" ]; do
                    local ci cj
                    ci=$(sed -n "${i}p" "$combos_file")
                    cj=$(sed -n "${j}p" "$combos_file")
                    run_keygen_test \
                        "RSA-${sz}  ${ci},${cj}  encrypt,decrypt" \
                        "RSA" "$sz" "${ci},${cj}" "encrypt,decrypt" "--transient $extra"
                    j=$((j + 1))
                done
                i=$((i + 1))
            done
        done
        section_footer

        rm -f "$combos_file"
    fi
}

# ---------------------------------------------------------------------------
# SMW-specific: persistent key tests
# ---------------------------------------------------------------------------
test_persistent_keys_smw() {
    local base_id=9000
    local kid
    local extra
    extra=$(_smw_extra)

    local list
    list=$(_get_list)
    [ -z "$list" ] && return 1

    # ── RSA Signature ────────────────────────────────────────────────────
    local rsa_sig_modes rsa_sig_hashes
    rsa_sig_modes=$(printf '%s' "$list" | awk \
        '/^  RSA Signature:/{f=1} f && /Modes:/{sub(/.*Modes: */,""); gsub(/ /,""); print; exit} f && /^  [A-Z]/{f=0}')
    rsa_sig_hashes=$(printf '%s' "$list" | awk \
        '/^  RSA Signature:/{f=1} f && /Hashes:/{sub(/.*Hashes: */,""); gsub(/ /,""); print; exit} f && /^  [A-Z]/{f=0}')

    if [ -n "$rsa_sig_modes" ] && [ -n "$rsa_sig_hashes" ]; then
        section_header "Persistent key tests — RSA Signature (SMW) ─────────────────────────┐"
        local IFS=','
        for sz in $(key_sizes_for_asym_type "RSA"); do
            for mode in $rsa_sig_modes; do
                for hash in $rsa_sig_hashes; do
                    kid=$((base_id))
                    base_id=$((base_id + 1))
                    $CLI key-delete -i "$kid" $extra >/dev/null 2>&1
                    run_keygen_test \
                        "RSA-${sz}  ${mode}-${hash}  sign,verify  persist" \
                        "RSA" "$sz" "${mode}-${hash}" "sign,verify" "-i $kid $extra"
                    $CLI key-delete -i "$kid" $extra >/dev/null 2>&1
                done
            done
        done
        section_footer
    fi

    # ── ECDSA Signature ──────────────────────────────────────────────────
    local ecdsa_kts ecdsa_hashes
    ecdsa_kts=$(printf '%s' "$list" | awk \
        '/^  ECDSA Signature:/{f=1} f && /Key types:/{sub(/.*Key types: */,""); gsub(/ /,""); print; exit} f && /^  [A-Z]/{f=0}')
    ecdsa_hashes=$(printf '%s' "$list" | awk \
        '/^  ECDSA Signature:/{f=1} f && /Hashes:/{sub(/.*Hashes: */,""); gsub(/ /,""); print; exit} f && /^  [A-Z]/{f=0}')

    if [ -n "$ecdsa_kts" ] && [ -n "$ecdsa_hashes" ]; then
        section_header "Persistent key tests — ECDSA Signature (SMW) ───────────────────────┐"
        local IFS=','
        for kt in $ecdsa_kts; do
            for sz in $(key_sizes_for_asym_type "$kt"); do
                for hash in $ecdsa_hashes; do
                    kid=$((base_id))
                    base_id=$((base_id + 1))
                    $CLI key-delete -i "$kid" $extra >/dev/null 2>&1
                    run_keygen_test \
                        "$kt-${sz}  ECDSA-${hash}  sign,verify  persist" \
                        "$kt" "$sz" "ECDSA-${hash}" "sign,verify" "-i $kid $extra"
                    $CLI key-delete -i "$kid" $extra >/dev/null 2>&1
                done
            done
        done
        section_footer
    fi

    # ── EdDSA Signature ──────────────────────────────────────────────────
    local eddsa_kts eddsa_variants
    eddsa_kts=$(printf '%s' "$list" | awk \
        '/^  EdDSA Signature:/{f=1} f && /Key types:/{sub(/.*Key types: */,""); gsub(/ /,""); print; exit} f && /^  [A-Z]/{f=0}')
    eddsa_variants=$(printf '%s' "$list" | awk \
        '/^  EdDSA Signature:/{f=1} f && /Variants:/{sub(/.*Variants: */,""); gsub(/ /,""); print; exit} f && /^  [A-Z]/{f=0}')

    if [ -n "$eddsa_kts" ] && [ -n "$eddsa_variants" ]; then
        section_header "Persistent key tests — EdDSA Signature (SMW) ───────────────────────┐"
        local IFS=','
        for kt in $eddsa_kts; do
            for variant in $eddsa_variants; do
                kid=$((base_id))
                base_id=$((base_id + 1))
                $CLI key-delete -i "$kid" $extra >/dev/null 2>&1
                run_keygen_test \
                    "$kt  EDDSA-${variant}  sign,verify  persist" \
                    "$kt" "" "EDDSA-${variant}" "sign,verify" "-i $kid $extra"
                $CLI key-delete -i "$kid" $extra >/dev/null 2>&1
            done
        done
        section_footer
    fi

    # ── DSA Signature ────────────────────────────────────────────────────
    local dsa_kts dsa_hashes
    dsa_kts=$(printf '%s' "$list" | awk \
        '/^  DSA Signature:/{f=1} f && /Key types:/{sub(/.*Key types: */,""); gsub(/ /,""); print; exit} f && /^  [A-Z]/{f=0}')
    dsa_hashes=$(printf '%s' "$list" | awk \
        '/^  DSA Signature:/{f=1} f && /Hashes:/{sub(/.*Hashes: */,""); gsub(/ /,""); print; exit} f && /^  [A-Z]/{f=0}')

    if [ -n "$dsa_kts" ] && [ -n "$dsa_hashes" ]; then
        section_header "Persistent key tests — DSA Signature (SMW) ─────────────────────────┐"
        local IFS=','
        for kt in $dsa_kts; do
            for sz in $(key_sizes_for_asym_type "$kt"); do
                for hash in $dsa_hashes; do
                    kid=$((base_id))
                    base_id=$((base_id + 1))
                    $CLI key-delete -i "$kid" $extra >/dev/null 2>&1
                    run_keygen_test \
                        "$kt-${sz}  ${hash}  sign,verify  persist" \
                        "$kt" "$sz" "$hash" "sign,verify" "-i $kid $extra"
                    $CLI key-delete -i "$kid" $extra >/dev/null 2>&1
                done
            done
        done
        section_footer
    fi

    # ── RSA Encryption ───────────────────────────────────────────────────
    local rsa_enc_modes rsa_enc_hashes
    rsa_enc_modes=$(printf '%s' "$list" | awk \
        '/^  RSA Encryption:/{f=1} f && /Modes:/{sub(/.*Modes: */,""); gsub(/ /,""); print; exit} f && /^  [A-Z]/{f=0}')
    rsa_enc_hashes=$(printf '%s' "$list" | awk \
        '/^  RSA Encryption:/{f=1} f && /Hashes:/{sub(/.*Hashes: */,""); gsub(/ /,""); print; exit} f && /^  [A-Z]/{f=0}')

    if [ -n "$rsa_enc_modes" ]; then
        section_header "Persistent key tests — RSA Encryption (SMW) ────────────────────────┐"
        local IFS=','
        for sz in $(key_sizes_for_asym_type "RSA"); do
            for mode in $rsa_enc_modes; do
                case "$mode" in
                    PKCS1V15)
                        kid=$((base_id))
                        base_id=$((base_id + 1))
                        $CLI key-delete -i "$kid" $extra >/dev/null 2>&1
                        run_keygen_test \
                            "RSA-${sz}  PKCS1V15-CRYPT  encrypt,decrypt  persist" \
                            "RSA" "$sz" "PKCS1V15-CRYPT" "encrypt,decrypt" "-i $kid $extra"
                        $CLI key-delete -i "$kid" $extra >/dev/null 2>&1
                        ;;
                    NOPAD)
                        kid=$((base_id))
                        base_id=$((base_id + 1))
                        $CLI key-delete -i "$kid" $extra >/dev/null 2>&1
                        run_keygen_test \
                            "RSA-${sz}  NOPAD  encrypt,decrypt  persist" \
                            "RSA" "$sz" "NOPAD" "encrypt,decrypt" "-i $kid $extra"
                        $CLI key-delete -i "$kid" $extra >/dev/null 2>&1
                        ;;
                    OAEP)
                        for hash in $rsa_enc_hashes; do
                            kid=$((base_id))
                            base_id=$((base_id + 1))
                            $CLI key-delete -i "$kid" $extra >/dev/null 2>&1
                            run_keygen_test \
                                "RSA-${sz}  OAEP-${hash}  encrypt,decrypt  persist" \
                                "RSA" "$sz" "OAEP-${hash}" "encrypt,decrypt" "-i $kid $extra"
                            $CLI key-delete -i "$kid" $extra >/dev/null 2>&1
                        done
                        ;;
                esac
            done
        done
        section_footer
    fi

    # ── Key Exchange ─────────────────────────────────────────────────────
    local kex_kts
    kex_kts=$(printf '%s' "$list" | awk \
        '/^Key Exchange \(derive\):/{f=1} f && /Key types:/{sub(/.*Key types: */,""); gsub(/ /,""); print; exit} f && /^[A-Z]/{f=0}')

    if [ -n "$kex_kts" ]; then
        section_header "Persistent key tests — Key Exchange (SMW) ──────────────────────────┐"
        local IFS=','
        for kt in $kex_kts; do
            local sizes
            sizes=$(key_sizes_for_asym_type "$kt")
            if [ -n "$sizes" ]; then
                local IFS=' '
                for sz in $sizes; do
                    kid=$((base_id))
                    base_id=$((base_id + 1))
                    $CLI key-delete -i "$kid" $extra >/dev/null 2>&1
                    run_keygen_test \
                        "$kt-${sz}  ECDH  derive  persist" \
                        "$kt" "$sz" "ECDH" "derive" "-i $kid $extra"
                    $CLI key-delete -i "$kid" $extra >/dev/null 2>&1
                done
            else
                kid=$((base_id))
                base_id=$((base_id + 1))
                $CLI key-delete -i "$kid" $extra >/dev/null 2>&1
                run_keygen_test \
                    "$kt  ECDH  derive  persist" \
                    "$kt" "" "ECDH" "derive" "-i $kid $extra"
                $CLI key-delete -i "$kid" $extra >/dev/null 2>&1
            fi
        done
        section_footer
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
echo "╔══════════════════════════════════════════════════════════════════════════╗"
echo "║       NXP SMW CLI — Asymmetric Key Generation Test Suite                 ║"
echo "╚══════════════════════════════════════════════════════════════════════════╝"

if ! command -v "$CLI" >/dev/null 2>&1; then
    echo "ERROR: '$CLI' not found in PATH. Aborting."
    exit 1
fi

if [ -n "$SUBSYSTEM" ]; then
    SUBSYSTEMS="$SUBSYSTEM"
else
    SUBSYSTEMS="ELE TEE"
fi

GLOBAL_FAIL=0

for SUBSYSTEM in $SUBSYSTEMS; do
    echo ""
    echo "╔══════════════════════════════════════════════════════════════════════════╗"
    printf "║  Subsystem: %-61s║\n" "$SUBSYSTEM"
    echo "╚══════════════════════════════════════════════════════════════════════════╝"

    # Reset list cache for each subsystem
    _LIST_CACHE=""

    reset_counters

    discover_and_test "$(_smw_extra)"
    test_sign_hash_usage_smw
    test_multi_algo
    test_persistent_keys_smw

    print_failure_report
    print_summary

    GLOBAL_FAIL=$((GLOBAL_FAIL + FAIL))
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

GLOBAL_FAIL=$((GLOBAL_FAIL + FAIL))

echo ""
echo "╔══════════════════════════════════════════════════════════════════════════╗"
if [ "$GLOBAL_FAIL" -eq 0 ]; then
    printf "║  Overall result: %-56s║\n" "ALL PASSED"
else
    printf "║  Overall result: %-56s║\n" "$GLOBAL_FAIL FAILURE(S)"
fi
echo "╚══════════════════════════════════════════════════════════════════════════╝"

[ "$GLOBAL_FAIL" -eq 0 ]
