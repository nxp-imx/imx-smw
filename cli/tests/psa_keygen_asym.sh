#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2026 NXP
#
# Asymmetric key generation test suite - PSA backend (nxp_psa)
#
# Usage:
#   ./psa_keygen_asym.sh
#
# Requires: nxp_psa in PATH

CLI="nxp_psa"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

. "$SCRIPT_DIR/lib_keygen_asym.sh"

# ---------------------------------------------------------------------------
# PSA-specific: persistent key tests
# ---------------------------------------------------------------------------
test_persistent_keys_psa() {
    local base_id=8000
    local kid

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
        section_header "Persistent key tests — RSA Signature (PSA) ──────────────────────────┐"
        local IFS=','
        for sz in $(key_sizes_for_asym_type "RSA"); do
            for mode in $rsa_sig_modes; do
                for hash in $rsa_sig_hashes; do
                    kid=$((base_id))
                    base_id=$((base_id + 1))
                    $CLI key-delete -i "$kid" >/dev/null 2>&1
                    run_keygen_test \
                        "RSA-${sz}  ${mode}-${hash}  sign,verify  persist" \
                        "RSA" "$sz" "${mode}-${hash}" "sign,verify" "-i $kid"
                    $CLI key-delete -i "$kid" >/dev/null 2>&1
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
        section_header "Persistent key tests — ECDSA Signature (PSA) ────────────────────────┐"
        local IFS=','
        for kt in $ecdsa_kts; do
            for sz in $(key_sizes_for_asym_type "$kt"); do
                for hash in $ecdsa_hashes; do
                    kid=$((base_id))
                    base_id=$((base_id + 1))
                    $CLI key-delete -i "$kid" >/dev/null 2>&1
                    run_keygen_test \
                        "$kt-${sz}  ECDSA-${hash}  sign,verify  persist" \
                        "$kt" "$sz" "ECDSA-${hash}" "sign,verify" "-i $kid"
                    $CLI key-delete -i "$kid" >/dev/null 2>&1
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
        section_header "Persistent key tests — EdDSA Signature (PSA) ────────────────────────┐"
        local IFS=','
        for kt in $eddsa_kts; do
            for variant in $eddsa_variants; do
                kid=$((base_id))
                base_id=$((base_id + 1))
                $CLI key-delete -i "$kid" >/dev/null 2>&1
                run_keygen_test \
                    "$kt  EDDSA-${variant}  sign,verify  persist" \
                    "$kt" "" "EDDSA-${variant}" "sign,verify" "-i $kid"
                $CLI key-delete -i "$kid" >/dev/null 2>&1
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
        section_header "Persistent key tests — RSA Encryption (PSA) ────────────────────────┐"
        local IFS=','
        for sz in $(key_sizes_for_asym_type "RSA"); do
            for mode in $rsa_enc_modes; do
                case "$mode" in
                    PKCS1V15)
                        kid=$((base_id))
                        base_id=$((base_id + 1))
                        $CLI key-delete -i "$kid" >/dev/null 2>&1
                        run_keygen_test \
                            "RSA-${sz}  PKCS1V15-CRYPT  encrypt,decrypt  persist" \
                            "RSA" "$sz" "PKCS1V15-CRYPT" "encrypt,decrypt" "-i $kid"
                        $CLI key-delete -i "$kid" >/dev/null 2>&1
                        ;;
                    NOPAD)
                        kid=$((base_id))
                        base_id=$((base_id + 1))
                        $CLI key-delete -i "$kid" >/dev/null 2>&1
                        run_keygen_test \
                            "RSA-${sz}  NOPAD  encrypt,decrypt  persist" \
                            "RSA" "$sz" "NOPAD" "encrypt,decrypt" "-i $kid"
                        $CLI key-delete -i "$kid" >/dev/null 2>&1
                        ;;
                    OAEP)
                        for hash in $rsa_enc_hashes; do
                            kid=$((base_id))
                            base_id=$((base_id + 1))
                            $CLI key-delete -i "$kid" >/dev/null 2>&1
                            run_keygen_test \
                                "RSA-${sz}  OAEP-${hash}  encrypt,decrypt  persist" \
                                "RSA" "$sz" "OAEP-${hash}" "encrypt,decrypt" "-i $kid"
                            $CLI key-delete -i "$kid" >/dev/null 2>&1
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
        section_header "Persistent key tests — Key Exchange (PSA) ──────────────────────────┐"
        local IFS=','
        for kt in $kex_kts; do
            local sizes
            sizes=$(key_sizes_for_asym_type "$kt")
            if [ -n "$sizes" ]; then
                local IFS=' '
                for sz in $sizes; do
                    kid=$((base_id))
                    base_id=$((base_id + 1))
                    $CLI key-delete -i "$kid" >/dev/null 2>&1
                    run_keygen_test \
                        "$kt-${sz}  ECDH  derive  persist" \
                        "$kt" "$sz" "ECDH" "derive" "-i $kid"
                    $CLI key-delete -i "$kid" >/dev/null 2>&1
                done
            else
                kid=$((base_id))
                base_id=$((base_id + 1))
                $CLI key-delete -i "$kid" >/dev/null 2>&1
                run_keygen_test \
                    "$kt  ECDH  derive  persist" \
                    "$kt" "" "ECDH" "derive" "-i $kid"
                $CLI key-delete -i "$kid" >/dev/null 2>&1
            fi
        done
        section_footer
    fi
}

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
main() {
    echo "========================================================================"
    echo "  Asymmetric Key Generation Tests — PSA backend"
    echo "========================================================================"

    reset_counters

    discover_and_test
    test_sign_hash_usage
    test_persistent_keys_psa
    test_negative_cases

    print_failure_report
    print_summary

    [ "$FAIL" -eq 0 ]
}

main "$@"
