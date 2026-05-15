#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2026 NXP

"""Convert raw public key bytes exported by C CLI into DER or PEM."""

import argparse
import sys

from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, x25519, x448
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# ── Key type registry ──

EC_CURVES = {
    "SECP_R1":       {192: ec.SECP192R1(), 224: ec.SECP224R1(),
                      256: ec.SECP256R1(), 384: ec.SECP384R1(),
                      521: ec.SECP521R1()},
    "BRAINPOOL_R1":  {256: ec.BrainpoolP256R1(), 384: ec.BrainpoolP384R1(),
                      512: ec.BrainpoolP512R1()},
    "BRAINPOOL_P_R1": {256: ec.BrainpoolP256R1(), 384: ec.BrainpoolP384R1(),
                       512: ec.BrainpoolP512R1()},
}

RAW_KEY_TYPES = {
    "ED25519": ed25519.Ed25519PublicKey,
    "ED448":   ed448.Ed448PublicKey,
    "X25519":  x25519.X25519PublicKey,
    "X448":    x448.X448PublicKey,
}

# Exact raw public-key sizes (bytes) per RFC 8032 / RFC 7748.
_RAW_KEY_SIZES = {
    "ED25519": 32,
    "ED448":   57,
    "X25519":  32,
    "X448":    56,
}


# ── Minimal PKCS#1 RSAPublicKey DER parser (PSA export format) ──

def _der_read_tag_len(data, off):
    tag = data[off]; off += 1
    length = data[off]; off += 1
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(data[off:off + n], "big")
        off += n
    return tag, length, off

def _der_read_integer(data, off):
    tag, length, off = _der_read_tag_len(data, off)
    if tag != 0x02:
        sys.exit("Expected INTEGER tag in RSA PKCS#1 blob")
    val = int.from_bytes(data[off:off + length], "big")
    return val, off + length

def load_rsa_pkcs1(data):
    """SEQUENCE { INTEGER modulus, INTEGER exponent } -> RSA key object."""
    tag, _, off = _der_read_tag_len(data, 0)
    if tag != 0x30:
        sys.exit("Expected SEQUENCE in RSA PKCS#1 blob")
    n, off = _der_read_integer(data, off)
    e, off = _der_read_integer(data, off)
    return RSAPublicNumbers(e, n).public_key()

def load_rsa_components(mod_path, exp_path):
    """Separate modulus + exponent files (SMW export) -> RSA key object."""
    n = int.from_bytes(open(mod_path, "rb").read(), "big")
    e = int.from_bytes(open(exp_path, "rb").read(), "big")
    return RSAPublicNumbers(e, n).public_key()

def load_rsa_components_from_stdin():
    """Read length-prefixed modulus + exponent from stdin."""
    data = sys.stdin.buffer.read()
    mod_len = int.from_bytes(data[:4], "big")
    mod = data[4:4 + mod_len]
    exp = data[4 + mod_len:]
    n = int.from_bytes(mod, "big")
    e = int.from_bytes(exp, "big")
    return RSAPublicNumbers(e, n).public_key()


# ── Generic loader ──

def load_pubkey(key_type, bits, raw, modulus_file=None, exponent_file=None,
                rsa_components=False):
    if key_type in RAW_KEY_TYPES:
        expected = _RAW_KEY_SIZES.get(key_type)
        if expected is not None and len(raw) != expected:
            if len(raw) == expected + 1 and raw[0] == 0x04:
                # Some PSA backends prepend a spurious 0x04 byte
                # print(f"Note: {key_type}: stripping 0x04 prefix "
                #       f"({len(raw)} -> {expected} bytes)",
                #       file=sys.stderr)
                raw = raw[1:]
            elif len(raw) > expected:
                print(f"Note: {key_type}: trimming raw key from "
                      f"{len(raw)} to {expected} bytes",
                      file=sys.stderr)
                raw = raw[:expected]
            else:
                sys.exit(f"{key_type}: raw key too short "
                         f"({len(raw)} < {expected} bytes)")
        return RAW_KEY_TYPES[key_type].from_public_bytes(raw)

    if key_type in EC_CURVES:
        curve = EC_CURVES[key_type].get(bits)
        if not curve:
            sys.exit(f"Unsupported curve: {key_type}/{bits}")
        point = raw if raw[0] == 0x04 else b"\x04" + raw
        return ec.EllipticCurvePublicKey.from_encoded_point(curve, point)

    if key_type == "RSA":
        if modulus_file and exponent_file:
            return load_rsa_components(modulus_file, exponent_file)
        if rsa_components:
            return load_rsa_components_from_stdin()
        return load_rsa_pkcs1(raw)

    sys.exit(f"Unsupported key type: {key_type}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-t", "--type",     required=True)
    ap.add_argument("-b", "--bits",     required=True, type=int)
    ap.add_argument("-i", "--input",    help="Raw key file (default: stdin)")
    ap.add_argument("-o", "--output",   required=True)
    ap.add_argument("-f", "--format",   choices=["der", "pem"], default="pem")
    ap.add_argument("--modulus",        help="RSA modulus file (SMW)")
    ap.add_argument("--exponent",       help="RSA exponent file (SMW)")
    ap.add_argument("--rsa-components", action="store_true",
                    help="Read modulus+exponent from stdin (SMW)")
    args = ap.parse_args()

    if args.modulus and args.exponent:
        key = load_pubkey(args.type.upper(), args.bits, b"",
                          modulus_file=args.modulus,
                          exponent_file=args.exponent)
    elif args.rsa_components:
        key = load_pubkey(args.type.upper(), args.bits, b"",
                          rsa_components=True)
    elif args.input:
        raw = open(args.input, "rb").read()
        key = load_pubkey(args.type.upper(), args.bits, raw)
    else:
        raw = sys.stdin.buffer.read()
        key = load_pubkey(args.type.upper(), args.bits, raw)

    enc = Encoding.PEM if args.format == "pem" else Encoding.DER
    open(args.output, "wb").write(
        key.public_bytes(enc, PublicFormat.SubjectPublicKeyInfo))


if __name__ == "__main__":
    main()
