#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2026 NXP

"""Generate SMW asymmetric key type mappings by parsing SMW headers dynamically"""

import re
import sys
from datetime import datetime
from pathlib import Path


def parse_curve_definitions(attr_h_path):
    with open(attr_h_path, 'r') as f:
        content = f.read()
    curves = {}
    pattern = r'#define\s+(SMW_ATTR_CURVE_(\w+))\s+'
    for match in re.finditer(pattern, content):
        macro_name = match.group(1)
        curve_name = match.group(2)
        if curve_name in ['NONE', 'ANY']:
            continue
        curves[curve_name] = macro_name
    return curves


def infer_curve_from_key_type(key_type_name, available_curves):
    normalized_key = key_type_name.upper().replace('-', '_')
    if normalized_key in available_curves:
        return available_curves[normalized_key]
    for curve_name, curve_macro in available_curves.items():
        if curve_name in normalized_key:
            return curve_macro
    for curve_name, curve_macro in available_curves.items():
        if normalized_key in curve_name:
            return curve_macro
    key_match = re.search(r'(\d+)', normalized_key)
    if key_match:
        key_number = key_match.group(1)
        for curve_name in available_curves:
            if key_number in curve_name:
                return available_curves[curve_name]
    return "SMW_ATTR_CURVE_NONE"


def sanitize_mode_name_for_cli(mode_name):
    if mode_name == "PKCS1-1-5":
        return "PKCS1V15"
    if mode_name == "NO-PAD":
        return "NOPAD"
    return mode_name


def sanitize_hash_name_for_cli(hash_name):
    hash_name = re.sub(r'SHA3-(\d)', r'SHA3_\1', hash_name)
    hash_name = re.sub(r'SHA512-(\d)', r'SHA512_\1', hash_name)
    return hash_name


def parse_tags(tags_str):
    result = {'flags': []}
    parts = [part.strip() for part in tags_str.split(',')]
    for part in parts:
        if ':' in part:
            key, value = part.split(':', 1)
            result[key.strip()] = value.strip()
        else:
            result['flags'].append(part.strip())
    return result


def parse_asymmetric_key_types(names_h_path, attr_h_path):
    available_curves = parse_curve_definitions(attr_h_path)
    with open(names_h_path, 'r') as f:
        content = f.read()
    key_types = []
    pattern = r'(SMW_KEY_TYPE_NAME_(\w+))\s*,\s*/\*\s*\[([^\]]+)\]\s*\*/'
    for match in re.finditer(pattern, content):
        macro_name = match.group(1)
        friendly   = match.group(2)
        tags_str   = match.group(3)
        tags       = parse_tags(tags_str)
        if 'asymmetric' not in tags['flags']:
            continue
        fixed_size  = int(tags['size']) if 'size' in tags else 0
        curve_macro = infer_curve_from_key_type(friendly, available_curves)
        key_types.append({
            'name':       friendly,
            'macro':      macro_name,
            'fixed_size': fixed_size,
            'curve':      curve_macro,
            'tags':       tags
        })
    return key_types


def categorize_key_types(key_types):
    categories = {
        'rsa_sig':      [],
        'ecdsa_sig':    [],
        'eddsa_sig':    [],
        'dsa_sig':      [],
        'rsa_enc':      [],
        'key_exchange': [],
    }
    for kt in key_types:
        flags = kt['tags']['flags']
        if 'signature' in flags:
            if 'ecdsa' in flags:
                categories['ecdsa_sig'].append(kt)
            elif 'eddsa' in flags:
                categories['eddsa_sig'].append(kt)
            elif 'dsa' in flags:
                categories['dsa_sig'].append(kt)
            else:
                categories['rsa_sig'].append(kt)
        if 'encryption' in flags:
            categories['rsa_enc'].append(kt)
        if 'key_ex' in flags:
            categories['key_exchange'].append(kt)
    return categories


def parse_eddsa_algorithms(attr_h_path):
    with open(attr_h_path, 'r') as f:
        content = f.read()
    eddsa_algos = []
    pattern = r'#define\s+(SMW_ATTR_SIGN_PARAM_EDDSA_(\w+))\s+0x([0-9A-Fa-f]+)'
    for match in re.finditer(pattern, content):
        macro_name   = match.group(1)
        variant_name = match.group(2)
        if variant_name == 'NONE':
            variant_name = 'PURE'
        cli_name = 'EDDSA-{}'.format(variant_name.replace('_', '-'))
        eddsa_algos.append({'name': cli_name, 'macro': macro_name})
    return eddsa_algos


def _kdf_cli_name(macro_name):
    """Convert SMW macro name to CLI KDF/TLS name."""
    mapping = {
        'SMW_ATTR_ALGO_HKDF':    'HKDF',
        'SMW_ATTR_ALGO_TLS_1_2': 'TLS12',
        'SMW_ATTR_ALGO_TLS_1_3': 'TLS13',
        'SMW_ATTR_ALGO_ECDH':    'ECDH',
        'SMW_ATTR_ALGO_DH':      'DH',
    }
    return mapping.get(macro_name, macro_name.replace('SMW_ATTR_ALGO_', ''))


def parse_kdf_algorithms(attr_h_path):
    """Parse KDF and TLS algorithm definitions from attr.h.

    Tag vocabulary:
      tls → TLS key derivation (TLS12, TLS13)
      kdf → all KDF algorithms (HKDF, ECDH, DH)

    The has_hash field is detected by checking if the macro
    definition contains a hash_alg parameter or equivalent.
    """
    with open(attr_h_path, 'r') as f:
        content = f.read()

    tls_algos = []
    kdf_algos = []
    seen = set()

    # Pattern: #define SMW_ATTR_ALGO_xxx value /* [tags] */
    pattern = (
        r'#define\s+(SMW_ATTR_ALGO_(\w+))\s+(\S+)'
        r'\s*/\*\s*\[([^\]]+)\]\s*\*/'
    )

    for match in re.finditer(pattern, content):
        macro_name    = match.group(1)
        tags_str      = match.group(4)
        tags          = parse_tags(tags_str)
        flags         = tags.get('flags', [])

        is_tls = 'tls' in flags
        is_kdf = 'kdf' in flags

        if not is_tls and not is_kdf:
            continue
        if macro_name in seen:
            continue
        seen.add(macro_name)

        # Detect if this algo needs a hash component
        # SMW KDFs that take a hash have 'hash_based' tag or
        # we detect by checking known hash-based algos
        has_hash = 'hash_based' in flags

        entry = {
            'name':     _kdf_cli_name(macro_name),
            'macro':    macro_name,
            'has_hash': has_hash,
        }

        if is_tls:
            tls_algos.append(entry)
        else:
            kdf_algos.append(entry)

    return tls_algos, kdf_algos


def parse_asymmetric_modes(attr_h_path):
    with open(attr_h_path, 'r') as f:
        content = f.read()
    modes = {'signature': [], 'encryption': []}
    pattern = r'#define\s+(SMW_ATTR_MODE_(\w+))\s+\S+\s*/\*\s*\[([^\]]+)\]\s*\*/'
    for match in re.finditer(pattern, content):
        macro_name    = match.group(1)
        friendly_name = match.group(2).replace('_', '-')
        tags          = parse_tags(match.group(3))
        if 'asym_sign' not in tags['flags'] and 'asym_encr' not in tags['flags']:
            continue
        cli_name  = sanitize_mode_name_for_cli(friendly_name)
        mode_info = {'name': cli_name, 'macro': macro_name, 'tags': tags}
        if 'asym_sign' in tags['flags']:
            modes['signature'].append(mode_info)
        if 'asym_encr' in tags['flags']:
            modes['encryption'].append(mode_info)
    return modes


def parse_hash_algorithms(attr_h_path):
    with open(attr_h_path, 'r') as f:
        content = f.read()
    hash_algos = []
    pattern = r'#define\s+(SMW_ATTR_HASH_(\w+))\s+\S+'
    skip = {'NONE', 'OFFSET', 'MASK', 'SHAKE128', 'SHAKE256', 'SHA1', 'SM3', 'MD5'}
    for match in re.finditer(pattern, content):
        macro_name    = match.group(1)
        friendly_name = match.group(2)
        if friendly_name in skip:
            continue
        cli_name = sanitize_hash_name_for_cli(
            friendly_name.replace('_', '-'))
        hash_algos.append({'name': cli_name, 'macro': macro_name})
    return hash_algos


# -------------------------------------------------------------------------
# Code generation
# -------------------------------------------------------------------------

def _file_header():
    year = datetime.now().year
    return (
        "// SPDX-License-Identifier: BSD-3-Clause\n"
        "/*\n * Copyright {} NXP\n */\n\n".format(year) +
        "/* AUTO-GENERATED FILE - DO NOT EDIT */\n\n"
    )


def _emit_key_type_entry(kt):
    return '\t{{ "{}", (uint32_t){}, {}u, (uint64_t){} }},\n'.format(
        kt["name"], kt["macro"], kt["fixed_size"], kt["curve"])


def _algo_value(entry):
    """Return the C value expression for an algo table entry."""
    if entry['has_hash']:
        return f'(uint64_t){entry["macro"]}_BASE'
    return f'(uint64_t){entry["macro"]}'


def generate_c_file(key_types, modes, hash_algos, eddsa_algos,
                    tls_algos, kdf_algos):
    categories = categorize_key_types(key_types)

    out  = _file_header()
    out += "#include <stddef.h>\n"
    out += "#include <stdint.h>\n"
    out += "#include <stdbool.h>\n"
    out += "#include <string.h>\n"
    out += "#include <strings.h>\n"
    out += "#include <smw/attr.h>\n"
    out += "#include <smw_keymgr.h>\n"
    out += '#include "key_asym_mappings.h"\n\n'

    # ---- main key types table ----------------------------------------
    out += "static const struct asym_key_type_mapping asym_key_types[] = {\n"
    for kt in key_types:
        out += _emit_key_type_entry(kt)
    out += "};\n\n"

    # ---- sign mode table ---------------------------------------------
    out += "static const struct asym_algo_mapping asym_sign_modes[] = {\n"
    for m in modes['signature']:
        out += '\t{{ "{}", (uint64_t){} }},\n'.format(m["name"], m["macro"])
    out += "};\n\n"

    # ---- encrypt mode table ------------------------------------------
    out += "static const struct asym_algo_mapping asym_encrypt_modes[] = {\n"
    for m in modes['encryption']:
        out += '\t{{ "{}", (uint64_t){} }},\n'.format(m["name"], m["macro"])
    out += "};\n\n"

    # ---- hash algo table ---------------------------------------------
    out += "static const struct asym_algo_mapping asym_hash_algos[] = {\n"
    for h in hash_algos:
        out += '\t{{ "{}", (uint64_t){} }},\n'.format(h["name"], h["macro"])
    out += "};\n\n"

    # ---- EdDSA algo table --------------------------------------------
    out += "static const struct asym_algo_mapping asym_eddsa_algos[] = {\n"
    for algo in eddsa_algos:
        out += '\t{{ "{}", (uint64_t){} }},\n'.format(
            algo["name"], algo["macro"])
    out += "};\n\n"

    # ---- TLS algo table ----------------------------------------------
    out += "static const struct asym_algo_mapping asym_tls_algos[] = {\n"
    for tls in tls_algos:
        out += '\t{{ "{}", {} }},\n'.format(tls["name"], _algo_value(tls))
    out += "};\n\n"

    # ---- KDF algo table ----------------------------------------------
    out += "static const struct asym_algo_mapping asym_kdf_algos[] = {\n"
    for kdf in kdf_algos:
        out += '\t{{ "{}", {} }},\n'.format(kdf["name"], _algo_value(kdf))
    out += "};\n\n"

    # ---- categorized sub-tables --------------------------------------
    cat_info = [
        ('rsa_sig',      'asym_rsa_sig_types'),
        ('ecdsa_sig',    'asym_ecdsa_sig_types'),
        ('eddsa_sig',    'asym_eddsa_sig_types'),
        ('dsa_sig',      'asym_dsa_sig_types'),
        ('rsa_enc',      'asym_rsa_enc_types'),
        ('key_exchange', 'asym_key_exchange_types'),
    ]
    for cat_key, arr_name in cat_info:
        out += "static const struct asym_key_type_mapping {}[] = {{\n".format(
            arr_name)
        for kt in categories[cat_key]:
            out += _emit_key_type_entry(kt)
        out += "};\n\n"

    # ---- getter functions for key type tables ------------------------
    out += (
        "const struct asym_key_type_mapping *get_asym_key_type_mappings(void)\n"
        "{\n"
        "\treturn asym_key_types;\n"
        "}\n\n"
        "size_t get_asym_key_type_mappings_count(void)\n"
        "{\n"
        "\treturn sizeof(asym_key_types) / sizeof(asym_key_types[0]);\n"
        "}\n\n"
    )

    key_type_getter_pairs = [
        ('get_rsa_sig_key_types',      'get_rsa_sig_key_types_count',
         'asym_rsa_sig_types'),
        ('get_ecdsa_sig_key_types',    'get_ecdsa_sig_key_types_count',
         'asym_ecdsa_sig_types'),
        ('get_eddsa_sig_key_types',    'get_eddsa_sig_key_types_count',
         'asym_eddsa_sig_types'),
        ('get_dsa_sig_key_types',      'get_dsa_sig_key_types_count',
         'asym_dsa_sig_types'),
        ('get_rsa_enc_key_types',      'get_rsa_enc_key_types_count',
         'asym_rsa_enc_types'),
        ('get_key_exchange_key_types', 'get_key_exchange_key_types_count',
         'asym_key_exchange_types'),
    ]
    for getter, counter, arr in key_type_getter_pairs:
        out += (
            "const struct asym_key_type_mapping *{}(void)\n"
            "{{\n"
            "\treturn {};\n"
            "}}\n\n"
            "size_t {}(void)\n"
            "{{\n"
            "\tif (!{}[0].name)\n"
            "\t\treturn 0;\n"
            "\treturn sizeof({}) / sizeof({}[0]);\n"
            "}}\n\n"
        ).format(getter, arr, counter, arr, arr, arr)

    # ---- getter functions for algo tables ----------------------------
    algo_getter_pairs = [
        ('get_sign_mode_mappings',      'get_sign_mode_mappings_count',
         'asym_sign_modes'),
        ('get_encrypt_mode_mappings',   'get_encrypt_mode_mappings_count',
         'asym_encrypt_modes'),
        ('get_sign_hash_algo_mappings', 'get_sign_hash_algo_mappings_count',
         'asym_hash_algos'),
        ('get_eddsa_algo_mappings',     'get_eddsa_algo_mappings_count',
         'asym_eddsa_algos'),
        ('get_tls_algo_mappings',       'get_tls_algo_mappings_count',
         'asym_tls_algos'),
        ('get_kdf_algo_mappings',       'get_kdf_algo_mappings_count',
         'asym_kdf_algos'),
    ]
    for getter, counter, arr in algo_getter_pairs:
        out += (
            "const struct asym_algo_mapping *{}(void)\n"
            "{{\n"
            "\treturn {};\n"
            "}}\n\n"
            "size_t {}(void)\n"
            "{{\n"
            "\treturn sizeof({}) / sizeof({}[0]);\n"
            "}}\n\n"
        ).format(getter, arr, counter, arr, arr)

    # ---- parse_asym_key_type -----------------------------------------
    out += (
        "int parse_asym_key_type(const char *str, uint32_t *fixed_size,\n"
        "\t\t\tuint32_t *value)\n"
        "{\n"
        "\tsize_t i;\n"
        "\tsize_t count = get_asym_key_type_mappings_count();\n"
        "\tconst struct asym_key_type_mapping *tbl = get_asym_key_type_mappings();\n"
        "\n"
        "\tif (!str || !fixed_size || !value)\n"
        "\t\treturn -1;\n"
        "\n"
        "\tfor (i = 0; i < count; i++) {\n"
        "\t\tif (tbl[i].name && !strcasecmp(str, tbl[i].name)) {\n"
        "\t\t\t*value      = tbl[i].value;\n"
        "\t\t\t*fixed_size = tbl[i].fixed_size;\n"
        "\t\t\treturn 0;\n"
        "\t\t}\n"
        "\t}\n"
        "\treturn -1;\n"
        "}\n\n"
    )

    # ---- asym_key_type_to_string -------------------------------------
    out += (
        "const char *asym_key_type_to_string(uint32_t value)\n"
        "{\n"
        "\tsize_t i;\n"
        "\tsize_t count = get_asym_key_type_mappings_count();\n"
        "\tconst struct asym_key_type_mapping *tbl = get_asym_key_type_mappings();\n"
        "\n"
        "\tfor (i = 0; i < count; i++) {\n"
        "\t\tif (tbl[i].value == value)\n"
        "\t\t\treturn tbl[i].name;\n"
        "\t}\n"
        "\treturn \"UNKNOWN\";\n"
        "}\n\n"
    )

    # ---- get_asym_curve ----------------------------------------------
    out += (
        "uint64_t get_asym_curve(uint32_t value)\n"
        "{\n"
        "\tsize_t i;\n"
        "\tsize_t count = get_asym_key_type_mappings_count();\n"
        "\tconst struct asym_key_type_mapping *tbl = get_asym_key_type_mappings();\n"
        "\n"
        "\tfor (i = 0; i < count; i++) {\n"
        "\t\tif (tbl[i].value == value)\n"
        "\t\t\treturn tbl[i].curve;\n"
        "\t}\n"
        "\treturn 0;\n"
        "}\n\n"
    )

    # ---- parse helpers -----------------------------------------------
    for fn, getter, counter in [
        ('parse_sign_mode',    'get_sign_mode_mappings',
         'get_sign_mode_mappings_count'),
        ('parse_encrypt_mode', 'get_encrypt_mode_mappings',
         'get_encrypt_mode_mappings_count'),
        ('parse_sign_hash',    'get_sign_hash_algo_mappings',
         'get_sign_hash_algo_mappings_count'),
    ]:
        out += (
            "uint64_t {}(const char *str)\n"
            "{{\n"
            "\tsize_t i;\n"
            "\tsize_t count = {}();\n"
            "\tconst struct asym_algo_mapping *tbl = {}();\n"
            "\n"
            "\tif (!str)\n"
            "\t\treturn 0;\n"
            "\n"
            "\tfor (i = 0; i < count; i++) {{\n"
            "\t\tif (tbl[i].name && !strcasecmp(str, tbl[i].name))\n"
            "\t\t\treturn tbl[i].value;\n"
            "\t}}\n"
            "\treturn 0;\n"
            "}}\n\n"
        ).format(fn, counter, getter)

    # ---- category check helpers --------------------------------------
    cat_checks = [
        ('is_asym_rsa_sig_type',   'get_rsa_sig_key_types',
         'get_rsa_sig_key_types_count'),
        ('is_asym_rsa_enc_type',   'get_rsa_enc_key_types',
         'get_rsa_enc_key_types_count'),
        ('is_asym_ecdsa_sig_type', 'get_ecdsa_sig_key_types',
         'get_ecdsa_sig_key_types_count'),
        ('is_asym_eddsa_sig_type', 'get_eddsa_sig_key_types',
         'get_eddsa_sig_key_types_count'),
        ('is_asym_dsa_sig_type',   'get_dsa_sig_key_types',
         'get_dsa_sig_key_types_count'),
        ('is_asym_key_ex_type',    'get_key_exchange_key_types',
         'get_key_exchange_key_types_count'),
    ]
    for fn, getter, counter in cat_checks:
        out += (
            "bool {}(const char *type_str)\n"
            "{{\n"
            "\tsize_t i;\n"
            "\tsize_t count = {}();\n"
            "\tconst struct asym_key_type_mapping *tbl = {}();\n"
            "\n"
            "\tif (!type_str)\n"
            "\t\treturn false;\n"
            "\n"
            "\tfor (i = 0; i < count; i++) {{\n"
            "\t\tif (tbl[i].name && !strcasecmp(type_str, tbl[i].name))\n"
            "\t\t\treturn true;\n"
            "\t}}\n"
            "\treturn false;\n"
            "}}\n\n"
        ).format(fn, counter, getter)

    return out


def generate_h_file():
    out  = _file_header()
    out += "#ifndef SMW_ASYM_KEY_MAPPINGS_GENERATED_H\n"
    out += "#define SMW_ASYM_KEY_MAPPINGS_GENERATED_H\n\n"
    out += "/* All declarations are in key_asym_mappings.h */\n"
    out += '#include "key_asym_mappings.h"\n\n'
    out += "#endif /* SMW_ASYM_KEY_MAPPINGS_GENERATED_H */\n"
    return out


def main():
    if len(sys.argv) < 2:
        print("Usage: {} <output_dir>".format(sys.argv[0]))
        sys.exit(1)

    output_dir   = Path(sys.argv[1])
    repo_root    = Path(__file__).resolve().parents[2]
    names_h_path = repo_root / "public" / "smw" / "names.h"
    attr_h_path  = repo_root / "public" / "smw" / "attr.h"

    print("Parsing {}".format(names_h_path))
    print("Parsing {}".format(attr_h_path))

    key_types    = parse_asymmetric_key_types(str(names_h_path),
                                              str(attr_h_path))
    modes        = parse_asymmetric_modes(str(attr_h_path))
    hash_algos   = parse_hash_algorithms(str(attr_h_path))
    eddsa_algos  = parse_eddsa_algorithms(str(attr_h_path))
    tls_algos, kdf_algos = parse_kdf_algorithms(str(attr_h_path))

    print("Found {} asymmetric key types".format(len(key_types)))
    print("Found {} signature modes".format(len(modes['signature'])))
    print("Found {} encryption modes".format(len(modes['encryption'])))
    print("Found {} hash algorithms".format(len(hash_algos)))
    print("Found {} EdDSA variants".format(len(eddsa_algos)))
    print("Found {} TLS algorithms".format(len(tls_algos)))
    print("Found {} KDF algorithms".format(len(kdf_algos)))

    c_path = output_dir / "smw_asym_key_mappings_generated.c"
    h_path = output_dir / "smw_asym_key_mappings_generated.h"

    c_path.write_text(generate_c_file(key_types, modes, hash_algos,
                                      eddsa_algos, tls_algos, kdf_algos))
    h_path.write_text(generate_h_file())

    print("Generated {}".format(c_path))
    print("Generated {}".format(h_path))


if __name__ == "__main__":
    main()
