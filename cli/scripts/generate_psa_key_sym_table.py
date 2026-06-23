#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2026 NXP

"""Generate PSA key type mappings by parsing PSA headers"""

import re
import sys
from datetime import datetime
from pathlib import Path


def parse_psa_constants(header_path):
    with open(header_path, 'r') as f:
        content = f.read()

    constants = {}
    pattern = r'#define\s+(PSA_[A-Z_0-9]+)\s+\(\([a-z_]+\)(0x[0-9A-Fa-f]+)\)'
    for match in re.finditer(pattern, content):
        constants[match.group(1)] = int(match.group(2), 16)
    return constants


def parse_psa_validation_macros(header_path, constants):
    with open(header_path, 'r') as f:
        content = f.read()

    validations = {}
    pattern = (r'#define\s+PSA_ALG_IS_([A-Z_]+)\([^)]+\)\s+[\\]?\s*'
               r'\(\(\([^)]+\)\s*&\s*\(?([A-Z_0-9|&\s]+)\)?\)\s*==\s*[\\]?\s*'
               r'([A-Z_0-9]+)\)')

    for match in re.finditer(pattern, content, re.MULTILINE):
        category      = match.group(1)
        mask_expr     = match.group(2).strip()
        expected_name = match.group(3).strip()

        mask_value     = evaluate_constant_expression(mask_expr, constants)
        expected_value = constants.get(expected_name)

        if mask_value is not None and expected_value is not None:
            validations[category] = (mask_value, expected_value)

    return validations


def evaluate_constant_expression(expr, constants):
    expr = expr.replace('(', '').replace(')', '').strip()
    for name in re.findall(r'PSA_[A-Z_0-9]+', expr):
        if name in constants:
            expr = expr.replace(name, f"0x{constants[name]:08x}")
        else:
            return None
    try:
        return eval(expr)
    except Exception:
        return None


def validate_algorithm(alg_value, category, validations):
    if category not in validations:
        return True
    mask, expected = validations[category]
    return (alg_value & mask) == expected


def parse_psa_key_types_with_tags(header_path):
    with open(header_path, 'r') as f:
        content = f.read()

    key_types = {
        'symmetric': [],
        'cipher': [],
        'aead': [],
        'mac': []
    }

    pattern = (
        r'\*\s*\.\.\s*\[\[([^\]]+)\]\]'
        r'[\s\S]*?'
        r'\*/'
        r'\s*#define\s+(PSA_KEY_TYPE_(\w+))\s+'
    )

    for match in re.finditer(pattern, content):
        tags          = [t.strip() for t in match.group(1).split(',')]
        macro_name    = match.group(2)
        friendly_name = match.group(3)

        info = {'name': friendly_name, 'macro': macro_name, 'tags': tags}

        if 'symmetric' in tags:
            key_types['symmetric'].append(info)
        if 'cipher' in tags:
            key_types['cipher'].append(info)
        if 'aead' in tags:
            key_types['aead'].append(info)
        if 'mac' in tags:
            key_types['mac'].append(info)

    return key_types


def parse_psa_hash_algorithms(header_path, constants):
    with open(header_path, 'r') as f:
        content = f.read()

    hash_algos = []

    hmac_blacklist = [
        'AES_MMO_ZIGBEE', 'MD2', 'MD4', 'RIPEMD160',
        'SHA_512_224', 'SHA_512_256', 'ANY_HASH', 'HASH_EDDSA',
    ]

    pattern = r'#define\s+(PSA_ALG_([A-Z0-9_]+))\s+\(\(psa_algorithm_t\)(0x[0-9A-Fa-f]+)\)'

    for match in re.finditer(pattern, content):
        macro = match.group(1)
        name  = match.group(2)
        value = int(match.group(3), 16)

        hash_category = constants.get('PSA_ALG_CATEGORY_HASH', 0x02000000)
        category_mask = constants.get('PSA_ALG_CATEGORY_MASK', 0x7f000000)

        if (value & category_mask) != hash_category:
            continue
        if any(x in name for x in ['NONE', 'ANY_HASH', 'CATEGORY', 'HASH_MASK', 'SHA3_', 'SHAKE']):
            continue
        if name in hmac_blacklist:
            print(f"  SKIP HMAC({name}): not suitable for HMAC")
            continue

        # SHA_1 -> SHA-1 -> SHA1  (align with SMW naming, no dash)
        display_name = name.replace('_', '-').replace('SHA-', 'SHA')
        hash_algos.append({'name': display_name, 'macro': macro, 'value': value})
        print(f"  HASH for HMAC: {display_name}")

    return hash_algos


def parse_psa_algorithms(header_path, constants, validations):
    with open(header_path, 'r') as f:
        content = f.read()

    algorithms = {'cipher': [], 'aead': [], 'cmac': []}

    category_mask   = constants.get('PSA_ALG_CATEGORY_MASK',   0x7f000000)
    cipher_category = constants.get('PSA_ALG_CATEGORY_CIPHER', 0x04000000)
    aead_category   = constants.get('PSA_ALG_CATEGORY_AEAD',   0x05000000)
    mac_category    = constants.get('PSA_ALG_CATEGORY_MAC',    0x03000000)

    pattern = r'#define\s+(PSA_ALG_([A-Z0-9_]+))\s+\(\(psa_algorithm_t\)(0x[0-9A-Fa-f]+)\)'

    for match in re.finditer(pattern, content):
        macro = match.group(1)
        name  = match.group(2)
        value = int(match.group(3), 16)

        skip_patterns = [
            'BASE', 'FLAG', 'MASK', 'OFFSET', 'NONE', 'VENDOR', 'CATEGORY',
            'ANY_HASH', 'HASH_EDDSA', 'DETERMINISTIC_ECDSA', 'ECDSA',
            'HMAC', 'HKDF', 'RSA_', 'PBKDF2', 'TLS12', 'PURE_EDDSA',
        ]
        if any(x in name for x in skip_patterns):
            continue

        display_name = name.replace('_NO_PADDING', '').replace('_', '-')
        algo_info = {'name': display_name, 'macro': macro, 'value': value}

        algo_category = value & category_mask

        if algo_category == cipher_category:
            if validate_algorithm(value, 'CIPHER', validations):
                algorithms['cipher'].append(algo_info)
                print(f"  CIPHER: {display_name}")
        elif algo_category == aead_category:
            if validate_algorithm(value, 'AEAD', validations):
                algorithms['aead'].append(algo_info)
                print(f"  AEAD: {display_name}")
        elif algo_category == mac_category:
            if validate_algorithm(value, 'MAC', validations):
                algorithms['cmac'].append(algo_info)
                print(f"  CMAC: {display_name}")

    return algorithms


def get_cmac_key_types(key_types):
    seen = set()
    result = []
    for kt in key_types['mac']:
        if kt['name'] == 'HMAC':
            continue
        if kt['name'] not in seen:
            seen.add(kt['name'])
            result.append(kt)
    return result


def dedup_list(items):
    seen = set()
    result = []
    for item in items:
        if item['name'] not in seen:
            seen.add(item['name'])
            result.append(item)
    return result


def generate_header_file():
    year = datetime.now().year
    return f"""// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright {year} NXP
 */

/* AUTO-GENERATED FILE - DO NOT EDIT */

#ifndef PSA_SYM_KEY_MAPPINGS_GENERATED_H
#define PSA_SYM_KEY_MAPPINGS_GENERATED_H

/*
 * All declarations are provided by key_sym_mappings.h.
 * This file intentionally left with no additional declarations.
 */

#endif /* PSA_SYM_KEY_MAPPINGS_GENERATED_H */
"""


def generate_c_file(key_types, algorithms, hash_algos, cmac_key_types):
    year = datetime.now().year

    def kt_entries(lst):
        return ''.join(
            f'\t{{ "{k["name"]}", (uint32_t){k["macro"]} }},\n'
            for k in lst)

    def algo_entries(lst):
        return ''.join(
            f'\t{{ "{a["name"]}", (uint32_t){a["macro"]} }},\n'
            for a in lst)

    def str_entries(lst):
        return ''.join(f'\t"{k["name"]}",\n' for k in lst)

    def hmac_entries(lst):
        return ''.join(
            f'\t{{ "{h["name"]}", (uint32_t)PSA_ALG_HMAC({h["macro"]}) }},\n'
            for h in lst)

    cipher_dedup = dedup_list(key_types['cipher'])
    aead_dedup   = dedup_list(key_types['aead'])
    cmac_dedup   = dedup_list(cmac_key_types)

    return f"""// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright {year} NXP
 */

/* AUTO-GENERATED FILE - DO NOT EDIT */

#include <stddef.h>
#include <string.h>
#include <strings.h>
#include <psa/crypto.h>

#include "key_sym_mappings.h"

static const struct key_type_mapping psa_key_types[] = {{
{kt_entries(dedup_list(key_types['symmetric']))}
}};

static const struct algo_mapping psa_cipher_algos[] = {{
{algo_entries(algorithms['cipher'])}
}};

static const struct algo_mapping psa_aead_algos[] = {{
{algo_entries(algorithms['aead'])}
}};

/* Block-cipher MAC modes (CMAC, CBC-MAC ...) */
static const struct algo_mapping psa_cmac_algos[] = {{
{algo_entries(algorithms['cmac'])}
}};

/* HMAC: hash algorithms */
static const struct algo_mapping psa_hmac_hash_algos[] = {{
{hmac_entries(hash_algos)}
}};

static const char *psa_cipher_key_types[] = {{
{str_entries(cipher_dedup)}
}};

static const char *psa_aead_key_types[] = {{
{str_entries(aead_dedup)}
}};

static const char *psa_cmac_key_types[] = {{
{str_entries(cmac_dedup)}
}};

/* -----------------------------------------------------------------------
 * key_sym_mappings.h interface implementation
 * -------------------------------------------------------------------- */

const struct key_type_mapping *get_key_type_mappings(void)
{{
\treturn psa_key_types;
}}

size_t get_key_type_mappings_count(void)
{{
\treturn sizeof(psa_key_types) / sizeof(psa_key_types[0]);
}}

const struct algo_mapping *get_cipher_algo_mappings(void)
{{
\treturn psa_cipher_algos;
}}

size_t get_cipher_algo_mappings_count(void)
{{
\treturn sizeof(psa_cipher_algos) / sizeof(psa_cipher_algos[0]);
}}

const struct algo_mapping *get_aead_algo_mappings(void)
{{
\treturn psa_aead_algos;
}}

size_t get_aead_algo_mappings_count(void)
{{
\treturn sizeof(psa_aead_algos) / sizeof(psa_aead_algos[0]);
}}

const struct algo_mapping *get_cmac_algo_mappings(void)
{{
\treturn psa_cmac_algos;
}}

size_t get_cmac_algo_mappings_count(void)
{{
\treturn sizeof(psa_cmac_algos) / sizeof(psa_cmac_algos[0]);
}}

const struct algo_mapping *get_hmac_hash_algo_mappings(void)
{{
\treturn psa_hmac_hash_algos;
}}

size_t get_hmac_hash_algo_mappings_count(void)
{{
\treturn sizeof(psa_hmac_hash_algos) / sizeof(psa_hmac_hash_algos[0]);
}}

const char **get_cipher_key_types(size_t *count)
{{
\t*count = sizeof(psa_cipher_key_types) / sizeof(psa_cipher_key_types[0]);
\treturn psa_cipher_key_types;
}}

const char **get_aead_key_types(size_t *count)
{{
\t*count = sizeof(psa_aead_key_types) / sizeof(psa_aead_key_types[0]);
\treturn psa_aead_key_types;
}}

const char **get_cmac_key_types(size_t *count)
{{
\t*count = sizeof(psa_cmac_key_types) / sizeof(psa_cmac_key_types[0]);
\treturn psa_cmac_key_types;
}}

int parse_key_type(const char *str, uint32_t *value)
{{
\tsize_t i;
\tsize_t count = sizeof(psa_key_types) / sizeof(psa_key_types[0]);

\tif (!str || !value)
\t\treturn -1;

\tfor (i = 0; i < count; i++) {{
\t\tif (psa_key_types[i].name &&
\t\t    !strcasecmp(str, psa_key_types[i].name)) {{
\t\t\t*value = psa_key_types[i].value;
\t\t\treturn 0;
\t\t}}
\t}}
\treturn -1;
}}

const char *key_type_to_string(uint32_t value)
{{
\tsize_t i;
\tsize_t count = sizeof(psa_key_types) / sizeof(psa_key_types[0]);

\tfor (i = 0; i < count; i++) {{
\t\tif (psa_key_types[i].value == value)
\t\t\treturn psa_key_types[i].name;
\t}}
\treturn NULL;
}}

int parse_single_algorithm(const char *algo_str, uint32_t key_type_value,
\t\t\t   uint32_t *algo_value)
{{
\tsize_t i;
\tsize_t count;
\tconst char *key_type_name;

\tif (!algo_str || !algo_value)
\t\treturn -1;

\tkey_type_name = key_type_to_string(key_type_value);

\t/* HMAC: search hash algorithm table */
\tif (key_type_name && !strcasecmp(key_type_name, "HMAC")) {{
\t\tcount = sizeof(psa_hmac_hash_algos) / sizeof(psa_hmac_hash_algos[0]);
\t\tfor (i = 0; i < count; i++) {{
\t\t\tif (psa_hmac_hash_algos[i].name &&
\t\t\t    !strcasecmp(algo_str, psa_hmac_hash_algos[i].name)) {{
\t\t\t\t*algo_value = psa_hmac_hash_algos[i].value;
\t\t\t\treturn 0;
\t\t\t}}
\t\t}}
\t\treturn -1;
\t}}

\t/* MAC modes (CMAC ...) */
\tcount = sizeof(psa_cmac_algos) / sizeof(psa_cmac_algos[0]);
\tfor (i = 0; i < count; i++) {{
\t\tif (psa_cmac_algos[i].name &&
\t\t    !strcasecmp(algo_str, psa_cmac_algos[i].name)) {{
\t\t\t*algo_value = psa_cmac_algos[i].value;
\t\t\treturn 0;
\t\t}}
\t}}

\t/* AEAD modes */
\tcount = sizeof(psa_aead_algos) / sizeof(psa_aead_algos[0]);
\tfor (i = 0; i < count; i++) {{
\t\tif (psa_aead_algos[i].name &&
\t\t    !strcasecmp(algo_str, psa_aead_algos[i].name)) {{
\t\t\t*algo_value = psa_aead_algos[i].value;
\t\t\treturn 0;
\t\t}}
\t}}

\t/* Cipher modes */
\tcount = sizeof(psa_cipher_algos) / sizeof(psa_cipher_algos[0]);
\tfor (i = 0; i < count; i++) {{
\t\tif (psa_cipher_algos[i].name &&
\t\t    !strcasecmp(algo_str, psa_cipher_algos[i].name)) {{
\t\t\t*algo_value = psa_cipher_algos[i].value;
\t\t\treturn 0;
\t\t}}
\t}}

\treturn -1;
}}
"""


def main():
    if len(sys.argv) < 2:
        print("ERROR: Output directory required", file=sys.stderr)
        sys.exit(1)

    output_dir = Path(sys.argv[1])
    script_dir = Path(__file__).parent
    repo_root  = script_dir.parent.parent

    psa_header = repo_root / "public" / "psa" / "crypto_values.h"
    if not psa_header.exists():
        print(f"ERROR: PSA header not found: {psa_header}", file=sys.stderr)
        sys.exit(1)

    print(f"Parsing {psa_header}...")

    constants   = parse_psa_constants(psa_header)
    validations = parse_psa_validation_macros(psa_header, constants)
    key_types   = parse_psa_key_types_with_tags(psa_header)
    algorithms  = parse_psa_algorithms(psa_header, constants, validations)
    hash_algos  = parse_psa_hash_algorithms(psa_header, constants)
    cmac_kt     = get_cmac_key_types(key_types)

    print(f"\n=== SUMMARY ===")
    print(f"Symmetric key types : {len(key_types['symmetric'])}")
    print(f"Cipher key types    : {len(key_types['cipher'])}")
    print(f"AEAD key types      : {len(key_types['aead'])}")
    print(f"CMAC key types      : {[k['name'] for k in cmac_kt]}")
    print(f"Cipher modes        : {len(algorithms['cipher'])}")
    print(f"AEAD modes          : {len(algorithms['aead'])}")
    print(f"CMAC modes          : {len(algorithms['cmac'])}")
    print(f"HMAC hash algos     : {len(hash_algos)}")

    output_c = output_dir / "psa_sym_key_mappings_generated.c"
    output_h = output_dir / "psa_sym_key_mappings_generated.h"
    output_c.parent.mkdir(parents=True, exist_ok=True)

    with open(output_h, 'w') as f:
        f.write(generate_header_file())

    with open(output_c, 'w') as f:
        f.write(generate_c_file(key_types, algorithms, hash_algos, cmac_kt))

    print(f"\nGenerated {output_h}")
    print(f"Generated {output_c}")


if __name__ == "__main__":
    main()