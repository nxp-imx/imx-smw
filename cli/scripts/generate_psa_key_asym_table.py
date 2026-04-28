#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2026 NXP

"""Generate PSA asymmetric key type mappings by parsing PSA headers.
   Generates the same key_asym_mappings.h interface as the SMW backend.
"""

import re
import sys
from datetime import datetime
from pathlib import Path


def normalize_hash_name(psa_macro_name):
    """Normalize PSA hash macro name to CLI format."""
    name = psa_macro_name.replace('PSA_ALG_', '')

    if name.startswith('SHA_512_'):
        variant = name.replace('SHA_512_', '')
        return f'SHA512-{variant}'
    elif name.startswith('SHA_') and not name.startswith('SHA3_'):
        return name.replace('_', '')
    elif name.startswith('SHA3_'):
        return name
    else:
        return name


def parse_tags(tags_str):
    """Parse tag string into a dictionary."""
    result = {'flags': []}
    parts = []
    current = ''
    in_value = False

    for char in tags_str:
        if char == ':':
            in_value = True
            current += char
        elif char == ',' and in_value:
            current += char
        elif char == ' ' and in_value and current.endswith(','):
            in_value = False
            parts.append(current.strip().rstrip(','))
            current = ''
        elif char == ',':
            parts.append(current.strip())
            current = ''
            in_value = False
        else:
            current += char

    if current.strip():
        parts.append(current.strip())

    for part in parts:
        part = part.strip()
        if ':' in part:
            key, value = part.split(':', 1)
            result[key.strip()] = value.strip()
        else:
            result['flags'].append(part.strip())

    return result


def parse_ecc_families(values_h_path):
    """Parse ECC families with capability tags from crypto_values.h."""
    with open(values_h_path, 'r') as f:
        content = f.read()

    families = []
    seen = set()
    doc_blocks = re.split(r'/\*\*', content)

    for block in doc_blocks:
        doc_match = re.search(
            r'\*\s*(?:DOC:\s*)?(PSA_ECC_FAMILY_(\w+))', block)
        if not doc_match:
            continue

        macro_name = doc_match.group(1)
        family_name = doc_match.group(2)

        if macro_name in seen:
            continue

        tags_match = re.search(r'\*\s*\.\.\s*\[\[([^\]]+)\]\]', block)
        if not tags_match:
            continue

        seen.add(macro_name)
        tags = parse_tags(tags_match.group(1))

        families.append({
            'name': family_name,
            'macro': macro_name,
            'tags': tags
        })

    return families


def parse_eddsa_algorithms(values_h_path):
    """Parse EdDSA algorithm definitions from crypto_values.h.

    Derives pure/prehashed and curve directly from the macro name:
      PSA_ALG_PURE_EDDSA  -> EDDSA-PURE   (curve-agnostic)
      PSA_ALG_ED25519PH   -> EDDSA-PREHASHED-ED25519
      PSA_ALG_ED448PH     -> EDDSA-PREHASHED-ED448

    The user always types 'EDDSA-PREHASHED' on the CLI; the curve suffix
    is resolved internally using the -t key type.
    """
    with open(values_h_path, 'r') as f:
        content = f.read()

    eddsa_algos = []
    seen_cli_names = set()

    pattern = (r'#define\s+(PSA_ALG_\w+)\s+\(\(psa_algorithm_t\)'
                r'0x[0-9A-Fa-f]+\)\s*\n\s*/\*\s*\.\.\s*\[\[([^\]]+)\]\]\s*\*/')

    for match in re.finditer(pattern, content):
        macro_name = match.group(1)
        tags_str = match.group(2)
        tags = parse_tags(tags_str)

        if 'eddsa' not in tags['flags']:
            continue

        if macro_name == 'PSA_ALG_PURE_EDDSA':
            cli_name = 'EDDSA-PURE'
            if cli_name not in seen_cli_names:
                seen_cli_names.add(cli_name)
                eddsa_algos.append({
                    'name': cli_name,
                    'macro': macro_name,
                    'curve': None,
                })
        elif macro_name.endswith('PH'):
            # e.g. PSA_ALG_ED25519PH -> curve = ED25519
            #      PSA_ALG_ED448PH   -> curve = ED448
            curve = macro_name.replace('PSA_ALG_', '').replace('PH', '')
            cli_name = f'EDDSA-PREHASHED-{curve}'
            if cli_name not in seen_cli_names:
                seen_cli_names.add(cli_name)
                eddsa_algos.append({
                    'name': cli_name,
                    'macro': macro_name,
                    'curve': curve,
                })

    return eddsa_algos


def parse_fixed_size_curves(values_h_path):
    """Parse fixed-size curve definitions from crypto_values.h."""
    curves = []

    with open(values_h_path, 'r') as f:
        lines = f.readlines()

    family_curve_map = {
        'MONTGOMERY': ('PSA_ECC_FAMILY_MONTGOMERY', 'key_exchange',
                       {255: 'X25519', 448: 'X448'}),
        'TWISTED_EDWARDS': ('PSA_ECC_FAMILY_TWISTED_EDWARDS', 'signature',
                            {255: 'ED25519', 448: 'ED448'}),
    }

    for family_name, (family_macro, usage, size_map) in family_curve_map.items():
        doc_marker = f'PSA_ECC_FAMILY_{family_name}'
        for i, line in enumerate(lines):
            if doc_marker not in line:
                continue
            for j in range(i + 1, min(i + 10, len(lines))):
                tags_match = re.search(r'\.\.\s*\[\[([^\]]+)\]\]', lines[j])
                if not tags_match:
                    continue
                tags = parse_tags(tags_match.group(1))
                if 'size' not in tags:
                    break
                for size_str in tags['size'].split(','):
                    size = int(size_str.strip())
                    curve_name = size_map.get(size)
                    if curve_name and not any(c['name'] == curve_name
                                              for c in curves):
                        curves.append({
                            'name': curve_name,
                            'family': family_macro,
                            'size': size,
                            'usage': usage
                        })
                break

    known_curves = {
        'ED25519': ('PSA_ECC_FAMILY_TWISTED_EDWARDS', 255, 'signature'),
        'ED448':   ('PSA_ECC_FAMILY_TWISTED_EDWARDS', 448, 'signature'),
        'X25519':  ('PSA_ECC_FAMILY_MONTGOMERY',      255, 'key_exchange'),
        'X448':    ('PSA_ECC_FAMILY_MONTGOMERY',      448, 'key_exchange'),
    }
    for name, (family, size, usage) in known_curves.items():
        if not any(c['name'] == name for c in curves):
            curves.append({'name': name, 'family': family,
                           'size': size, 'usage': usage})

    return curves


def parse_hash_algorithms(values_h_path):
    """Parse all hash algorithms from crypto_values.h."""
    with open(values_h_path, 'r') as f:
        content = f.read()

    hash_algos = []
    seen = set()
    hash_category = 0x02000000
    category_mask = 0x7f000000
    blacklist = ['AES_MMO_ZIGBEE', 'MD2', 'MD4', 'MD5', 'SHAKE256_512',
                 'NONE', 'CATEGORY', 'MASK', 'SHAKE', 'SHA_512_',
                 'RIPEMD', 'SHA_1', 'SHA224', 'SM3']

    pattern = r'#define\s+(PSA_ALG_(\w+))\s+\(\(psa_algorithm_t\)(0x[0-9A-Fa-f]+)\)'

    for match in re.finditer(pattern, content):
        macro_name = match.group(1)
        name = match.group(2)
        value = int(match.group(3), 16)

        if (value & category_mask) != hash_category:
            continue
        if macro_name in seen:
            continue
        if any(x in name for x in blacklist):
            continue

        seen.add(macro_name)
        hash_algos.append({
            'name': normalize_hash_name(macro_name),
            'macro': macro_name,
            'value': value
        })

    hash_algos.sort(key=lambda x: x['value'])
    return hash_algos


def parse_rsa_modes(values_h_path):
    """Parse RSA mode definitions from crypto_values.h."""
    with open(values_h_path, 'r') as f:
        content = f.read()

    sign_modes = []
    encrypt_modes = []

    base_pattern = r'#define\s+PSA_ALG_RSA_(\w+)_BASE\s+\(\(psa_algorithm_t\)'
    for match in re.finditer(base_pattern, content):
        mode_name = match.group(1)
        if mode_name in ['PSS', 'PKCS1V15_SIGN']:
            cli_name = 'PSS' if mode_name == 'PSS' else 'PKCS1V15'
            if not any(m['name'] == cli_name for m in sign_modes):
                sign_modes.append({'name': cli_name})
        elif mode_name == 'OAEP':
            if not any(m['name'] == 'OAEP' for m in encrypt_modes):
                encrypt_modes.append({'name': 'OAEP'})

    if re.search(r'#define\s+PSA_ALG_RSA_PKCS1V15_CRYPT\s+\(\(psa_algorithm_t\)',
                 content):
        if not any(m['name'] == 'PKCS1V15' for m in encrypt_modes):
            encrypt_modes.append({'name': 'PKCS1V15'})

    if not sign_modes:
        sign_modes = [{'name': 'PKCS1V15'}, {'name': 'PSS'}]
    if not encrypt_modes:
        encrypt_modes = [{'name': 'PKCS1V15'}, {'name': 'OAEP'}]

    return sign_modes, encrypt_modes


def _kdf_cli_name(macro_name):
    """Convert PSA macro name to CLI KDF/TLS name."""
    mapping = {
        'PSA_ALG_HKDF':         'HKDF',
        'PSA_ALG_TLS12_PRF':    'TLS12',
        'PSA_ALG_VENDOR_TLS13': 'TLS13',
        'PSA_ALG_ECDH':         'ECDH',
        'PSA_ALG_FFDH':         'DH',
    }
    return mapping.get(macro_name, macro_name.replace('PSA_ALG_', ''))


def parse_kdf_algorithms(values_h_path):
    """Parse KDF/TLS algorithm definitions from crypto_values.h.

    Tag vocabulary:
      tls → TLS key derivation (TLS12, TLS13)
      kdf → all KDF algorithms (HKDF, ECDH, DH)

    The has_hash field is detected by checking if the macro
    definition contains a hash_alg parameter.
    """
    with open(values_h_path, 'r') as f:
        content = f.read()

    tls_algos = []
    kdf_algos = []
    seen = set()

    # Pattern A: doc block with [[...]] tag followed by #define
    pattern_a = (
        r'/\*\*.*?\.\.\s*\[\[([^\]]+)\]\].*?\*/\s*'
        r'#define\s+(PSA_ALG_\w+)([^\n]*)'
    )

    # Pattern B: #define followed by /* .. [[...]] */
    pattern_b = (
        r'#define\s+(PSA_ALG_\w+)([^\n]*)\n'
        r'\s*/\*\s*\.\.\s*\[\[([^\]]+)\]\]\s*\*/'
    )

    def process_match(macro_name, tags_str, macro_def):
        if macro_name in seen:
            return
        tags = parse_tags(tags_str)
        flags = tags.get('flags', [])

        is_tls = 'tls' in flags
        is_kdf = 'kdf' in flags

        if not is_tls and not is_kdf:
            return

        seen.add(macro_name)

        # Detect if macro takes a hash argument from its definition
        has_hash = 'hash_alg' in macro_def

        entry = {
            'name': _kdf_cli_name(macro_name),
            'macro': macro_name,
            'has_hash': has_hash,
        }

        if is_tls:
            tls_algos.append(entry)
        else:
            kdf_algos.append(entry)

    for match in re.finditer(pattern_a, content, re.DOTALL):
        process_match(match.group(2), match.group(1), match.group(3))
    for match in re.finditer(pattern_b, content):
        process_match(match.group(1), match.group(3), match.group(2))

    return tls_algos, kdf_algos


def categorize_families(families):
    """Categorize ECC families by their capability tags.

    Tags aligned with SMW names.h vocabulary:
      signature → can sign
      key_ex    → can do key exchange / derivation
      ecdsa     → ECDSA signature family
      eddsa     → EdDSA signature family
    """
    categories = {'ecdsa': [], 'key_ex': [], 'eddsa': []}
    for fam in families:
        flags = fam['tags']['flags']
        if 'ecdsa' in flags:
            categories['ecdsa'].append(fam)
        if 'key_ex' in flags:
            categories['key_ex'].append(fam)
        if 'eddsa' in flags:
            categories['eddsa'].append(fam)
    return categories


# -------------------------------------------------------------------------
# Code generation
# -------------------------------------------------------------------------

def _file_header():
    year = datetime.now().year
    return (
        "// SPDX-License-Identifier: BSD-3-Clause\n"
        f"/*\n * Copyright {year} NXP\n */\n\n"
        "/* AUTO-GENERATED FILE - DO NOT EDIT */\n\n"
    )


def _algo_value(entry):
    """Return the C value expression for an algo table entry."""
    if entry['has_hash']:
        return f'(uint64_t){entry["macro"]}_BASE'
    return f'(uint64_t){entry["macro"]}'


def generate_c_file(families, hash_algos, eddsa_algos, fixed_curves,
                    sign_modes, encrypt_modes, tls_algos, kdf_algos):

    categories = categorize_families(families)

    out = _file_header()
    out += "#include <stddef.h>\n"
    out += "#include <stdint.h>\n"
    out += "#include <stdbool.h>\n"
    out += "#include <string.h>\n"
    out += "#include <strings.h>\n"
    out += "#include <psa/crypto.h>\n"
    out += '#include "key_asym_mappings.h"\n\n'

    # ---- main key types table ----------------------------------------
    out += "static const struct asym_key_type_mapping asym_key_types[] = {\n"
    out += '\t{ "RSA", (uint32_t)PSA_KEY_TYPE_RSA_KEY_PAIR, 0u, 0u },\n'
    for fam in families:
        if fam['name'] in ('TWISTED_EDWARDS', 'MONTGOMERY'):
            continue
        psa_type = f'PSA_KEY_TYPE_ECC_KEY_PAIR({fam["macro"]})'
        out += (f'\t{{ "{fam["name"]}", (uint32_t){psa_type}, '
                f'0u, (uint64_t){fam["macro"]} }},\n')
    out += '\n\t/* Fixed-size curves */\n'
    for curve in sorted(fixed_curves,
                        key=lambda c: (c['usage'] != 'signature', c['size'])):
        psa_type = f'PSA_KEY_TYPE_ECC_KEY_PAIR({curve["family"]})'
        out += (f'\t{{ "{curve["name"]}", (uint32_t){psa_type}, '
                f'{curve["size"]}u, (uint64_t){curve["family"]} }},\n')
    out += "};\n\n"

    # ---- sign mode table ---------------------------------------------
    out += "static const struct asym_algo_mapping asym_sign_modes[] = {\n"
    for m in sign_modes:
        out += f'\t{{ "{m["name"]}", 0u }},\n'
    out += "};\n\n"

    # ---- encrypt mode table ------------------------------------------
    out += "static const struct asym_algo_mapping asym_encrypt_modes[] = {\n"
    for m in encrypt_modes:
        out += f'\t{{ "{m["name"]}", 0u }},\n'
    out += "};\n\n"

    # ---- hash algo table ---------------------------------------------
    out += "static const struct asym_algo_mapping asym_hash_algos[] = {\n"
    for h in hash_algos:
        out += f'\t{{ "{h["name"]}", (uint64_t){h["macro"]} }},\n'
    out += "};\n\n"

    # ---- EdDSA algo table --------------------------------------------
    out += "static const struct asym_algo_mapping asym_eddsa_algos[] = {\n"
    for algo in sorted(eddsa_algos,
                       key=lambda a: (0 if 'PURE' in a['name'] else 1,
                                      a.get('curve') or '')):
        if algo.get('curve'):
            comment = f' /* user types: EDDSA-PREHASHED with -t {algo["curve"]} */'
        else:
            comment = ''
        out += f'\t{{ "{algo["name"]}", (uint64_t){algo["macro"]} }},{comment}\n'
    out += "};\n\n"

    # ---- TLS algo table ----------------------------------------------
    out += "static const struct asym_algo_mapping asym_tls_algos[] = {\n"
    for tls in tls_algos:
        out += f'\t{{ "{tls["name"]}", {_algo_value(tls)} }},\n'
    out += "};\n\n"

    # ---- KDF algo table ----------------------------------------------
    out += "static const struct asym_algo_mapping asym_kdf_algos[] = {\n"
    for kdf in kdf_algos:
        out += f'\t{{ "{kdf["name"]}", {_algo_value(kdf)} }},\n'
    out += "};\n\n"

    # ---- categorized sub-tables --------------------------------------
    out += "static const struct asym_key_type_mapping asym_rsa_sig_types[] = {\n"
    out += '\t{ "RSA", (uint32_t)PSA_KEY_TYPE_RSA_KEY_PAIR, 0u, 0u },\n'
    out += "};\n\n"

    out += "static const struct asym_key_type_mapping asym_ecdsa_sig_types[] = {\n"
    for fam in categories['ecdsa']:
        if fam['name'] in ('TWISTED_EDWARDS', 'MONTGOMERY'):
            continue
        psa_type = f'PSA_KEY_TYPE_ECC_KEY_PAIR({fam["macro"]})'
        out += (f'\t{{ "{fam["name"]}", (uint32_t){psa_type}, '
                f'0u, (uint64_t){fam["macro"]} }},\n')
    out += "};\n\n"

    out += "static const struct asym_key_type_mapping asym_eddsa_sig_types[] = {\n"
    for curve in sorted(fixed_curves, key=lambda c: c['size']):
        if curve['usage'] != 'signature':
            continue
        psa_type = f'PSA_KEY_TYPE_ECC_KEY_PAIR({curve["family"]})'
        out += (f'\t{{ "{curve["name"]}", (uint32_t){psa_type}, '
                f'{curve["size"]}u, (uint64_t){curve["family"]} }},\n')
    out += "};\n\n"

    out += "static const struct asym_key_type_mapping asym_dsa_sig_types[] = {\n"
    out += "\t{ NULL, 0u, 0u, 0u },\n"
    out += "};\n\n"

    out += "static const struct asym_key_type_mapping asym_rsa_enc_types[] = {\n"
    out += '\t{ "RSA", (uint32_t)PSA_KEY_TYPE_RSA_KEY_PAIR, 0u, 0u },\n'
    out += "};\n\n"

    out += "static const struct asym_key_type_mapping asym_key_exchange_types[] = {\n"
    for fam in categories['key_ex']:
        if fam['name'] in ('TWISTED_EDWARDS', 'MONTGOMERY'):
            continue
        psa_type = f'PSA_KEY_TYPE_ECC_KEY_PAIR({fam["macro"]})'
        out += (f'\t{{ "{fam["name"]}", (uint32_t){psa_type}, '
                f'0u, (uint64_t){fam["macro"]} }},\n')
    for curve in sorted(fixed_curves, key=lambda c: c['size']):
        if curve['usage'] != 'key_exchange':
            continue
        psa_type = f'PSA_KEY_TYPE_ECC_KEY_PAIR({curve["family"]})'
        out += (f'\t{{ "{curve["name"]}", (uint32_t){psa_type}, '
                f'{curve["size"]}u, (uint64_t){curve["family"]} }},\n')
    out += "};\n\n"

    # ---- getter functions for key type tables ------------------------
    out += ("const struct asym_key_type_mapping *get_asym_key_type_mappings(void)\n"
            "{\n\treturn asym_key_types;\n}\n\n")
    out += ("size_t get_asym_key_type_mappings_count(void)\n"
            "{\n\treturn sizeof(asym_key_types) / sizeof(asym_key_types[0]);\n}\n\n")

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
        out += (f"const struct asym_key_type_mapping *{getter}(void)\n"
                f"{{\n\treturn {arr};\n}}\n\n")
        out += (f"size_t {counter}(void)\n"
                f"{{\n"
                f"\tif ({arr}[0].name == NULL)\n"
                f"\t\treturn 0;\n"
                f"\treturn sizeof({arr}) / sizeof({arr}[0]);\n"
                f"}}\n\n")

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
        out += (f"const struct asym_algo_mapping *{getter}(void)\n"
                f"{{\n\treturn {arr};\n}}\n\n")
        out += (f"size_t {counter}(void)\n"
                f"{{\n\treturn sizeof({arr}) / sizeof({arr}[0]);\n}}\n\n")

    # ---- parse_asym_key_type -----------------------------------------
    out += """int parse_asym_key_type(const char *str, uint32_t *fixed_size,
			uint32_t *value)
{
	size_t i;
	size_t count = get_asym_key_type_mappings_count();
	const struct asym_key_type_mapping *tbl = get_asym_key_type_mappings();

	if (!str || !fixed_size || !value)
		return -1;

	for (i = 0; i < count; i++) {
		if (tbl[i].name && !strcasecmp(str, tbl[i].name)) {
			*value      = tbl[i].value;
			*fixed_size = tbl[i].fixed_size;
			return 0;
		}
	}
	return -1;
}

"""

    # ---- asym_key_type_to_string -------------------------------------
    out += """const char *asym_key_type_to_string(uint32_t value)
{
	size_t i;
	size_t count = get_asym_key_type_mappings_count();
	const struct asym_key_type_mapping *tbl = get_asym_key_type_mappings();

	for (i = 0; i < count; i++) {
		if (tbl[i].name && tbl[i].value == value &&
		    tbl[i].fixed_size == 0)
			return tbl[i].name;
	}
	return "UNKNOWN";
}

"""

    # ---- get_asym_curve ----------------------------------------------
    out += """uint64_t get_asym_curve(uint32_t value)
{
	size_t i;
	size_t count = get_asym_key_type_mappings_count();
	const struct asym_key_type_mapping *tbl = get_asym_key_type_mappings();

	for (i = 0; i < count; i++) {
		if (tbl[i].value == value)
			return tbl[i].curve;
	}
	return 0;
}

"""

    # ---- parse_sign_mode ---------------------------------------------
    out += """uint64_t parse_sign_mode(const char *str)
{
	size_t i;
	size_t count = get_sign_mode_mappings_count();
	const struct asym_algo_mapping *tbl = get_sign_mode_mappings();

	if (!str)
		return 0;

	for (i = 0; i < count; i++) {
		if (tbl[i].name && !strcasecmp(str, tbl[i].name))
			return tbl[i].value;
	}
	return 0;
}

"""

    # ---- parse_encrypt_mode ------------------------------------------
    out += """uint64_t parse_encrypt_mode(const char *str)
{
	size_t i;
	size_t count = get_encrypt_mode_mappings_count();
	const struct asym_algo_mapping *tbl = get_encrypt_mode_mappings();

	if (!str)
		return 0;

	for (i = 0; i < count; i++) {
		if (tbl[i].name && !strcasecmp(str, tbl[i].name))
			return tbl[i].value;
	}
	return 0;
}

"""

    # ---- parse_sign_hash ---------------------------------------------
    out += """uint64_t parse_sign_hash(const char *str)
{
	size_t i;
	size_t count = get_sign_hash_algo_mappings_count();
	const struct asym_algo_mapping *tbl = get_sign_hash_algo_mappings();

	if (!str)
		return 0;

	for (i = 0; i < count; i++) {
		if (tbl[i].name && !strcasecmp(str, tbl[i].name))
			return tbl[i].value;
	}
	return 0;
}

"""

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
            f"bool {fn}(const char *type_str)\n"
            f"{{\n"
            f"\tsize_t i;\n"
            f"\tsize_t count = {counter}();\n"
            f"\tconst struct asym_key_type_mapping *tbl = {getter}();\n"
            f"\n"
            f"\tif (!type_str)\n"
            f"\t\treturn false;\n"
            f"\n"
            f"\tfor (i = 0; i < count; i++) {{\n"
            f"\t\tif (tbl[i].name && !strcasecmp(type_str, tbl[i].name))\n"
            f"\t\t\treturn true;\n"
            f"\t}}\n"
            f"\treturn false;\n"
            f"}}\n\n"
        )

    # ---- PSA-specific helpers ----------------------------------------
    out += """psa_key_type_t parse_psa_asym_key_type(const char *str, size_t *key_bits)
{
	uint32_t fixed_size = 0;
	uint32_t value = 0;

	if (!str || !key_bits)
		return PSA_KEY_TYPE_NONE;

	if (parse_asym_key_type(str, &fixed_size, &value) != 0)
		return PSA_KEY_TYPE_NONE;

	if (value > (uint32_t)UINT16_MAX)
		return PSA_KEY_TYPE_NONE;

	*key_bits = fixed_size;
	return (psa_key_type_t)value;
}

const char *psa_key_type_to_export_name(psa_key_type_t key_type,
					size_t key_bits)
{
	size_t i;
	size_t count = get_asym_key_type_mappings_count();
	const struct asym_key_type_mapping *tbl = get_asym_key_type_mappings();
	psa_ecc_family_t family;

	if (PSA_KEY_TYPE_IS_RSA(key_type))
		return "RSA";

	if (!PSA_KEY_TYPE_IS_ECC(key_type))
		return NULL;

	family = PSA_KEY_TYPE_ECC_GET_FAMILY(key_type);

	/* First pass: match family + exact size (ED25519, X448, etc.) */
	for (i = 0; i < count; i++) {
		if (!tbl[i].name)
			continue;
		if ((uint64_t)family != tbl[i].curve)
			continue;
		if (tbl[i].fixed_size > 0 && tbl[i].fixed_size == key_bits)
			return tbl[i].name;
	}

	/* Second pass: match family with variable size (SECP_R1, etc.) */
	for (i = 0; i < count; i++) {
		if (!tbl[i].name)
			continue;
		if ((uint64_t)family != tbl[i].curve)
			continue;
		if (tbl[i].fixed_size == 0)
			return tbl[i].name;
	}

	return NULL;
}

"""

    return out


def generate_h_file():
    out = _file_header()
    out += "#ifndef PSA_ASYM_KEY_MAPPINGS_GENERATED_H\n"
    out += "#define PSA_ASYM_KEY_MAPPINGS_GENERATED_H\n\n"
    out += "#include <psa/crypto.h>\n"
    out += "/* All backend-agnostic declarations are in key_asym_mappings.h */\n"
    out += '#include "key_asym_mappings.h"\n\n'
    out += "/* PSA-specific helpers */\n"
    out += "psa_key_type_t parse_psa_asym_key_type(const char *str,"
    out += " size_t *key_bits);\n"
    out += "const char *psa_key_type_to_export_name(psa_key_type_t key_type,"
    out += " size_t key_bits);\n\n"
    out += "#endif /* PSA_ASYM_KEY_MAPPINGS_GENERATED_H */\n"
    return out


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <output_dir>")
        sys.exit(1)

    output_dir = Path(sys.argv[1])
    repo_root = Path(__file__).resolve().parents[2]
    psa_values_h = repo_root / "public" / "psa" / "crypto_values.h"

    if not psa_values_h.exists():
        print(f"ERROR: PSA values header not found: {psa_values_h}",
              file=sys.stderr)
        sys.exit(1)

    print(f"Parsing {psa_values_h}...")

    families     = parse_ecc_families(psa_values_h)
    hash_algos   = parse_hash_algorithms(psa_values_h)
    eddsa_algos  = parse_eddsa_algorithms(psa_values_h)
    fixed_curves = parse_fixed_size_curves(psa_values_h)
    sign_modes, encrypt_modes = parse_rsa_modes(psa_values_h)
    tls_algos, kdf_algos = parse_kdf_algorithms(psa_values_h)

    categories = categorize_families(families)
    print(f"Found {len(families)} ECC families")
    print(f"  ECDSA:  {len(categories['ecdsa'])}")
    print(f"  key_ex: {len(categories['key_ex'])}")
    print(f"  EdDSA:  {len(categories['eddsa'])}")
    print(f"Found {len(hash_algos)} hash algorithms")
    print(f"Found {len(eddsa_algos)} EdDSA algorithm variants")
    print(f"Found {len(fixed_curves)} fixed-size curves")
    print(f"Found {len(sign_modes)} RSA signature modes, "
          f"{len(encrypt_modes)} encryption modes")
    print(f"Found {len(tls_algos)} TLS algorithms")
    print(f"Found {len(kdf_algos)} KDF algorithms")

    output_dir.mkdir(parents=True, exist_ok=True)

    output_c = output_dir / "psa_asym_key_mappings_generated.c"
    output_h = output_dir / "psa_asym_key_mappings_generated.h"

    output_c.write_text(generate_c_file(families, hash_algos, eddsa_algos,
                                        fixed_curves, sign_modes, encrypt_modes,
                                        tls_algos, kdf_algos))
    output_h.write_text(generate_h_file())

    print(f"\nGenerated {output_c}")
    print(f"Generated {output_h}")
    print("\nDone!")


if __name__ == "__main__":
    main()
