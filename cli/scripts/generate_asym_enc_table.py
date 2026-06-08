#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2026 NXP

"""Generate asymmetric encryption algorithm combination tables from headers.

Parses public/smw/names.h for asymmetric encryption mode definitions with
inline tags, and public/psa/crypto_values.h for PSA algorithm macros tagged
with [[asymm_enc]].

Generates:
  - asym_enc_algo_generated.h / .c : enum, lookup table, core functions
  - asym_enc_smw_mapping_generated.h / .c : SMW-specific mapping
  - asym_enc_psa_mapping_generated.h / .c : PSA-specific mapping

Usage:
    python generate_asym_enc_table.py <output_dir>
"""

import re
import sys
from datetime import datetime
from pathlib import Path


# =========================================================================
# SMW Parsing
# =========================================================================

def parse_all_smw_hashes(content):
    """Parse all hash names from smw_hash_algo_t enum.

    Returns list: ['MD5', 'SHA1', 'SHA224', 'SHA256', ...]
    """
    hashes = []
    pattern = r'SMW_HASH_ALGO_NAME_(\w+)\s*[,}]'

    for match in re.finditer(pattern, content):
        name = match.group(1)
        if name not in ('NONE', 'NB'):
            hashes.append(name)

    return hashes


def get_asymm_enc_hashes(all_hashes):
    """Filter hashes valid for asymmetric encryption.

    Selects SHA-1/SHA-2 family: names matching SHA followed by digits
    only (e.g. SHA1, SHA256), excluding SHA-3 variants (SHA3_224) and
    other families (MD5, SM3, SHAKE256).
    """
    return [h for h in all_hashes if re.fullmatch(r'SHA\d+', h)]


def smw_hash_to_psa_macro(smw_hash_name):
    """Convert SMW hash name to PSA macro name.

    SHA1   -> PSA_ALG_SHA_1
    SHA256 -> PSA_ALG_SHA_256
    """
    return f"PSA_ALG_SHA_{smw_hash_name[3:]}"


def parse_asymm_enc_mode_descriptions(content):
    """Parse doc comments above smw_asymmetric_encryption_mode_t."""
    descriptions = {}
    pattern = (
        r'\*\s+\*\s+SMW_ASYMMETRIC_ENCRYPTION_MODE_NAME_(\w+):\s+(.+)')

    for match in re.finditer(pattern, content):
        name = match.group(1)
        desc = match.group(2).strip()
        if name not in ('NONE', 'NB'):
            descriptions[name] = desc

    return descriptions


def parse_asymm_enc_modes(content):
    """Parse smw_asymmetric_encryption_mode_t entries with inline tags.

    Expected:
        SMW_ASYMMETRIC_ENCRYPTION_MODE_NAME_OAEP, /* [RSA, hash, salt] */
        SMW_ASYMMETRIC_ENCRYPTION_MODE_NAME_PKCS1_1_5, /* [RSA] */
    """
    modes = []
    pattern = (r'(SMW_ASYMMETRIC_ENCRYPTION_MODE_NAME_(\w+))'
               r'\s*,\s*/\*\s*\[([^\]]+)\]\s*\*/')

    for match in re.finditer(pattern, content):
        macro = match.group(1)
        mode_name = match.group(2)
        raw_tags = [t.strip() for t in match.group(3).split(',')]

        if mode_name in ('NONE', 'NB'):
            continue

        algo_families = []
        uses_hash = False
        needs_salt = False

        for tag in raw_tags:
            lower = tag.lower()
            if lower == 'hash':
                uses_hash = True
            elif lower == 'salt':
                needs_salt = True
            else:
                algo_families.append(tag.upper())

        modes.append({
            'macro': macro,
            'mode_name': mode_name,
            'algo_families': algo_families,
            'uses_hash': uses_hash,
            'needs_salt': needs_salt,
        })

    return modes


# =========================================================================
# PSA Parsing
# =========================================================================

def parse_psa_asymm_enc_macros(content):
    """Parse PSA macros tagged with [[asymmetric_encryption]].

    Handles two tag locations used in crypto_values.h:
    - Doc comment tag (parameterized macros):
        * .. [[asymmetric_encryption, rsa, hash_based]]
        ...
        */
        #define PSA_ALG_RSA_OAEP(hash_alg) ...

    - Next-line comment tag (non-parameterized macros):
        #define PSA_ALG_RSA_PKCS1V15_CRYPT ((psa_algorithm_t)0x...)
        /* .. [[asymmetric_encryption]] */

    Returns list of dicts:
        [{'macro': 'PSA_ALG_RSA_OAEP', 'parameterized': True,
          'psa_suffix': 'OAEP'}, ...]
    """
    macros = []

    # Parameterized: tag in doc comment before #define MACRO(param)
    # Match the tag, then skip to end of doc comment (*/) and the #define
    pattern_param = (
        r'\*\s*\.\.\s*\[\[([^\]]*\basymmetric_encryption\b[^\]]*)\]\]'
        r'[\s\S]*?'
        r'\*/'
        r'\s*'
        r'#define\s+(PSA_ALG_(\w+))\((\w+)\)')

    for match in re.finditer(pattern_param, content):
        macro_name = match.group(2)
        suffix = match.group(3)

        # Strip leading RSA_ if present
        if suffix.startswith('RSA_'):
            suffix = suffix[4:]

        macros.append({
            'macro': macro_name,
            'parameterized': True,
            'psa_suffix': suffix,
        })

    # Non-parameterized: tag in next-line comment after #define MACRO value
    pattern_simple = (
        r'#define\s+(PSA_ALG_(\w+))\s+'
        r'\(\(psa_algorithm_t\)\s*0x[0-9a-fA-F]+\)'
        r'\s*\n'
        r'\s*/\*\s*\.\.\s*\[\[([^\]]*\basymmetric_encryption\b'
        r'[^\]]*)\]\]\s*\*/')

    for match in re.finditer(pattern_simple, content):
        macro_name = match.group(1)
        suffix = match.group(2)

        if suffix.startswith('RSA_'):
            suffix = suffix[4:]

        macros.append({
            'macro': macro_name,
            'parameterized': False,
            'psa_suffix': suffix,
        })

    return macros


def parse_all_psa_hashes(content):
    """Parse all PSA hash algorithm macros by matching the hash category.

    Hash category = 0x02000000 (PSA_ALG_CATEGORY_HASH).
    Matches: #define PSA_ALG_SHA_256 ((psa_algorithm_t)0x02000009)

    Returns dict: {'PSA_ALG_SHA_1': 0x02000005, ...}
    """
    psa_hashes = {}
    pattern = (r'#define\s+(PSA_ALG_\w+)\s+'
               r'\(\(psa_algorithm_t\)\s*(0x[0-9a-fA-F]+)\)')

    for match in re.finditer(pattern, content):
        macro = match.group(1)
        value = int(match.group(2), 16)

        # Check hash category: (value & 0x7f000000) == 0x02000000
        if (value & 0x7f000000) == 0x02000000 and value != 0:
            psa_hashes[macro] = value

    return psa_hashes


def validate_psa_hashes(hashes, all_psa_hashes):
    """Validate that derived PSA hash macros exist."""
    for h in hashes:
        psa_macro = smw_hash_to_psa_macro(h)
        if psa_macro not in all_psa_hashes:
            print(f"WARNING: PSA hash macro '{psa_macro}' for "
                  f"'{h}' not found in crypto_values.h",
                  file=sys.stderr)



def build_psa_mode_map(psa_macros, smw_modes):
    """Build mapping: SMW mode name -> PSA macro info.

    By default the PSA suffix is used as-is as the SMW mode name.
    Exceptions are handled for suffixes that differ from SMW names
    (e.g. PKCS1V15_CRYPT -> PKCS1_1_5).

    Returns dict: {'OAEP': {'macro': 'PSA_ALG_RSA_OAEP',
                            'parameterized': True}, ...}
    """
    # Only needed when PSA suffix differs from SMW mode name
    psa_suffix_exceptions = {
        'PKCS1V15_CRYPT': 'PKCS1_1_5',
    }

    smw_mode_names = {m['mode_name'] for m in smw_modes}
    result = {}

    for psa in psa_macros:
        smw_mode = psa_suffix_exceptions.get(psa['psa_suffix'],
                                             psa['psa_suffix'])

        if smw_mode in smw_mode_names:
            result[smw_mode] = {
                'macro': psa['macro'],
                'parameterized': psa['parameterized'],
            }
        else:
            print(f"WARNING: PSA suffix '{psa['psa_suffix']}' "
                  f"(from {psa['macro']}) maps to '{smw_mode}' "
                  f"which is not a known SMW mode",
                  file=sys.stderr)

    return result


# =========================================================================
# Combination builder
# =========================================================================

def build_asym_enc_combinations(modes, hashes, mode_descriptions,
                                psa_mode_map):
    """Build all (algo_family, mode, hash?) combinations."""
    combinations = []

    # Display-friendly mode names for CLI usage
    mode_display_names = {
        'PKCS1_1_5': 'PKCS1V15',
    }

    for mode in modes:
        display_mode = mode_display_names.get(mode['mode_name'],
                                              mode['mode_name'])
        for algo in mode['algo_families']:
            if mode['uses_hash']:
                for h in hashes:
                    mode_desc = mode_descriptions.get(
                        mode['mode_name'], mode['mode_name'])

                    # PSA expression
                    psa_info = psa_mode_map.get(mode['mode_name'])
                    psa_hash = smw_hash_to_psa_macro(h)
                    if psa_info and psa_info['parameterized']:
                        psa_expr = f"{psa_info['macro']}({psa_hash})"
                    else:
                        psa_expr = 'PSA_ALG_NONE'

                    combinations.append({
                        'name': f"{algo}-{display_mode}-{h}",
                        'enum': (f"ASYM_ENC_ALGO_"
                                 f"{algo}_{mode['mode_name']}_{h}"),
                        'algo_family': algo,
                        'mode_name': mode['mode_name'],
                        'mode_macro': mode['macro'],
                        'hash_name': h,
                        'needs_salt': mode['needs_salt'],
                        'description': f"{algo} {mode_desc} with {h}",
                        'psa_alg_expr': psa_expr,
                    })
            else:
                mode_desc = mode_descriptions.get(
                    mode['mode_name'], mode['mode_name'])

                psa_info = psa_mode_map.get(mode['mode_name'])
                if psa_info and not psa_info['parameterized']:
                    psa_expr = psa_info['macro']
                else:
                    psa_expr = 'PSA_ALG_NONE'

                combinations.append({
                    'name': f"{algo}-{display_mode}",
                    'enum': (f"ASYM_ENC_ALGO_"
                             f"{algo}_{mode['mode_name']}"),
                    'algo_family': algo,
                    'mode_name': mode['mode_name'],
                    'mode_macro': mode['macro'],
                    'hash_name': None,
                    'needs_salt': mode['needs_salt'],
                    'description': f"{algo} {mode_desc}",
                    'psa_alg_expr': psa_expr,
                })

    return combinations


# =========================================================================
# Code generation helpers
# =========================================================================

def _file_header(year, extra_includes=None):
    inc = ''
    if extra_includes:
        inc = '\n'.join(extra_includes) + '\n\n'
    return (f"// SPDX-License-Identifier: BSD-3-Clause\n"
            f"/*\n * Copyright {year} NXP\n */\n\n"
            f"/* AUTO-GENERATED FILE - DO NOT EDIT */\n\n{inc}")


# =========================================================================
# Core header / source
# =========================================================================

def generate_core_header(combinations):
    year = datetime.now().year
    lines = [_file_header(year)]
    lines.append("#ifndef ASYM_ENC_ALGO_GENERATED_H\n"
                 "#define ASYM_ENC_ALGO_GENERATED_H\n\n"
                 "#include <stdbool.h>\n"
                 "#include <stddef.h>\n\n")

    lines.append("enum asym_enc_algo {\n"
                 "\tASYM_ENC_ALGO_NONE = 0,\n")
    for c in combinations:
        lines.append(f"\t{c['enum']},\n")
    lines.append("};\n\n")

    lines.append("struct asym_enc_algo_info {\n"
                 "\tconst char *name;\n"
                 "\tenum asym_enc_algo algo;\n"
                 "\tbool needs_salt;\n"
                 "\tconst char *description;\n"
                 "};\n\n")

    lines.append(
        "const struct asym_enc_algo_info *"
        "get_asym_enc_algo_table(size_t *count);\n"
        "enum asym_enc_algo parse_asym_enc_algo_str"
        "(const char *algo_str);\n"
        "bool asym_enc_algo_needs_salt(enum asym_enc_algo algo);\n"
        "const char *asym_enc_algo_to_string(enum asym_enc_algo algo);\n"
        "void print_asym_enc_algo_list(void);\n\n"
        "#endif /* ASYM_ENC_ALGO_GENERATED_H */\n")

    return ''.join(lines)


def generate_core_source(combinations):
    year = datetime.now().year
    lines = [_file_header(year, [
        '#include <stdio.h>',
        '#include <stddef.h>',
        '#include <strings.h>',
        '',
        '#include "asym_enc_algo_generated.h"',
    ])]

    lines.append(
        "static const struct asym_enc_algo_info"
        " asym_enc_algo_table[] = {\n")
    for c in combinations:
        salt = "true" if c['needs_salt'] else "false"
        lines.append(f'\t{{ "{c["name"]}", {c["enum"]}, {salt},\n')
        lines.append(f'\t  "{c["description"]}" }},\n')
    lines.append("};\n\n")

    lines.append(
        "static const size_t asym_enc_algo_table_size =\n"
        "\tsizeof(asym_enc_algo_table)"
        " / sizeof(asym_enc_algo_table[0]);\n\n")

    lines.append("""\
const struct asym_enc_algo_info *get_asym_enc_algo_table(size_t *count)
{
\tif (count)
\t\t*count = asym_enc_algo_table_size;

\treturn asym_enc_algo_table;
}

enum asym_enc_algo parse_asym_enc_algo_str(const char *algo_str)
{
\tsize_t i = 0;

\tif (!algo_str || algo_str[0] == '\\0')
\t\treturn ASYM_ENC_ALGO_NONE;

\tfor (; i < asym_enc_algo_table_size; i++) {
\t\tif (!strcasecmp(algo_str, asym_enc_algo_table[i].name))
\t\t\treturn asym_enc_algo_table[i].algo;
\t}

\treturn ASYM_ENC_ALGO_NONE;
}

bool asym_enc_algo_needs_salt(enum asym_enc_algo algo)
{
\tsize_t i = 0;

\tfor (; i < asym_enc_algo_table_size; i++) {
\t\tif (asym_enc_algo_table[i].algo == algo)
\t\t\treturn asym_enc_algo_table[i].needs_salt;
\t}

\treturn false;
}

const char *asym_enc_algo_to_string(enum asym_enc_algo algo)
{
\tsize_t i = 0;

\tfor (; i < asym_enc_algo_table_size; i++) {
\t\tif (asym_enc_algo_table[i].algo == algo)
\t\t\treturn asym_enc_algo_table[i].name;
\t}

\treturn "UNKNOWN";
}

void print_asym_enc_algo_list(void)
{
\tsize_t i = 0;
\tconst struct asym_enc_algo_info *info = NULL;

\tprintf("\\nAvailable Asymmetric Algorithms\\n");
\tprintf("===============================\\n\\n");
\tprintf("%-20s %-8s %s\\n", "Algorithm", "Salt", "Description");
\tprintf("%-20s %-8s %s\\n", "---------", "----", "-----------");

\tfor (; i < asym_enc_algo_table_size; i++) {
\t\tinfo = &asym_enc_algo_table[i];
\t\tprintf("%-20s %-8s %s\\n", info->name,
\t\t       info->needs_salt ? "Optional" : "No",
\t\t       info->description);
\t}

\tprintf("\\nNote: Actual support depends on the backend"
\t       " and subsystem capabilities.\\n\\n");
}
""")

    return ''.join(lines)


# =========================================================================
# SMW mapping
# =========================================================================

def generate_smw_mapping_header():
    year = datetime.now().year
    return (f"{_file_header(year)}"
            "#ifndef ASYM_ENC_SMW_MAPPING_GENERATED_H\n"
            "#define ASYM_ENC_SMW_MAPPING_GENERATED_H\n\n"
            "#include <smw/names.h>\n"
            "#include <smw/attr.h>\n"
            "#include <smw_keymgr.h>\n\n"
            "#include \"asym_enc_algo_generated.h\"\n\n"
            "smw_key_type_t get_smw_asym_enc_key_type"
            "(enum asym_enc_algo algo);\n"
            "const char *get_smw_asym_enc_hash_name"
            "(enum asym_enc_algo algo);\n"
            "smw_attr_algo_t get_smw_asym_enc_algo"
            "(enum asym_enc_algo algo);\n\n"
            "#endif /* ASYM_ENC_SMW_MAPPING_GENERATED_H */\n")


def generate_smw_mapping_source(combinations):
    year = datetime.now().year
    lines = [_file_header(year, [
        '#include <smw/names.h>',
        '#include <smw/attr.h>',
        '#include <smw_keymgr.h>',
        '',
        '#include "asym_enc_algo_generated.h"',
        '#include "smw_asym_enc_mapping_generated.h"',
    ])]

    lines.append("struct asym_enc_smw_mapping {\n"
                 "\tenum asym_enc_algo algo;\n"
                 "\tsmw_key_type_t key_type;\n"
                 "\tconst char *hash_name;\n"
                 "\tsmw_attr_algo_t smw_algo_attr;\n"
                 "};\n\n")

    lines.append(
        "static const struct asym_enc_smw_mapping"
        " asym_enc_smw_map[] = {\n")

    for c in combinations:
        kt = f"SMW_KEY_TYPE_NAME_{c['algo_family']}"
        mode_attr = f"SMW_ATTR_MODE_{c['mode_name']}"
        if c['hash_name']:
            hash_attr = f"SMW_ATTR_HASH_{c['hash_name']}"
            hash_str = f'"{c["hash_name"]}"'
        else:
            hash_attr = 'SMW_ATTR_HASH_NONE'
            hash_str = 'NULL'

        algo_attr = (f"SMW_ATTR_ALGO_ASYMMETRIC_ENCRYPTION_"
                     f"{c['algo_family']}({mode_attr}, {hash_attr})")

        lines.append(f"\t{{ {c['enum']}, {kt}, {hash_str},\n")
        lines.append(f"\t  {algo_attr} }},\n")

    lines.append(
        "\t{ ASYM_ENC_ALGO_NONE, SMW_KEY_TYPE_NAME_NONE,"
        " NULL, 0 },\n"
        "};\n\n"
        "static const size_t asym_enc_smw_map_size =\n"
        "\tsizeof(asym_enc_smw_map)"
        " / sizeof(asym_enc_smw_map[0]) - 1;\n\n")

    lines.append("""\
smw_key_type_t get_smw_asym_enc_key_type(enum asym_enc_algo algo)
{
\tsize_t i = 0;

\tfor (; i < asym_enc_smw_map_size; i++) {
\t\tif (asym_enc_smw_map[i].algo == algo)
\t\t\treturn asym_enc_smw_map[i].key_type;
\t}

\treturn SMW_KEY_TYPE_NAME_NONE;
}

const char *get_smw_asym_enc_hash_name(enum asym_enc_algo algo)
{
\tsize_t i = 0;

\tfor (; i < asym_enc_smw_map_size; i++) {
\t\tif (asym_enc_smw_map[i].algo == algo)
\t\t\treturn asym_enc_smw_map[i].hash_name;
\t}

\treturn NULL;
}

smw_attr_algo_t get_smw_asym_enc_algo(enum asym_enc_algo algo)
{
\tsize_t i = 0;

\tfor (; i < asym_enc_smw_map_size; i++) {
\t\tif (asym_enc_smw_map[i].algo == algo)
\t\t\treturn asym_enc_smw_map[i].smw_algo_attr;
\t}

\treturn 0;
}
""")

    return ''.join(lines)


# =========================================================================
# PSA mapping
# =========================================================================

def generate_psa_mapping_header():
    year = datetime.now().year
    return (f"{_file_header(year)}"
            "#ifndef ASYM_ENC_PSA_MAPPING_GENERATED_H\n"
            "#define ASYM_ENC_PSA_MAPPING_GENERATED_H\n\n"
            "#include <psa/crypto.h>\n\n"
            "#include \"asym_enc_algo_generated.h\"\n\n"
            "psa_algorithm_t get_psa_asym_enc_alg"
            "(enum asym_enc_algo algo);\n"
            "const char *get_psa_asym_enc_alg_name"
            "(psa_algorithm_t alg);\n\n"
            "#endif /* ASYM_ENC_PSA_MAPPING_GENERATED_H */\n")


def generate_psa_mapping_source(combinations):
    year = datetime.now().year
    lines = [_file_header(year, [
        '#include <psa/crypto.h>',
        '',
        '#include "asym_enc_algo_generated.h"',
        '#include "psa_asym_enc_mapping_generated.h"',
    ])]

    lines.append("struct asym_enc_psa_mapping {\n"
                 "\tenum asym_enc_algo algo;\n"
                 "\tpsa_algorithm_t psa_alg;\n"
                 "};\n\n")

    lines.append(
        "static const struct asym_enc_psa_mapping"
        " asym_enc_psa_map[] = {\n")
    for c in combinations:
        lines.append(f"\t{{ {c['enum']}, {c['psa_alg_expr']} }},\n")
    lines.append(
        "\t{ ASYM_ENC_ALGO_NONE, PSA_ALG_NONE },\n"
        "};\n\n"
        "static const size_t asym_enc_psa_map_size =\n"
        "\tsizeof(asym_enc_psa_map)"
        " / sizeof(asym_enc_psa_map[0]) - 1;\n\n")

    # Name table
    seen = []
    unique = []
    for c in combinations:
        expr = c['psa_alg_expr']
        if expr != 'PSA_ALG_NONE' and expr not in seen:
            seen.append(expr)
            unique.append(expr)

    lines.append("struct psa_asym_alg_name_entry {\n"
                 "\tpsa_algorithm_t alg;\n"
                 "\tconst char *name;\n"
                 "};\n\n")

    lines.append(
        "static const struct psa_asym_alg_name_entry"
        " psa_asym_alg_names[] = {\n")
    for expr in unique:
        lines.append(f'\t{{ {expr}, "{expr}" }},\n')
    lines.append("};\n\n")

    lines.append(
        "static const size_t psa_asym_alg_names_size =\n"
        "\tsizeof(psa_asym_alg_names)"
        " / sizeof(psa_asym_alg_names[0]);\n\n")

    lines.append("""\
psa_algorithm_t get_psa_asym_enc_alg(enum asym_enc_algo algo)
{
\tsize_t i = 0;

\tfor (; i < asym_enc_psa_map_size; i++) {
\t\tif (asym_enc_psa_map[i].algo == algo)
\t\t\treturn asym_enc_psa_map[i].psa_alg;
\t}

\treturn PSA_ALG_NONE;
}

const char *get_psa_asym_enc_alg_name(psa_algorithm_t alg)
{
\tsize_t i = 0;

\tfor (; i < psa_asym_alg_names_size; i++) {
\t\tif (psa_asym_alg_names[i].alg == alg)
\t\t\treturn psa_asym_alg_names[i].name;
\t}

\treturn "UNKNOWN";
}
""")

    return ''.join(lines)


# =========================================================================
# Main
# =========================================================================

def main():
    if len(sys.argv) < 2:
        print("ERROR: Output directory required", file=sys.stderr)
        print(f"Usage: {sys.argv[0]} <output_dir>", file=sys.stderr)
        sys.exit(1)

    output_dir = Path(sys.argv[1])
    script_dir = Path(__file__).parent
    repo_root = script_dir.parent.parent

    smw_names_h = repo_root / "public" / "smw" / "names.h"
    psa_values_h = repo_root / "public" / "psa" / "crypto_values.h"

    for path in (smw_names_h, psa_values_h):
        if not path.exists():
            print(f"ERROR: Header not found: {path}", file=sys.stderr)
            sys.exit(1)

    # --- SMW ---
    print(f"Parsing {smw_names_h}...")
    with open(smw_names_h, 'r') as f:
        smw_content = f.read()

    all_hashes = parse_all_smw_hashes(smw_content)
    print(f"Found {len(all_hashes)} hash algorithms in smw_hash_algo_t")

    hashes = get_asymm_enc_hashes(all_hashes)
    print(f"Selected {len(hashes)} SHA-1/SHA-2 hashes: {', '.join(hashes)}")

    mode_descriptions = parse_asymm_enc_mode_descriptions(smw_content)
    modes = parse_asymm_enc_modes(smw_content)
    print(f"Found {len(modes)} tagged asymmetric encryption modes")

    for mode in modes:
        tags = ', '.join(mode['algo_families'])
        if mode['uses_hash']:
            tags += ', hash'
        if mode['needs_salt']:
            tags += ', salt'
        print(f"  {mode['mode_name']}: [{tags}]")

    if not modes:
        print("ERROR: No tagged modes found", file=sys.stderr)
        sys.exit(1)

    # --- PSA ---
    print(f"\nParsing {psa_values_h}...")
    with open(psa_values_h, 'r') as f:
        psa_content = f.read()

    psa_macros = parse_psa_asymm_enc_macros(psa_content)
    print(f"Found {len(psa_macros)} PSA asymmetric encryption macros")
    for p in psa_macros:
        param = " (parameterized)" if p['parameterized'] else ""
        print(f"  {p['macro']} -> suffix: {p['psa_suffix']}{param}")

    all_psa_hashes = parse_all_psa_hashes(psa_content)
    print(f"Found {len(all_psa_hashes)} PSA hash macros")
    validate_psa_hashes(hashes, all_psa_hashes)

    psa_mode_map = build_psa_mode_map(psa_macros, modes)
    print(f"PSA mode map: {len(psa_mode_map)} entries")
    for smw_mode, info in psa_mode_map.items():
        print(f"  SMW {smw_mode} -> {info['macro']}")

    # --- Build ---
    combinations = build_asym_enc_combinations(
        modes, hashes, mode_descriptions, psa_mode_map)

    print(f"\nGenerated {len(combinations)} combinations:")
    for c in combinations:
        salt = " (salt)" if c['needs_salt'] else ""
        print(f"  {c['enum']:40s} -> {c['name']:20s}"
              f"  PSA: {c['psa_alg_expr']}{salt}")

    no_psa = [c for c in combinations if c['psa_alg_expr'] == 'PSA_ALG_NONE']
    if no_psa:
        print(f"\nNote: {len(no_psa)} combinations have no PSA mapping:")
        for c in no_psa:
            print(f"  {c['enum']}")

    # --- Write ---
    output_dir.mkdir(parents=True, exist_ok=True)

    files = {
        "asym_enc_algo_generated.h":
            generate_core_header(combinations),
        "asym_enc_algo_generated.c":
            generate_core_source(combinations),
        "smw_asym_enc_mapping_generated.h":
            generate_smw_mapping_header(),
        "smw_asym_enc_mapping_generated.c":
            generate_smw_mapping_source(combinations),
        "psa_asym_enc_mapping_generated.h":
            generate_psa_mapping_header(),
        "psa_asym_enc_mapping_generated.c":
            generate_psa_mapping_source(combinations),
    }

    for name, content in files.items():
        path = output_dir / name
        with open(path, 'w') as f:
            f.write(content)
        print(f"Generated {path}")


if __name__ == "__main__":
    main()