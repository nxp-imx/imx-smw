#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2026 NXP

"""Generate cipher algorithm combination tables from SMW headers with inline tags.

Parses public/smw/names.h for cipher mode definitions with inline key type tags
and psa_sym_key_mappings_generated.c for PSA algorithm mappings, and generates:
  - cipher_algo_generated.h / .c : enum, lookup table, core functions
  - smw_cipher_mapping_generated.h / .c : SMW-specific mapping functions
  - psa_cipher_mapping_generated.h / .c : PSA-specific mapping functions

Usage:
    python generate_cipher_table.py <output_dir>
"""

import re
import sys
from datetime import datetime
from pathlib import Path


def parse_cipher_mode_descriptions(content):
    """Parse doc comments above smw_cipher_mode_t for mode descriptions.

    Matches lines like:
        * * SMW_CIPHER_MODE_NAME_CBC: Cipher Block Chaining mode
    """
    descriptions = {}

    desc_pattern = r'\*\s+\*\s+SMW_CIPHER_MODE_NAME_(\w+):\s+(.+)'

    for match in re.finditer(desc_pattern, content):
        mode_name = match.group(1)
        description = match.group(2).strip()

        if mode_name in ('NONE', 'NB'):
            continue

        if description.endswith(' mode'):
            description = description[:-5]

        descriptions[mode_name] = description

    return descriptions


def parse_cipher_modes_with_tags(content):
    """Parse smw_cipher_mode_t enum entries with inline key type tags.

    Expected format:
        SMW_CIPHER_MODE_NAME_CBC, /* [AES, DES3, SM4] */
        SMW_CIPHER_MODE_NAME_ECB, /* [AES, DES3, SM4, no_iv] */

    Returns a list of mode dicts with key_types and needs_iv.
    """
    modes = []

    pattern = r'(SMW_CIPHER_MODE_NAME_(\w+))\s*,\s*/\*\s*\[([^\]]+)\]\s*\*/'

    for match in re.finditer(pattern, content):
        macro = match.group(1)
        mode_name = match.group(2)
        raw_tags = [t.strip() for t in match.group(3).split(',')]

        if mode_name in ('NONE', 'NB'):
            continue

        key_types = []
        needs_iv = True

        for tag in raw_tags:
            if tag.lower() == 'no_iv':
                needs_iv = False
            else:
                key_types.append(tag.upper())

        modes.append({
            'macro': macro,
            'mode_name': mode_name,
            'key_types': key_types,
            'needs_iv': needs_iv,
        })

    return modes


def parse_psa_cipher_algorithms(content):
    """Parse PSA cipher algorithm mappings from psa_sym_key_mappings_generated.c.

    Reads the psa_cipher_algos[] table:

        static const struct algo_mapping psa_cipher_algos[] = {
            { "CBC", (uint32_t)PSA_ALG_CBC_NO_PADDING },
            { "CFB", (uint32_t)PSA_ALG_CFB },
            ...
        };

    Returns dict mapping mode name to PSA macro:
        {'CBC': 'PSA_ALG_CBC_NO_PADDING', 'CTR': 'PSA_ALG_CTR', ...}
    """
    psa_algos = {}

    table_pattern = (
        r'static\s+const\s+struct\s+algo_mapping\s+psa_cipher_algos\[\]\s*=\s*\{'
        r'(.*?)'
        r'\};'
    )

    table_match = re.search(table_pattern, content, re.DOTALL)
    if not table_match:
        print("WARNING: psa_cipher_algos[] table not found", file=sys.stderr)
        return psa_algos

    table_body = table_match.group(1)

    entry_pattern = (
        r'\{\s*"(\w[\w-]*)"\s*,'
        r'\s*\(uint32_t\)\s*'
        r'(PSA_ALG_\w+)'
        r'\s*\}'
    )

    for match in re.finditer(entry_pattern, table_body, re.DOTALL):
        mode = match.group(1)
        macro = match.group(2)
        psa_algos[mode] = macro

    return psa_algos


def build_cipher_combinations(modes, mode_descriptions, psa_mode_to_alg):
    """Build all key_type+mode combinations with both SMW and PSA mappings."""
    seen = []
    for mode in modes:
        for kt in mode['key_types']:
            if kt not in seen:
                seen.append(kt)

    combinations = []

    for key_type in seen:
        for mode in modes:
            if key_type not in mode['key_types']:
                continue

            combo_name = f"{key_type}-{mode['mode_name']}"
            enum_name = f"CIPHER_ALGO_{key_type}_{mode['mode_name']}"

            mode_desc = mode_descriptions.get(mode['mode_name'],
                                              mode['mode_name'])

            description = f"{key_type} {mode_desc}"
            if not mode['needs_iv']:
                description += " (no IV)"

            combinations.append({
                'name': combo_name,
                'enum': enum_name,
                'key_type': key_type,
                'key_type_macro': f"SMW_KEY_TYPE_NAME_{key_type}",
                'mode_name': mode['mode_name'],
                'mode_macro': mode['macro'],
                'needs_iv': mode['needs_iv'],
                'description': description,
                'psa_alg_macro': psa_mode_to_alg.get(
                    mode['mode_name'], 'PSA_ALG_NONE'),
            })

    return combinations


# =========================================================================
# Code generation
# =========================================================================

def _file_header(year, extra_includes=None):
    """Return the common auto-generated file banner."""
    inc = ''
    if extra_includes:
        inc = '\n'.join(extra_includes) + '\n\n'
    return (f"// SPDX-License-Identifier: BSD-3-Clause\n"
            f"/*\n * Copyright {year} NXP\n */\n\n"
            f"/* AUTO-GENERATED FILE - DO NOT EDIT */\n\n{inc}")


def generate_core_header(combinations):
    """Generate cipher_algo_generated.h."""
    year = datetime.now().year

    lines = [_file_header(year)]
    lines.append("#ifndef CIPHER_ALGO_GENERATED_H\n"
                 "#define CIPHER_ALGO_GENERATED_H\n\n"
                 "#include <stdbool.h>\n"
                 "#include <stddef.h>\n\n")

    lines.append("/**\n"
                 " * @brief Cipher algorithm/mode combinations (auto-generated)\n"
                 " */\n"
                 "enum cipher_algo {\n"
                 "\tCIPHER_ALGO_NONE = 0,\n")
    for c in combinations:
        lines.append(f"\t{c['enum']},\n")
    lines.append("};\n\n")

    lines.append("/**\n"
                 " * @brief Cipher algorithm info entry\n"
                 " */\n"
                 "struct cipher_algo_info {\n"
                 "\tconst char *name;\n"
                 "\tenum cipher_algo algo;\n"
                 "\tbool needs_iv;\n"
                 "\tconst char *description;\n"
                 "};\n\n")

    lines.append(
        "const struct cipher_algo_info *get_cipher_algo_table(size_t *count);\n"
        "enum cipher_algo parse_cipher_algo_str(const char *algo_str);\n"
        "bool cipher_algo_requires_iv(enum cipher_algo algo);\n"
        "const char *cipher_algo_to_string(enum cipher_algo algo);\n"
        "void print_cipher_algo_list(void);\n\n"
        "#endif /* CIPHER_ALGO_GENERATED_H */\n")

    return ''.join(lines)


def generate_core_source(combinations):
    """Generate cipher_algo_generated.c."""
    year = datetime.now().year

    lines = [_file_header(year, [
        '#include <stdio.h>',
        '#include <stddef.h>',
        '#include <strings.h>',
        '',
        '#include "cipher_algo_generated.h"',
    ])]

    lines.append("static const struct cipher_algo_info cipher_algo_table[] = {\n")
    for c in combinations:
        iv = "true" if c['needs_iv'] else "false"
        lines.append(f'\t{{ "{c["name"]}", {c["enum"]}, {iv},\n')
        lines.append(f'\t  "{c["description"]}" }},\n')
    lines.append("};\n\n")

    lines.append(
        "static const size_t cipher_algo_table_size =\n"
        "\tsizeof(cipher_algo_table) / sizeof(cipher_algo_table[0]);\n\n")

    lines.append("""\
const struct cipher_algo_info *get_cipher_algo_table(size_t *count)
{
\tif (count)
\t\t*count = cipher_algo_table_size;

\treturn cipher_algo_table;
}

enum cipher_algo parse_cipher_algo_str(const char *algo_str)
{
\tsize_t i = 0;

\tif (!algo_str || algo_str[0] == '\\0')
\t\treturn CIPHER_ALGO_NONE;

\tfor (; i < cipher_algo_table_size; i++) {
\t\tif (!strcasecmp(algo_str, cipher_algo_table[i].name))
\t\t\treturn cipher_algo_table[i].algo;
\t}

\treturn CIPHER_ALGO_NONE;
}

bool cipher_algo_requires_iv(enum cipher_algo algo)
{
\tsize_t i = 0;

\tfor (; i < cipher_algo_table_size; i++) {
\t\tif (cipher_algo_table[i].algo == algo)
\t\t\treturn cipher_algo_table[i].needs_iv;
\t}

\treturn true;
}

const char *cipher_algo_to_string(enum cipher_algo algo)
{
\tsize_t i = 0;

\tfor (; i < cipher_algo_table_size; i++) {
\t\tif (cipher_algo_table[i].algo == algo)
\t\t\treturn cipher_algo_table[i].name;
\t}

\treturn "UNKNOWN";
}

void print_cipher_algo_list(void)
{
\tsize_t i = 0;
\tconst struct cipher_algo_info *info = NULL;

\tprintf("\\n");
\tprintf("Available Symmetric Algorithms\\n");
\tprintf("==============================\\n\\n");
\tprintf("%-12s %-8s %s\\n", "Algorithm", "IV", "Description");
\tprintf("%-12s %-8s %s\\n", "---------", "--", "-----------");

\tfor (; i < cipher_algo_table_size; i++) {
\t\tinfo = &cipher_algo_table[i];
\t\tprintf("%-12s %-8s %s\\n", info->name,
\t\t       info->needs_iv ? "Yes" : "No", info->description);
\t}

\tprintf("\\nNote: Actual support depends on the backend"
\t       " and subsystem capabilities.\\n");
\tprintf("      The operation may fail at runtime"
\t       " if unsupported.\\n\\n");
}
""")

    return ''.join(lines)


def generate_smw_mapping_header():
    """Generate smw_cipher_mapping_generated.h."""
    year = datetime.now().year

    return (f"{_file_header(year)}"
            "#ifndef CIPHER_SMW_MAPPING_GENERATED_H\n"
            "#define CIPHER_SMW_MAPPING_GENERATED_H\n\n"
            "#include <smw/names.h>\n\n"
            "#include \"cipher_algo_generated.h\"\n\n"
            "smw_cipher_mode_t get_smw_cipher_mode(enum cipher_algo algo);\n\n"
            "smw_key_type_t get_smw_cipher_key_type(enum cipher_algo algo);\n\n"
            "#endif /* CIPHER_SMW_MAPPING_GENERATED_H */\n")


def generate_smw_mapping_source(combinations):
    """Generate smw_cipher_mapping_generated.c."""
    year = datetime.now().year

    lines = [_file_header(year, [
        '#include <smw/names.h>',
        '',
        '#include "cipher_algo_generated.h"',
        '#include "smw_cipher_mapping_generated.h"',
    ])]

    lines.append("struct cipher_smw_mapping {\n"
                 "\tenum cipher_algo algo;\n"
                 "\tsmw_cipher_mode_t mode;\n"
                 "\tsmw_key_type_t key_type;\n"
                 "};\n\n")

    lines.append("static const struct cipher_smw_mapping cipher_smw_map[] = {\n")
    for c in combinations:
        lines.append(
            f"\t{{ {c['enum']}, {c['mode_macro']}, {c['key_type_macro']} }},\n")
    lines.append(
        "\t{ CIPHER_ALGO_NONE, SMW_CIPHER_MODE_NAME_NONE,"
        " SMW_KEY_TYPE_NAME_NONE },\n"
        "};\n\n"
        "static const size_t cipher_smw_map_size =\n"
        "\tsizeof(cipher_smw_map) / sizeof(cipher_smw_map[0]) - 1;\n\n")

    lines.append("""\
smw_cipher_mode_t get_smw_cipher_mode(enum cipher_algo algo)
{
\tsize_t i = 0;

\tfor (; i < cipher_smw_map_size; i++) {
\t\tif (cipher_smw_map[i].algo == algo)
\t\t\treturn cipher_smw_map[i].mode;
\t}

\treturn SMW_CIPHER_MODE_NAME_NONE;
}

smw_key_type_t get_smw_cipher_key_type(enum cipher_algo algo)
{
\tsize_t i = 0;

\tfor (; i < cipher_smw_map_size; i++) {
\t\tif (cipher_smw_map[i].algo == algo)
\t\t\treturn cipher_smw_map[i].key_type;
\t}

\treturn SMW_KEY_TYPE_NAME_NONE;
}
""")

    return ''.join(lines)


def generate_psa_mapping_header():
    """Generate psa_cipher_mapping_generated.h."""
    year = datetime.now().year

    return (f"{_file_header(year)}"
            "#ifndef CIPHER_PSA_MAPPING_GENERATED_H\n"
            "#define CIPHER_PSA_MAPPING_GENERATED_H\n\n"
            "#include <psa/crypto.h>\n\n"
            "#include \"cipher_algo_generated.h\"\n\n"
            "psa_algorithm_t get_psa_cipher_alg(enum cipher_algo algo);\n\n"
            "const char *get_psa_cipher_alg_name(psa_algorithm_t alg);\n\n"
            "#endif /* CIPHER_PSA_MAPPING_GENERATED_H */\n")


def generate_psa_mapping_source(combinations):
    """Generate psa_cipher_mapping_generated.c."""
    year = datetime.now().year

    lines = [_file_header(year, [
        '#include <psa/crypto.h>',
        '',
        '#include "cipher_algo_generated.h"',
        '#include "psa_cipher_mapping_generated.h"',
    ])]

    lines.append("struct cipher_psa_mapping {\n"
                 "\tenum cipher_algo algo;\n"
                 "\tpsa_algorithm_t psa_alg;\n"
                 "};\n\n")

    lines.append(
        "static const struct cipher_psa_mapping cipher_psa_map[] = {\n")
    for c in combinations:
        lines.append(f"\t{{ {c['enum']}, {c['psa_alg_macro']} }},\n")
    lines.append(
        "\t{ CIPHER_ALGO_NONE, PSA_ALG_NONE },\n"
        "};\n\n"
        "static const size_t cipher_psa_map_size =\n"
        "\tsizeof(cipher_psa_map) / sizeof(cipher_psa_map[0]) - 1;\n\n")

    unique_psa = []
    seen_macros = set()
    for c in combinations:
        macro = c['psa_alg_macro']
        if macro != 'PSA_ALG_NONE' and macro not in seen_macros:
            seen_macros.add(macro)
            unique_psa.append(macro)

    lines.append("struct psa_alg_name_entry {\n"
                 "\tpsa_algorithm_t alg;\n"
                 "\tconst char *name;\n"
                 "};\n\n")

    lines.append(
        "static const struct psa_alg_name_entry psa_alg_names[] = {\n")
    for macro in unique_psa:
        lines.append(f'\t{{ {macro}, "{macro}" }},\n')
    lines.append("};\n\n")

    lines.append(
        "static const size_t psa_alg_names_size =\n"
        "\tsizeof(psa_alg_names) / sizeof(psa_alg_names[0]);\n\n")

    lines.append("""\
psa_algorithm_t get_psa_cipher_alg(enum cipher_algo algo)
{
\tsize_t i = 0;

\tfor (; i < cipher_psa_map_size; i++) {
\t\tif (cipher_psa_map[i].algo == algo)
\t\t\treturn cipher_psa_map[i].psa_alg;
\t}

\treturn PSA_ALG_NONE;
}

const char *get_psa_cipher_alg_name(psa_algorithm_t alg)
{
\tsize_t i = 0;

\tfor (; i < psa_alg_names_size; i++) {
\t\tif (psa_alg_names[i].alg == alg)
\t\t\treturn psa_alg_names[i].name;
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
    psa_sym_key_mappings = output_dir / "psa_sym_key_mappings_generated.c"

    for path in (smw_names_h, psa_sym_key_mappings):
        if not path.exists():
            print(f"ERROR: File not found: {path}", file=sys.stderr)
            sys.exit(1)

    # Parse SMW names.h
    print(f"Parsing {smw_names_h}...")
    with open(smw_names_h, 'r') as f:
        smw_content = f.read()

    mode_descriptions = parse_cipher_mode_descriptions(smw_content)
    modes = parse_cipher_modes_with_tags(smw_content)

    print(f"Found {len(mode_descriptions)} cipher mode descriptions")
    print(f"Found {len(modes)} tagged cipher modes")

    if not modes:
        print("ERROR: No tagged cipher modes found in names.h",
              file=sys.stderr)
        sys.exit(1)

    for mode in modes:
        iv_info = "needs IV" if mode['needs_iv'] else "no IV"
        print(f"  {mode['mode_name']}: "
              f"{', '.join(mode['key_types'])} ({iv_info})")

    # Parse PSA cipher mappings from already generated file
    print(f"\nParsing {psa_sym_key_mappings}...")
    with open(psa_sym_key_mappings, 'r') as f:
        psa_content = f.read()

    psa_mode_to_alg = parse_psa_cipher_algorithms(psa_content)
    print(f"Found {len(psa_mode_to_alg)} PSA cipher algorithm mappings")
    for mode, macro in psa_mode_to_alg.items():
        print(f"  {mode} → {macro}")

    # Warn about modes without PSA mapping
    for mode in modes:
        if mode['mode_name'] not in psa_mode_to_alg:
            print(f"WARNING: No PSA mapping for mode {mode['mode_name']}",
                  file=sys.stderr)

    # Build combinations
    combinations = build_cipher_combinations(modes, mode_descriptions,
                                             psa_mode_to_alg)
    print(f"\nGenerated {len(combinations)} cipher algorithm combinations:")
    for c in combinations:
        print(f"  {c['enum']:30s} → {c['name']:12s}"
              f"  (PSA: {c['psa_alg_macro']})")

    # Write output files
    output_dir.mkdir(parents=True, exist_ok=True)

    files = {
        "cipher_algo_generated.h":
            generate_core_header(combinations),
        "cipher_algo_generated.c":
            generate_core_source(combinations),
        "smw_cipher_mapping_generated.h":
            generate_smw_mapping_header(),
        "smw_cipher_mapping_generated.c":
            generate_smw_mapping_source(combinations),
        "psa_cipher_mapping_generated.h":
            generate_psa_mapping_header(),
        "psa_cipher_mapping_generated.c":
            generate_psa_mapping_source(combinations),
    }

    for name, content in files.items():
        path = output_dir / name
        with open(path, 'w') as f:
            f.write(content)
        print(f"Generated {path}")


if __name__ == "__main__":
    main()
