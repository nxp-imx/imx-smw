#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2026 NXP

"""
Generate SMW MAC algorithm tables for the CLI parser by reading the already
generated smw_sym_key_mappings_generated.c file.

Extracts:
  - smw_cmac_algos[]      -> CMAC base algorithms (e.g. "CMAC")
  - smw_hmac_hash_algos[] -> HMAC hash algorithms (e.g. "SHA256")

And generates:
  - smw_mac_algo_table_generated.h -> SMW-specific structs + declarations
  - smw_mac_algo_table_generated.c -> backend-agnostic accessor functions
                                      + SMW-specific tables + mapping functions
"""

import re
import sys
from datetime import datetime
from pathlib import Path


def find_all_algo_arrays(content):
    """
    Find all algo_mapping array names in the file for debugging.
    """
    pattern = r'static\s+const\s+struct\s+algo_mapping\s+(\w+)\s*\['
    return re.findall(pattern, content)


def parse_algo_array(content, array_name):
    """
    Parse a C array using brace-depth scanning to handle nested braces.

    Handles arrays of the form:
        static const struct algo_mapping <array_name>[] = {
            { "NAME", (uint32_t)MACRO },
            ...
        };

    Returns list of (name, macro) tuples.
    """
    start_pattern = (
        r'static\s+const\s+struct\s+algo_mapping\s+' +
        re.escape(array_name) +
        r'\s*\[\s*\]\s*=\s*\{'
    )

    start_match = re.search(start_pattern, content)
    if not start_match:
        print(f"WARNING: Array '{array_name}' not found in generated file",
              file=sys.stderr)
        return []

    # Manually scan from the opening '{' to find the matching '};'
    pos = start_match.end() - 1
    depth = 0
    block_start = pos
    block_end = pos

    for i in range(pos, len(content)):
        if content[i] == '{':
            depth += 1
        elif content[i] == '}':
            depth -= 1
            if depth == 0:
                block_end = i
                break

    block = content[block_start:block_end + 1]

    # Extract { "NAME", (uint32_t)MACRO } entries
    entries = re.findall(
        r'\{\s*"([^"]+)"\s*,\s*\(uint32_t\)(\w+)\s*\}', block
    )

    return entries


def make_truncated_name(name):
    """
    Build the truncated variant name for a given base algo name.
    e.g. "CMAC" -> "CMAC_TRUNCATED"
    """
    return f"{name}_TRUNCATED"


def smw_mac_enum(name):
    """SMW MAC enum name e.g. "CMAC" -> "SMW_MAC_ALGO_NAME_CMAC" """
    return f"SMW_MAC_ALGO_NAME_{name}"


def smw_hash_enum(name):
    """SMW hash enum name e.g. "SHA256" -> "SMW_HASH_ALGO_NAME_SHA256" """
    return f"SMW_HASH_ALGO_NAME_{name}"


def generate_header(cmac_entries, hmac_hash_entries, year):
    """Generate the .h file content."""

    return f"""\
// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright {year} NXP
 */

/* AUTO-GENERATED FILE - DO NOT EDIT */

#ifndef SMW_MAC_ALGO_TABLE_GENERATED_H
#define SMW_MAC_ALGO_TABLE_GENERATED_H

#include <stddef.h>
#include <stdbool.h>
#include <smw_crypto.h>

/**
 * struct mac_algo_entry - SMW MAC algorithm table entry
 * @name:         Algorithm name string (e.g. "CMAC", "CMAC_TRUNCATED")
 * @smw_algo:     Corresponding SMW MAC algorithm enum value
 * @needs_hash:   true if this is an HMAC base (requires hash suffix)
 * @is_truncated: true if this is a truncated variant
 */
struct mac_algo_entry {{
\tconst char *name;
\tsmw_mac_algo_t smw_algo;
\tbool needs_hash;
\tbool is_truncated;
}};

/**
 * struct hash_algo_entry - SMW HMAC hash algorithm table entry
 * @name:      Hash algorithm name string (e.g. "SHA256")
 * @smw_hash:  Corresponding SMW hash algorithm enum value
 */
struct hash_algo_entry {{
\tconst char *name;
\tsmw_hash_algo_t smw_hash;
}};

/* SMW-specific MAC base table (with smw_algo field) */
extern const struct mac_algo_entry smw_mac_base_algos[];
extern const size_t smw_mac_base_algos_count;

/* SMW-specific HMAC hash table (with smw_hash field) */
extern const struct hash_algo_entry smw_hmac_hash_algos[];
extern const size_t smw_hmac_hash_algos_count;

/**
 * cli_mac_base_to_smw() - Convert base MAC algorithm string to SMW enum.
 * @base: Base algorithm string (e.g. "CMAC", "HMAC", "HMAC_TRUNCATED")
 *
 * Table-driven lookup against smw_mac_base_algos[].
 *
 * Return: SMW MAC algorithm enum value, or SMW_MAC_ALGO_NAME_NONE on error.
 */
smw_mac_algo_t cli_mac_base_to_smw(const char *base);

/**
 * cli_hash_str_to_smw() - Convert hash algorithm string to SMW enum.
 * @hash_str: Hash algorithm string (e.g. "SHA256", "MD5")
 *
 * Table-driven lookup against smw_hmac_hash_algos[].
 *
 * Return: SMW hash algorithm enum value, or SMW_HASH_ALGO_NAME_NONE on error.
 */
smw_hash_algo_t cli_hash_str_to_smw(const char *hash_str);

#endif /* SMW_MAC_ALGO_TABLE_GENERATED_H */
"""


def generate_source(cmac_entries, hmac_hash_entries, year):
    """Generate the .c file content."""

    # Backend-agnostic base entries (name + flags only)
    base_entries = []
    for name, macro in cmac_entries:
        base_entries.append(f'\t{{ "{name}", false, false }},')
        base_entries.append(
            f'\t{{ "{make_truncated_name(name)}", false, true }},')
    if hmac_hash_entries:
        base_entries.append('\t{ "HMAC", true, false },')
        base_entries.append('\t{ "HMAC_TRUNCATED", true, true },')

    base_entries_str = '\n'.join(base_entries)

    # Backend-agnostic hash entries (name only)
    hash_entries = []
    for name, macro in hmac_hash_entries:
        hash_entries.append(f'\t{{ "{name}" }},')

    hash_entries_str = '\n'.join(hash_entries)

    # SMW-specific base entries (with smw_algo field)
    smw_base_entries = []
    for name, macro in cmac_entries:
        smw_base_entries.append(
            f'\t{{ "{name}", {smw_mac_enum(name)}, false, false }},'
        )
        trunc = make_truncated_name(name)
        smw_base_entries.append(
            f'\t{{ "{trunc}", {smw_mac_enum(trunc)}, false, true }},'
        )
    if hmac_hash_entries:
        smw_base_entries.append(
            f'\t{{ "HMAC", {smw_mac_enum("HMAC")}, true, false }},'
        )
        smw_base_entries.append(
            f'\t{{ "HMAC_TRUNCATED", {smw_mac_enum("HMAC_TRUNCATED")},'
            f' true, true }},'
        )

    smw_base_entries_str = '\n'.join(smw_base_entries)

    # SMW-specific hash entries (with smw_hash field)
    smw_hash_entries = []
    for name, macro in hmac_hash_entries:
        smw_hash_entries.append(
            f'\t{{ "{name}", {smw_hash_enum(name)} }},'
        )

    smw_hash_entries_str = '\n'.join(smw_hash_entries)

    return f"""\
// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright {year} NXP
 */

/* AUTO-GENERATED FILE - DO NOT EDIT */

#include <stddef.h>
#include <stdbool.h>
#include <strings.h>
#include <smw_crypto.h>

#include "mac_algo_mappings.h"
#include "smw_mac_algo_table_generated.h"

/*
 * Backend-agnostic base MAC entry table (name + flags only).
 * Used by parser_mac.c via get_mac_base_entries().
 * Derived from smw_cmac_algos[] in smw_sym_key_mappings_generated.c.
 */
static const struct mac_base_entry mac_base_table[] = {{
{base_entries_str}
}};

/*
 * Backend-agnostic HMAC hash entry table (name only).
 * Used by parser_mac.c via get_mac_hash_entries().
 * Derived from smw_hmac_hash_algos[] in smw_sym_key_mappings_generated.c.
 */
static const struct mac_hash_entry mac_hash_table[] = {{
{hash_entries_str}
}};

/* -----------------------------------------------------------------------
 * Implement mac_algo_mappings.h interface (used by parser_mac.c)
 * ----------------------------------------------------------------------- */

const struct mac_base_entry *get_mac_base_entries(void)
{{
\treturn mac_base_table;
}}

size_t get_mac_base_entries_count(void)
{{
\treturn sizeof(mac_base_table) / sizeof(mac_base_table[0]);
}}

const struct mac_hash_entry *get_mac_hash_entries(void)
{{
\treturn mac_hash_table;
}}

size_t get_mac_hash_entries_count(void)
{{
\treturn sizeof(mac_hash_table) / sizeof(mac_hash_table[0]);
}}

/* -----------------------------------------------------------------------
 * SMW-specific tables (used by cli/smw/mac.c)
 * ----------------------------------------------------------------------- */

const struct mac_algo_entry smw_mac_base_algos[] = {{
{smw_base_entries_str}
}};

const size_t smw_mac_base_algos_count =
\tsizeof(smw_mac_base_algos) / sizeof(smw_mac_base_algos[0]);

const struct hash_algo_entry smw_hmac_hash_algos[] = {{
{smw_hash_entries_str}
}};

const size_t smw_hmac_hash_algos_count =
\tsizeof(smw_hmac_hash_algos) / sizeof(smw_hmac_hash_algos[0]);

/* -----------------------------------------------------------------------
 * SMW-specific mapping functions (used by cli/smw/mac.c)
 * ----------------------------------------------------------------------- */

/**
 * cli_mac_base_to_smw() - Convert base MAC algorithm string to SMW enum.
 * Table-driven: iterates smw_mac_base_algos[] — no if-chains.
 */
smw_mac_algo_t cli_mac_base_to_smw(const char *base)
{{
\tsize_t i = 0;

\tif (!base)
\t\treturn SMW_MAC_ALGO_NAME_NONE;

\tfor (; i < smw_mac_base_algos_count; i++) {{
\t\tif (!strcasecmp(base, smw_mac_base_algos[i].name))
\t\t\treturn smw_mac_base_algos[i].smw_algo;
\t}}

\treturn SMW_MAC_ALGO_NAME_NONE;
}}

/**
 * cli_hash_str_to_smw() - Convert hash algorithm string to SMW enum.
 * Table-driven: iterates smw_hmac_hash_algos[] — no if-chains.
 */
smw_hash_algo_t cli_hash_str_to_smw(const char *hash_str)
{{
\tsize_t i = 0;

\tif (!hash_str || !*hash_str)
\t\treturn SMW_HASH_ALGO_NAME_NONE;

\tfor (; i < smw_hmac_hash_algos_count; i++) {{
\t\tif (!strcasecmp(hash_str, smw_hmac_hash_algos[i].name))
\t\t\treturn smw_hmac_hash_algos[i].smw_hash;
\t}}

\treturn SMW_HASH_ALGO_NAME_NONE;
}}
"""


def main():
    if len(sys.argv) < 3:
        print(
            "Usage: generate_smw_mac_algo_table.py "
            "<smw_sym_key_mappings_generated.c> <output_dir>",
            file=sys.stderr
        )
        sys.exit(1)

    input_file = Path(sys.argv[1])
    output_dir = Path(sys.argv[2])

    if not input_file.exists():
        print(f"ERROR: Input file not found: {input_file}", file=sys.stderr)
        sys.exit(1)

    print(f"Parsing {input_file}...")

    content = input_file.read_text()
    year = datetime.now().year

    # Debug: show all algo_mapping arrays found in the file
    all_arrays = find_all_algo_arrays(content)
    print(f"DEBUG: Found algo_mapping arrays: {all_arrays}")

    # Extract CMAC entries from smw_cmac_algos[]
    cmac_entries = parse_algo_array(content, "smw_cmac_algos")
    print(f"Found {len(cmac_entries)} CMAC algorithm(s): "
          f"{[n for n, m in cmac_entries]}")

    # Extract HMAC hash entries from smw_hmac_hash_algos[]
    hmac_hash_entries = parse_algo_array(content, "smw_hmac_hash_algos")
    print(f"Found {len(hmac_hash_entries)} HMAC hash algorithm(s): "
          f"{[n for n, m in hmac_hash_entries]}")

    if not cmac_entries and not hmac_hash_entries:
        print("ERROR: No MAC algorithms found in input file", file=sys.stderr)
        print("       Available arrays:", all_arrays, file=sys.stderr)
        sys.exit(1)

    output_dir.mkdir(parents=True, exist_ok=True)

    output_h = output_dir / "smw_mac_algo_table_generated.h"
    output_c = output_dir / "smw_mac_algo_table_generated.c"

    output_h.write_text(
        generate_header(cmac_entries, hmac_hash_entries, year))
    output_c.write_text(
        generate_source(cmac_entries, hmac_hash_entries, year))

    print(f"Generated {output_h}")
    print(f"Generated {output_c}")


if __name__ == "__main__":
    main()
