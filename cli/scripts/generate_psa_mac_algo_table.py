#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2026 NXP

"""
Generate PSA MAC algorithm tables for the CLI parser by reading the already
generated psa_sym_key_mappings_generated.c file.

Extracts:
  - psa_cmac_algos[]      -> CMAC-based algorithms (CBC-MAC, CMAC, ...)
  - psa_hmac_hash_algos[] -> HMAC hash algorithms (SHA256, ...)

And generates:
  - psa_mac_algo_table_generated.c -> backend-agnostic accessor functions
                                      + PSA-specific tables + mapping functions
  - psa_mac_algo_table_generated.h -> PSA-specific struct + declarations
"""

import re
import sys
from datetime import datetime
from pathlib import Path


def find_all_algo_arrays(content):
    """Find all algo_mapping array names in the file for debugging."""
    pattern = r'static\s+const\s+struct\s+algo_mapping\s+(\w+)\s*\['
    return re.findall(pattern, content)


def parse_algo_array_names_only(content, array_name):
    """
    Parse a C array using brace-depth scanning.
    Returns list of name strings only.
    Handles nested macros like PSA_ALG_HMAC(PSA_ALG_SHA_256).
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

    # Extract quoted names only — handles both simple and nested macros
    names = re.findall(r'\{\s*"([^"]+)"\s*,', block)
    return names


def parse_algo_array_with_macros(content, array_name):
    """
    Parse a C array using brace-depth scanning.
    Returns list of (name, full_macro_expr) tuples.
    Captures the full macro expression including nested calls.

    e.g.:
      { "CMAC", (uint32_t)PSA_ALG_CMAC }
        -> ("CMAC", "PSA_ALG_CMAC")
      { "SHA256", (uint32_t)PSA_ALG_HMAC(PSA_ALG_SHA_256) }
        -> ("SHA256", "PSA_ALG_HMAC(PSA_ALG_SHA_256)")
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

    # Match { "NAME", (uint32_t)<anything up to } or ,> }
    # Captures full macro expression including nested parens
    entries = re.findall(
        r'\{\s*"([^"]+)"\s*,\s*\(uint32_t\)([\w()]+)\s*\}',
        block
    )
    return entries


def make_truncated_name(name):
    """
    Build the truncated variant name.
    e.g. "CMAC" -> "CMAC_TRUNCATED", "CBC-MAC" -> "CBC-MAC_TRUNCATED"
    """
    return f"{name}_TRUNCATED"


def psa_mac_enum(name):
    """
    Map a CMAC base name to its PSA algorithm macro.
    e.g. "CMAC" -> "PSA_ALG_CMAC", "CBC-MAC" -> "PSA_ALG_CBC_MAC"
    """
    mapping = {
        "CMAC":    "PSA_ALG_CMAC",
        "CBC-MAC": "PSA_ALG_CBC_MAC",
    }
    return mapping.get(name, f"PSA_ALG_{name.replace('-', '_')}")


def generate_header(cmac_names, hmac_hash_entries, year):
    """Generate the PSA .h file content."""

    return f"""\
// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright {year} NXP
 */

/* AUTO-GENERATED FILE - DO NOT EDIT */

#ifndef PSA_MAC_ALGO_TABLE_GENERATED_H
#define PSA_MAC_ALGO_TABLE_GENERATED_H

#include <stddef.h>
#include <stdbool.h>
#include <psa/crypto.h>

/**
 * struct psa_mac_algo_entry - PSA MAC algorithm table entry
 * @name:         Algorithm name string (e.g. "CMAC", "CBC-MAC")
 * @psa_algo:     Corresponding PSA MAC algorithm value
 * @needs_hash:   true if HMAC base (requires hash suffix)
 * @is_truncated: true if truncated variant
 */
struct psa_mac_algo_entry {{
\tconst char *name;
\tpsa_algorithm_t psa_algo;
\tbool needs_hash;
\tbool is_truncated;
}};

/**
 * struct psa_hash_algo_entry - PSA HMAC hash algorithm table entry
 * @name:      Hash algorithm name string (e.g. "SHA256")
 * @psa_hash:  Corresponding PSA hash algorithm value
 */
struct psa_hash_algo_entry {{
\tconst char *name;
\tpsa_algorithm_t psa_hash;
}};

/* PSA-specific MAC base table */
extern const struct psa_mac_algo_entry psa_mac_base_algos[];
extern const size_t psa_mac_base_algos_count;

/* PSA-specific HMAC hash table */
extern const struct psa_hash_algo_entry psa_hmac_hash_algos_map[];
extern const size_t psa_hmac_hash_algos_map_count;

/**
 * cli_mac_base_to_psa() - Convert base MAC algorithm string to PSA algo.
 * @base:      Base algorithm string (e.g. "CMAC", "CBC-MAC")
 * @truncated: Output: true if truncated variant
 *
 * Table-driven lookup against psa_mac_base_algos[].
 *
 * Return: PSA algorithm value, or PSA_ALG_NONE on error.
 */
psa_algorithm_t cli_mac_base_to_psa(const char *base, bool *truncated);

/**
 * cli_hash_str_to_psa() - Convert hash algorithm string to PSA hash algo.
 * @hash_str: Hash algorithm string (e.g. "SHA256", "MD5")
 *
 * Table-driven lookup against psa_hmac_hash_algos_map[].
 *
 * Return: PSA hash algorithm value, or PSA_ALG_NONE on error.
 */
psa_algorithm_t cli_hash_str_to_psa(const char *hash_str);

#endif /* PSA_MAC_ALGO_TABLE_GENERATED_H */
"""


def generate_source(cmac_names, hmac_hash_entries, year):
    """Generate the PSA .c file content."""

    # Backend-agnostic base entries (name + flags only)
    base_entries = []
    for name in cmac_names:
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

    if hash_entries:
        hash_entries_str = '\n'.join(hash_entries)
    else:
        hash_entries_str = '\t/* No HMAC hash algorithms available */'

    # PSA-specific base entries (with psa_algo field)
    # Non-truncated: use base PSA algo
    # Truncated: use PSA_ALG_TRUNCATED_MAC(base, 0) as placeholder
    #            actual truncation size is applied at runtime
    psa_base_entries = []
    for name in cmac_names:
        algo = psa_mac_enum(name)
        psa_base_entries.append(
            f'\t{{ "{name}", {algo}, false, false }},'
        )
        trunc = make_truncated_name(name)
        psa_base_entries.append(
            f'\t{{ "{trunc}", {algo}, false, true }},'
        )
    if hmac_hash_entries:
        psa_base_entries.append(
            '\t{ "HMAC", PSA_ALG_HMAC_BASE, true, false },'
        )
        psa_base_entries.append(
            '\t{ "HMAC_TRUNCATED", PSA_ALG_HMAC_BASE, true, true },'
        )

    psa_base_entries_str = '\n'.join(psa_base_entries)

    # PSA-specific hash entries (with psa_hash field)
    # Extract the inner hash macro from PSA_ALG_HMAC(PSA_ALG_SHA_256)
    psa_hash_entries = []
    for name, macro in hmac_hash_entries:
        # macro is e.g. "PSA_ALG_HMAC(PSA_ALG_SHA_256)"
        # extract inner: PSA_ALG_SHA_256
        inner_match = re.search(r'PSA_ALG_HMAC\((\w+)\)', macro)
        if inner_match:
            inner = inner_match.group(1)
        else:
            # fallback: use macro as-is (simple case)
            inner = macro
        psa_hash_entries.append(
            f'\t{{ "{name}", {inner} }},'
        )

    if psa_hash_entries:
        psa_hash_entries_str = '\n'.join(psa_hash_entries)
    else:
        psa_hash_entries_str = '\t/* No HMAC hash algorithms available */'

    return f"""\
// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright {year} NXP
 */

/* AUTO-GENERATED FILE - DO NOT EDIT */

#include <stddef.h>
#include <stdbool.h>
#include <strings.h>
#include <psa/crypto.h>

#include "mac_algo_mappings.h"
#include "psa_mac_algo_table_generated.h"

/*
 * Backend-agnostic base MAC entry table (name + flags only).
 * Used by parser_mac.c via get_mac_base_entries().
 * Derived from psa_cmac_algos[] in psa_sym_key_mappings_generated.c.
 */
static const struct mac_base_entry mac_base_table[] = {{
{base_entries_str}
}};

/*
 * Backend-agnostic HMAC hash entry table (name only).
 * Used by parser_mac.c via get_mac_hash_entries().
 * Derived from psa_hmac_hash_algos[] in psa_sym_key_mappings_generated.c.
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
 * PSA-specific tables (used by cli/psa/mac.c)
 * ----------------------------------------------------------------------- */

/*
 * PSA MAC base algorithm table (with psa_algo field).
 * Derived from psa_cmac_algos[] in psa_sym_key_mappings_generated.c.
 * For truncated variants, psa_algo holds the base algorithm —
 * PSA_ALG_TRUNCATED_MAC() is applied at runtime once MAC size is known.
 */
const struct psa_mac_algo_entry psa_mac_base_algos[] = {{
{psa_base_entries_str}
}};

const size_t psa_mac_base_algos_count =
\tsizeof(psa_mac_base_algos) / sizeof(psa_mac_base_algos[0]);

/*
 * PSA HMAC hash algorithm table (with psa_hash field).
 * Derived from psa_hmac_hash_algos[] in psa_sym_key_mappings_generated.c.
 * psa_hash holds the raw hash algo (e.g. PSA_ALG_SHA_256),
 * PSA_ALG_HMAC() is applied at runtime in cli_hash_str_to_psa().
 */
const struct psa_hash_algo_entry psa_hmac_hash_algos_map[] = {{
{psa_hash_entries_str}
}};

const size_t psa_hmac_hash_algos_map_count =
\tsizeof(psa_hmac_hash_algos_map) / sizeof(psa_hmac_hash_algos_map[0]);

/* -----------------------------------------------------------------------
 * PSA-specific mapping functions (used by cli/psa/mac.c)
 * ----------------------------------------------------------------------- */

/**
 * cli_mac_base_to_psa() - Convert base MAC algorithm string to PSA algo.
 *
 * Table-driven: iterates psa_mac_base_algos[] — no if-chains.
 * Sets *truncated = true for CMAC_TRUNCATED / HMAC_TRUNCATED variants.
 */
psa_algorithm_t cli_mac_base_to_psa(const char *base, bool *truncated)
{{
\tsize_t i = 0;

\tif (!base || !truncated)
\t\treturn PSA_ALG_NONE;

\t*truncated = false;

\tfor (; i < psa_mac_base_algos_count; i++) {{
\t\tif (!strcasecmp(base, psa_mac_base_algos[i].name)) {{
\t\t\t*truncated = psa_mac_base_algos[i].is_truncated;
\t\t\treturn psa_mac_base_algos[i].psa_algo;
\t\t}}
\t}}

\treturn PSA_ALG_NONE;
}}

/**
 * cli_hash_str_to_psa() - Convert hash algorithm string to PSA hash algo.
 *
 * Table-driven: iterates psa_hmac_hash_algos_map[] — no if-chains.
 * Returns the raw hash algo (e.g. PSA_ALG_SHA_256).
 * Caller applies PSA_ALG_HMAC() if needed.
 */
psa_algorithm_t cli_hash_str_to_psa(const char *hash_str)
{{
\tsize_t i = 0;

\tif (!hash_str || !*hash_str)
\t\treturn PSA_ALG_NONE;

\tfor (; i < psa_hmac_hash_algos_map_count; i++) {{
\t\tif (!strcasecmp(hash_str, psa_hmac_hash_algos_map[i].name))
\t\t\treturn psa_hmac_hash_algos_map[i].psa_hash;
\t}}

\treturn PSA_ALG_NONE;
}}
"""


def main():
    if len(sys.argv) < 3:
        print(
            "Usage: generate_psa_mac_algo_table.py "
            "<psa_sym_key_mappings_generated.c> <output_dir>",
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

    all_arrays = find_all_algo_arrays(content)
    print(f"DEBUG: Found algo_mapping arrays: {all_arrays}")

    # Extract CMAC names from psa_cmac_algos[]
    cmac_names = parse_algo_array_names_only(content, "psa_cmac_algos")
    print(f"Found {len(cmac_names)} CMAC algorithm(s): {cmac_names}")

    # Extract HMAC hash entries with macros from psa_hmac_hash_algos[]
    hmac_hash_entries = parse_algo_array_with_macros(
        content, "psa_hmac_hash_algos")
    print(f"Found {len(hmac_hash_entries)} HMAC hash algorithm(s): "
          f"{[n for n, m in hmac_hash_entries]}")

    if not cmac_names and not hmac_hash_entries:
        print("ERROR: No MAC algorithms found in input file", file=sys.stderr)
        print("       Available arrays:", all_arrays, file=sys.stderr)
        sys.exit(1)

    output_dir.mkdir(parents=True, exist_ok=True)

    output_h = output_dir / "psa_mac_algo_table_generated.h"
    output_c = output_dir / "psa_mac_algo_table_generated.c"

    output_h.write_text(
        generate_header(cmac_names, hmac_hash_entries, year))
    output_c.write_text(
        generate_source(cmac_names, hmac_hash_entries, year))

    print(f"Generated {output_h}")
    print(f"Generated {output_c}")


if __name__ == "__main__":
    main()
