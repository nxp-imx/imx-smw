#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2026 NXP

"""Generate SMW key type mappings by parsing SMW headers with usage tags"""

import re
import sys
from datetime import datetime
from pathlib import Path


def parse_smw_algorithms_with_tags(header_path):
    with open(header_path, 'r') as f:
        content = f.read()

    algorithms = {'symmetric': [], 'cipher': [], 'aead': [], 'mac': []}

    algo_pattern = r'#define\s+(SMW_ATTR_ALGO_\w+)\s+\S+\s*/\*\s*\[([^\]]+)\]\s*\*/'

    for match in re.finditer(algo_pattern, content):
        macro_name    = match.group(1)
        tags          = [tag.strip() for tag in match.group(2).split(',')]
        friendly_name = macro_name.replace('SMW_ATTR_ALGO_', '')
        key_type_macro = macro_name.replace('SMW_ATTR_ALGO_', 'SMW_KEY_TYPE_NAME_')

        algo_info = {
            'name': friendly_name,
            'key_type_macro': key_type_macro,
            'attr_algo_macro': macro_name,
            'tags': tags,
        }

        if 'symmetric' in tags:
            algorithms['symmetric'].append(algo_info)
        if 'cipher' in tags:
            algorithms['cipher'].append(algo_info)
        if 'aead' in tags:
            algorithms['aead'].append(algo_info)
        if 'mac' in tags:
            algorithms['mac'].append(algo_info)

    return algorithms


def parse_smw_modes_with_tags(header_path):
    with open(header_path, 'r') as f:
        content = f.read()

    modes = {'cipher': [], 'aead': [], 'mac': []}

    mode_pattern = r'#define\s+(SMW_ATTR_MODE_\w+)\s+\S+\s*/\*\s*\[([^\]]+)\]\s*\*/'

    for match in re.finditer(mode_pattern, content):
        macro_name    = match.group(1)
        tags          = [tag.strip() for tag in match.group(2).split(',')]
        friendly_name = macro_name.replace('SMW_ATTR_MODE_', '').replace('_NO_PAD', '')

        mode_info = {'name': friendly_name, 'macro': macro_name, 'tags': tags}

        if 'cipher' in tags:
            modes['cipher'].append(mode_info)
        if 'aead' in tags:
            modes['aead'].append(mode_info)
        if 'mac' in tags:
            modes['mac'].append(mode_info)

    return modes


def parse_smw_hash_algorithms(header_path):
    with open(header_path, 'r') as f:
        content = f.read()

    hash_algos = []
    hash_pattern = r'-\s+(SMW_ATTR_HASH_\w+):\s+(.+)'

    for match in re.finditer(hash_pattern, content):
        macro_name  = match.group(1)
        description = match.group(2).strip()

        if any(x in macro_name for x in ['NONE', 'ANY', 'OFFSET', 'MASK', 'SHAKE', 'SHA3_']):
            continue

        friendly_name = macro_name.replace('SMW_ATTR_HASH_', '').replace('_', '-').replace('SHA-', 'SHA')

        hash_algos.append({
            'name': friendly_name,
            'macro': macro_name,
            'description': description
        })

    return hash_algos


def parse_symmetric_key_types(names_h_path):
    with open(names_h_path, 'r') as f:
        content = f.read()

    key_types = []
    pattern = r'(SMW_KEY_TYPE_NAME_(\w+))\s*,\s*/\*\s*\[([^\]]+)\]\s*\*/'

    for match in re.finditer(pattern, content):
        macro_name    = match.group(1)
        friendly_name = match.group(2)
        tags          = [t.strip() for t in match.group(3).split(',')]

        if 'symmetric' not in tags:
            continue

        key_types.append({'name': friendly_name, 'macro': macro_name})

    return key_types


def match_key_types_with_algos(key_types_from_names, algorithms_from_attr):
    matched = []

    for kt in key_types_from_names:
        algo_match = None
        for algo in algorithms_from_attr['symmetric']:
            if algo['name'] == kt['name']:
                algo_match = algo
                break

        if algo_match:
            matched.append({
                'name': kt['name'],
                'key_type_macro': kt['macro'],
                'attr_algo_macro': algo_match['attr_algo_macro'],
                'tags': algo_match['tags'],
            })
        else:
            print(f"WARNING: No matching ATTR_ALGO for {kt['name']}", file=sys.stderr)

    return matched


def get_cmac_key_types(matched_types):
    return [kt for kt in matched_types if 'cipher' in kt['tags']]


def dedup(items):
    seen = set()
    result = []
    for item in items:
        if item['name'] not in seen:
            seen.add(item['name'])
            result.append(item)
    return result


def generate_c_file(matched_types, algorithms, modes, hash_algos, cmac_key_types):
    year = datetime.now().year

    def kt_entries(lst):
        return ''.join(
            f'\t{{ "{a["name"]}", (uint32_t){a["key_type_macro"]} }},\n'
            for a in lst)

    def kt_to_algo_entries(lst):
        return ''.join(
            f'\t{{ (uint32_t){a["key_type_macro"]}, {a["attr_algo_macro"]} }},\n'
            for a in lst)

    def mode_entries(lst):
        return ''.join(
            f'\t{{ "{m["name"]}", (uint32_t){m["macro"]} }},\n'
            for m in lst)

    def hash_entries(lst):
        return ''.join(
            f'\t{{ "{h["name"]}", (uint32_t){h["macro"]} }},\n'
            for h in lst)

    def str_entries(lst):
        return ''.join(f'\t"{a["name"]}",\n' for a in lst)

    cipher_dedup = dedup(algorithms['cipher'])
    aead_dedup   = dedup(algorithms['aead'])
    cmac_dedup   = dedup(cmac_key_types)

    return f"""// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright {year} NXP
 */

/* AUTO-GENERATED FILE - DO NOT EDIT */

#include <stddef.h>
#include <string.h>
#include <strings.h>
#include <smw/attr.h>
#include <smw_keymgr.h>

#include "key_sym_mappings.h"

static const struct key_type_mapping smw_key_types[] = {{
{kt_entries(matched_types)}
}};

static const struct {{
\tuint32_t        key_type;
\tsmw_attr_algo_t attr_algo;
}} key_type_to_algo_table[] = {{
{kt_to_algo_entries(matched_types)}
}};

static const struct algo_mapping smw_cipher_algos[] = {{
{mode_entries(modes['cipher'])}
}};

static const struct algo_mapping smw_aead_algos[] = {{
{mode_entries(modes['aead'])}
}};

static const struct algo_mapping smw_hmac_hash_algos[] = {{
{hash_entries(hash_algos)}
}};

static const struct algo_mapping smw_cmac_algos[] = {{
{mode_entries(modes['mac'])}
}};

static const char *smw_cipher_key_types[] = {{
{str_entries(cipher_dedup)}
}};

static const char *smw_aead_key_types[] = {{
{str_entries(aead_dedup)}
}};

static const char *smw_cmac_key_types[] = {{
{str_entries(cmac_dedup)}
}};

/* -----------------------------------------------------------------------
 * key_sym_mappings.h interface implementation
 * -------------------------------------------------------------------- */

const struct key_type_mapping *get_key_type_mappings(void)
{{
\treturn smw_key_types;
}}

size_t get_key_type_mappings_count(void)
{{
\treturn sizeof(smw_key_types) / sizeof(smw_key_types[0]);
}}

const struct algo_mapping *get_cipher_algo_mappings(void)
{{
\treturn smw_cipher_algos;
}}

size_t get_cipher_algo_mappings_count(void)
{{
\treturn sizeof(smw_cipher_algos) / sizeof(smw_cipher_algos[0]);
}}

const struct algo_mapping *get_aead_algo_mappings(void)
{{
\treturn smw_aead_algos;
}}

size_t get_aead_algo_mappings_count(void)
{{
\treturn sizeof(smw_aead_algos) / sizeof(smw_aead_algos[0]);
}}

const struct algo_mapping *get_cmac_algo_mappings(void)
{{
\treturn smw_cmac_algos;
}}

size_t get_cmac_algo_mappings_count(void)
{{
\treturn sizeof(smw_cmac_algos) / sizeof(smw_cmac_algos[0]);
}}

const struct algo_mapping *get_hmac_hash_algo_mappings(void)
{{
\treturn smw_hmac_hash_algos;
}}

size_t get_hmac_hash_algo_mappings_count(void)
{{
\treturn sizeof(smw_hmac_hash_algos) / sizeof(smw_hmac_hash_algos[0]);
}}

const char **get_cipher_key_types(size_t *count)
{{
\t*count = sizeof(smw_cipher_key_types) / sizeof(smw_cipher_key_types[0]);
\treturn smw_cipher_key_types;
}}

const char **get_aead_key_types(size_t *count)
{{
\t*count = sizeof(smw_aead_key_types) / sizeof(smw_aead_key_types[0]);
\treturn smw_aead_key_types;
}}

const char **get_cmac_key_types(size_t *count)
{{
\t*count = sizeof(smw_cmac_key_types) / sizeof(smw_cmac_key_types[0]);
\treturn smw_cmac_key_types;
}}

int parse_key_type(const char *str, uint32_t *value)
{{
\tsize_t i;
\tsize_t count = sizeof(smw_key_types) / sizeof(smw_key_types[0]);

\tif (!str || !value)
\t\treturn -1;

\tfor (i = 0; i < count; i++) {{
\t\tif (smw_key_types[i].name &&
\t\t    !strcasecmp(str, smw_key_types[i].name)) {{
\t\t\t*value = smw_key_types[i].value;
\t\t\treturn 0;
\t\t}}
\t}}
\treturn -1;
}}

const char *key_type_to_string(uint32_t value)
{{
\tsize_t i;
\tsize_t count = sizeof(smw_key_types) / sizeof(smw_key_types[0]);

\tfor (i = 0; i < count; i++) {{
\t\tif (smw_key_types[i].value == value)
\t\t\treturn smw_key_types[i].name;
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
\t\tcount = sizeof(smw_hmac_hash_algos) / sizeof(smw_hmac_hash_algos[0]);
\t\tfor (i = 0; i < count; i++) {{
\t\t\tif (smw_hmac_hash_algos[i].name &&
\t\t\t    !strcasecmp(algo_str, smw_hmac_hash_algos[i].name)) {{
\t\t\t\t*algo_value = smw_hmac_hash_algos[i].value;
\t\t\t\treturn 0;
\t\t\t}}
\t\t}}
\t\treturn -1;
\t}}

\t/* MAC modes (CMAC ...) */
\tcount = sizeof(smw_cmac_algos) / sizeof(smw_cmac_algos[0]);
\tfor (i = 0; i < count; i++) {{
\t\tif (smw_cmac_algos[i].name &&
\t\t    !strcasecmp(algo_str, smw_cmac_algos[i].name)) {{
\t\t\t*algo_value = smw_cmac_algos[i].value;
\t\t\treturn 0;
\t\t}}
\t}}

\t/* AEAD modes */
\tcount = sizeof(smw_aead_algos) / sizeof(smw_aead_algos[0]);
\tfor (i = 0; i < count; i++) {{
\t\tif (smw_aead_algos[i].name &&
\t\t    !strcasecmp(algo_str, smw_aead_algos[i].name)) {{
\t\t\t*algo_value = smw_aead_algos[i].value;
\t\t\treturn 0;
\t\t}}
\t}}

\t/* Cipher modes */
\tcount = sizeof(smw_cipher_algos) / sizeof(smw_cipher_algos[0]);
\tfor (i = 0; i < count; i++) {{
\t\tif (smw_cipher_algos[i].name &&
\t\t    !strcasecmp(algo_str, smw_cipher_algos[i].name)) {{
\t\t\t*algo_value = smw_cipher_algos[i].value;
\t\t\treturn 0;
\t\t}}
\t}}

\treturn -1;
}}

/* -----------------------------------------------------------------------
 * SMW-specific helper (not part of key_sym_mappings.h)
 * -------------------------------------------------------------------- */

smw_attr_algo_t key_type_to_algo(smw_key_type_t key_type)
{{
\tsize_t i;
\tsize_t count = sizeof(key_type_to_algo_table) /
\t\t       sizeof(key_type_to_algo_table[0]);

\tfor (i = 0; i < count; i++) {{
\t\tif (key_type_to_algo_table[i].key_type == (uint32_t)key_type)
\t\t\treturn key_type_to_algo_table[i].attr_algo;
\t}}
\treturn SMW_ATTR_ALGO_NONE;
}}
"""


def generate_header_file():
    year = datetime.now().year
    return f"""// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright {year} NXP
 */

/* AUTO-GENERATED FILE - DO NOT EDIT */

#ifndef SMW_SYM_KEY_MAPPINGS_GENERATED_H
#define SMW_SYM_KEY_MAPPINGS_GENERATED_H

#include <smw/attr.h>
#include <smw_keymgr.h>

/**
 * key_type_to_algo() - Convert SMW key type to algorithm attribute.
 *
 * SMW-specific helper used by keygen_sym.c to build the permitted_algo
 * field. Not part of the backend-agnostic key_sym_mappings.h interface.
 */
smw_attr_algo_t key_type_to_algo(smw_key_type_t key_type);

#endif /* SMW_SYM_KEY_MAPPINGS_GENERATED_H */
"""


def main():
    if len(sys.argv) < 2:
        print("ERROR: Output directory required", file=sys.stderr)
        sys.exit(1)

    output_dir = Path(sys.argv[1])
    script_dir = Path(__file__).parent
    repo_root  = script_dir.parent.parent

    smw_attr_h  = repo_root / "public" / "smw" / "attr.h"
    smw_names_h = repo_root / "public" / "smw" / "names.h"

    if not smw_attr_h.exists():
        print(f"ERROR: SMW header not found: {smw_attr_h}", file=sys.stderr)
        sys.exit(1)

    if not smw_names_h.exists():
        print(f"ERROR: SMW names header not found: {smw_names_h}", file=sys.stderr)
        sys.exit(1)

    print(f"Parsing {smw_attr_h}...")
    print(f"Parsing {smw_names_h}...")

    key_types_from_names = parse_symmetric_key_types(smw_names_h)
    algorithms           = parse_smw_algorithms_with_tags(smw_attr_h)
    modes                = parse_smw_modes_with_tags(smw_attr_h)
    hash_algos           = parse_smw_hash_algorithms(smw_attr_h)
    matched_types        = match_key_types_with_algos(key_types_from_names, algorithms)
    cmac_key_types       = get_cmac_key_types(matched_types)

    print(f"Found {len(algorithms['symmetric'])} symmetric algorithms")
    print(f"Found {len(modes['cipher'])} cipher modes")
    print(f"Found {len(modes['aead'])} AEAD modes")
    print(f"Found {len(modes['mac'])} MAC (CMAC) modes")
    print(f"Found {len(hash_algos)} hash algorithms (HMAC)")
    print(f"Matched {len(matched_types)} symmetric key types")
    print(f"CMAC key types: {[kt['name'] for kt in cmac_key_types]}")

    output_c = output_dir / "smw_sym_key_mappings_generated.c"
    output_h = output_dir / "smw_sym_key_mappings_generated.h"
    output_c.parent.mkdir(parents=True, exist_ok=True)

    with open(output_c, 'w') as f:
        f.write(generate_c_file(matched_types, algorithms, modes,
                                hash_algos, cmac_key_types))

    with open(output_h, 'w') as f:
        f.write(generate_header_file())

    print(f"Generated {output_c}")
    print(f"Generated {output_h}")


if __name__ == "__main__":
    main()