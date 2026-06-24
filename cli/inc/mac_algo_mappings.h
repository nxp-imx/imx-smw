/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2026 NXP
 */

#ifndef CLI_MAC_ALGO_MAPPINGS_H
#define CLI_MAC_ALGO_MAPPINGS_H

#include <stddef.h>
#include <stdbool.h>

#include "backend.h"

/**
 * struct mac_base_entry - MAC base algorithm table entry
 * @name:         Algorithm name string (e.g. "CMAC", "CMAC_TRUNCATED")
 * @needs_hash:   true if this is an HMAC base (requires hash suffix)
 * @is_truncated: true if this is a truncated variant
 */
struct mac_base_entry {
	const char *name;
	bool needs_hash;
	bool is_truncated;
};

/**
 * struct mac_hash_entry - HMAC hash algorithm table entry
 * @name: Hash algorithm name string (e.g. "SHA256")
 */
struct mac_hash_entry {
	const char *name;
};

/* Base MAC algorithm table (CMAC, CMAC_TRUNCATED, HMAC, HMAC_TRUNCATED) */
const struct mac_base_entry *get_mac_base_entries(void);
size_t get_mac_base_entries_count(void);

/* HMAC hash algorithm table (MD5, SHA1, SHA256, ...) */
const struct mac_hash_entry *get_mac_hash_entries(void);
size_t get_mac_hash_entries_count(void);

#endif /* CLI_MAC_ALGO_MAPPINGS_H */
