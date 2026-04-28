/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2026 NXP
 */

#ifndef KEYGEN_COMMON_H
#define KEYGEN_COMMON_H

#include <stddef.h>
#include <stdbool.h>
#include <smw_keymgr.h>

smw_attr_usage_t parse_smw_usage_flags(const char *usage_str);

void append_usage_str(char *buffer, size_t buffer_size, size_t *written,
		      const char *usage);

void usage_flags_to_string(smw_attr_usage_t usage_flags, char *buffer,
			   size_t buffer_size);

void log_smw_keygen_params(const struct smw_generate_key_args *args);

#endif /* KEYGEN_COMMON_H */
