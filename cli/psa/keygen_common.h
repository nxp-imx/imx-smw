/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2026 NXP
 */

#ifndef KEYGEN_COMMON_PSA_H
#define KEYGEN_COMMON_PSA_H

#include <psa/crypto.h>
#include <stdbool.h>

psa_key_usage_t parse_psa_usage_flags(const char *usage_str);
void usage_flags_to_string(psa_key_usage_t usage_flags, char *buffer,
			   size_t buffer_size);
void log_psa_keygen_params(const psa_key_attributes_t *attributes,
			   psa_key_id_t key_id);

#endif /* KEYGEN_COMMON_PSA_H */
