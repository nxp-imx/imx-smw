// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <psa/crypto.h>
#include "helper.h"
#include "keygen_common.h"
#include "logger.h"

/**
 * @brief Parse PSA usage flags from comma-separated string
 *
 * @param usage_str Comma-separated usage flags
 */
psa_key_usage_t parse_psa_usage_flags(const char *usage_str)
{
	psa_key_usage_t flags = 0;
	char *usage_copy = NULL;
	char *token = NULL;
	char *saveptr = NULL;

	if (!usage_str)
		return 0;

	usage_copy = strdup(usage_str);
	if (!usage_copy)
		return 0;

	token = strtok_r(usage_copy, ",", &saveptr);
	while (token) {
		/* Trim whitespace */
		while (*token == ' ')
			token++;

		if (!strcasecmp(token, "sign")) {
			flags |= PSA_KEY_USAGE_SIGN_MESSAGE;
		} else if (!strcasecmp(token, "verify")) {
			flags |= PSA_KEY_USAGE_VERIFY_MESSAGE;
		} else if (!strcasecmp(token, "sign_hash")) {
			flags |= PSA_KEY_USAGE_SIGN_HASH;
		} else if (!strcasecmp(token, "verify_hash")) {
			flags |= PSA_KEY_USAGE_VERIFY_HASH;
		} else if (!strcasecmp(token, "encrypt")) {
			flags |= PSA_KEY_USAGE_ENCRYPT;
		} else if (!strcasecmp(token, "decrypt")) {
			flags |= PSA_KEY_USAGE_DECRYPT;
		} else if (!strcasecmp(token, "derive")) {
			flags |= PSA_KEY_USAGE_DERIVE;
		} else if (!strcasecmp(token, "export")) {
			flags |= PSA_KEY_USAGE_EXPORT;
		} else {
			free(usage_copy);
			return 0;
		}

		token = strtok_r(NULL, ",", &saveptr);
	}

	free(usage_copy);
	return flags;
}

/**
 * @brief Convert PSA usage flags to string representation
 *
 * @param usage_flags Usage flags from key attributes
 * @param buffer Output buffer for usage string
 * @param buffer_size Size of output buffer
 */
void usage_flags_to_string(psa_key_usage_t usage_flags, char *buf,
			   size_t buf_size)
{
	static const struct {
		psa_key_usage_t flag;
		const char *name;
	} usage_map[] = {
		{ PSA_KEY_USAGE_SIGN_MESSAGE, "sign" },
		{ PSA_KEY_USAGE_VERIFY_MESSAGE, "verify" },
		{ PSA_KEY_USAGE_SIGN_HASH, "sign_hash" },
		{ PSA_KEY_USAGE_VERIFY_HASH, "verify_hash" },
		{ PSA_KEY_USAGE_ENCRYPT, "encrypt" },
		{ PSA_KEY_USAGE_DECRYPT, "decrypt" },
		{ PSA_KEY_USAGE_DERIVE, "derive" },
		{ PSA_KEY_USAGE_EXPORT, "export" },
		{ PSA_KEY_USAGE_COPY, "copy" },
	};

	size_t i = 0;
	bool first = true;
	size_t buf_len = 0;
	size_t name_len = 0;
	size_t sep_len = 0;
	size_t required_space = 0;

	if (!buf || buf_size == 0)
		return;

	buf[0] = '\0';

	for (i = 0; i < ARRAY_SIZE(usage_map); i++) {
		if (!(usage_flags & usage_map[i].flag))
			continue;

		buf_len = strlen(buf);
		sep_len = first ? 0u : 2u; /* ", " separator */
		name_len = strlen(usage_map[i].name);

		/* Check for overflow before addition */
		if (buf_len > SIZE_MAX - sep_len)
			break;
		if (buf_len + sep_len > SIZE_MAX - name_len)
			break;
		if (buf_len + sep_len + name_len > SIZE_MAX - 1u)
			break;

		required_space = buf_len + sep_len + name_len + 1u;
		if (required_space > buf_size)
			break;

		if (!first) {
			/* Safe: we checked buf_len + 2 + 1 <= buf_size */
			strncat(buf, ", ", buf_size - buf_len - 1u);
			buf_len = strlen(buf);
		}

		/* Safe: we checked total required space */
		if (buf_len < buf_size - 1u)
			strncat(buf, usage_map[i].name,
				buf_size - buf_len - 1u);

		first = false;
	}
}

/**
 * @brief Log PSA key generation parameters
 *
 * @param attributes Pointer to PSA key attributes
 * @param key_id Key identifier
 */
void log_psa_keygen_params(const psa_key_attributes_t *attributes,
			   psa_key_id_t key_id)
{
	if (!attributes)
		return;

	LOG_INFO("=== psa_generate_key Parameters ===");
	LOG_INFO("  key_id: 0x%08x (%u)", key_id, key_id);
	LOG_INFO("  key_type: 0x%08x", psa_get_key_type(attributes));
	LOG_INFO("  key_bits: %zu", psa_get_key_bits(attributes));
	LOG_INFO("  algorithm: 0x%08x", psa_get_key_algorithm(attributes));
	LOG_INFO("  usage_flags: 0x%08x", psa_get_key_usage_flags(attributes));
	LOG_INFO("  lifetime: 0x%08x", psa_get_key_lifetime(attributes));
	LOG_INFO("====================================");
}
