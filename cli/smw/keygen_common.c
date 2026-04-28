// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <smw_keymgr.h>
#include "common.h"
#include "helper.h"
#include "key_sym_mappings.h"
#include "keygen_common.h"
#include "logger.h"

/**
 * @brief Parse usage flags from comma-separated string
 *
 * @param usage_str Comma-separated usage flags
 */
smw_attr_usage_t parse_smw_usage_flags(const char *usage_str)
{
	smw_attr_usage_t flags = SMW_ATTR_USAGE_NONE;
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
			SMW_ATTR_USAGE_SET_SIGN_MESSAGE(flags);
		} else if (!strcasecmp(token, "verify")) {
			SMW_ATTR_USAGE_SET_VERIFY_MESSAGE(flags);
		} else if (!strcasecmp(token, "sign_hash")) {
			SMW_ATTR_USAGE_SET_SIGN_HASH(flags);
		} else if (!strcasecmp(token, "verify_hash")) {
			SMW_ATTR_USAGE_SET_VERIFY_HASH(flags);
		} else if (!strcasecmp(token, "encrypt")) {
			SMW_ATTR_USAGE_SET_ENCRYPT(flags);
		} else if (!strcasecmp(token, "decrypt")) {
			SMW_ATTR_USAGE_SET_DECRYPT(flags);
		} else if (!strcasecmp(token, "derive")) {
			SMW_ATTR_USAGE_SET_DERIVE(flags);
		} else if (!strcasecmp(token, "export")) {
			SMW_ATTR_USAGE_SET_EXPORT(flags);
		} else {
			LOG_ERROR("Unknown usage flag: %s", token);
			free(usage_copy);
			return 0;
		}

		token = strtok_r(NULL, ",", &saveptr);
	}

	free(usage_copy);
	return flags;
}

/**
 * @brief Append a usage string to a buffer with comma separator
 *
 * @param buffer Destination buffer
 * @param buffer_size Size of the buffer
 * @param written Bytes already written, updated after append
 * @param usage string to append
 */
void append_usage_str(char *buffer, size_t buffer_size, size_t *written,
		      const char *usage)
{
	int ret = 0;

	if (*written > 0 && *written < buffer_size) {
		ret = snprintf(buffer + *written, buffer_size - *written, ", ");
		if (ret > 0 && (size_t)ret < buffer_size - *written)
			*written += ret;
	}

	if (*written < buffer_size) {
		ret = snprintf(buffer + *written, buffer_size - *written, "%s",
			       usage);
		if (ret > 0 && (size_t)ret < buffer_size - *written)
			*written += ret;
	}
}

/**
 * @brief Convert usage flags to string representation
 *
 * @param usage_flags Usage flags from key attributes
 * @param buffer Output buffer for usage string
 * @param buffer_size Size of output buffer
 */
void usage_flags_to_string(smw_attr_usage_t usage_flags, char *buffer,
			   size_t buffer_size)
{
	size_t written = 0;

	if (!buffer || !buffer_size)
		return;

	buffer[0] = '\0';

	if (SMW_ATTR_USAGE_IS_ENCRYPT(usage_flags))
		append_usage_str(buffer, buffer_size, &written, "encrypt");

	if (SMW_ATTR_USAGE_IS_DECRYPT(usage_flags))
		append_usage_str(buffer, buffer_size, &written, "decrypt");

	if (SMW_ATTR_USAGE_IS_SIGN_MESSAGE(usage_flags))
		append_usage_str(buffer, buffer_size, &written, "sign");

	if (SMW_ATTR_USAGE_IS_VERIFY_MESSAGE(usage_flags))
		append_usage_str(buffer, buffer_size, &written, "verify");

	if (SMW_ATTR_USAGE_IS_SIGN_HASH(usage_flags))
		append_usage_str(buffer, buffer_size, &written, "sign_hash");

	if (SMW_ATTR_USAGE_IS_VERIFY_HASH(usage_flags))
		append_usage_str(buffer, buffer_size, &written, "verify_hash");

	if (SMW_ATTR_USAGE_IS_DERIVE(usage_flags))
		append_usage_str(buffer, buffer_size, &written, "derive");

	if (SMW_ATTR_USAGE_IS_EXPORT(usage_flags))
		append_usage_str(buffer, buffer_size, &written, "export");

	if (!written && buffer_size > 0)
		SNPRINTF(buffer, buffer_size, "none");
}

/**
 * @brief Log SMW key generation parameters
 *
 * @param args Pointer to SMW generate key arguments structure
 */
void log_smw_keygen_params(const struct smw_generate_key_args *args)
{
	if (!args || !args->key_descriptor)
		return;

	LOG_INFO("=== smw_generate_key Parameters ===");
	LOG_INFO("  version: %u", args->version);
	LOG_INFO("  subsystem_name: %s",
		 cli_smw_get_subsystem_name(args->subsystem_name));
	LOG_INFO("  key_descriptor:");
	LOG_INFO("    type_name: %s (%u)",
		 key_type_to_string(args->key_descriptor->type_name),
		 (unsigned int)args->key_descriptor->type_name);
	LOG_INFO("    security_size: %u bits",
		 args->key_descriptor->security_size);
	LOG_INFO("    id: 0x%08x (%u)", args->key_descriptor->id,
		 args->key_descriptor->id);
	LOG_INFO("    buffer: %p", (void *)args->key_descriptor->buffer);
	LOG_INFO("  attributes:");
	LOG_INFO("    permitted_algo: 0x%llx",
		 (unsigned long long)
			 args->key_descriptor->attributes.permitted_algo);
	LOG_INFO("    usage_flags: 0x%08x",
		 args->key_descriptor->attributes.usage_flags);
	LOG_INFO("    storage_id: %u",
		 args->key_descriptor->attributes.storage_id);
	LOG_INFO("    attributes: 0x%08x",
		 args->key_descriptor->attributes.attributes);
	LOG_INFO("====================================");
}
