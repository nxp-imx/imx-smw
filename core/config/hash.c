// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2021, 2023-2024 NXP
 */

#include "smw_status.h"
#include "smw_crypto.h"

#include "compiler.h"
#include "global.h"
#include "debug.h"
#include "utils.h"
#include "operations.h"
#include "subsystems.h"
#include "config.h"
#include "hash.h"
#include "list.h"

#include "common.h"
#include "tag.h"

static const char *const hash_algo_strings[] = {
	[SMW_CONFIG_HASH_ALGO_ID_MD5] = "MD5",
	[SMW_CONFIG_HASH_ALGO_ID_SHA1] = "SHA1",
	[SMW_CONFIG_HASH_ALGO_ID_SHA224] = "SHA224",
	[SMW_CONFIG_HASH_ALGO_ID_SHA256] = "SHA256",
	[SMW_CONFIG_HASH_ALGO_ID_SHA384] = "SHA384",
	[SMW_CONFIG_HASH_ALGO_ID_SHA512] = "SHA512",
	[SMW_CONFIG_HASH_ALGO_ID_SHA3_224] = "SHA3_224",
	[SMW_CONFIG_HASH_ALGO_ID_SHA3_256] = "SHA3_256",
	[SMW_CONFIG_HASH_ALGO_ID_SHA3_384] = "SHA3_384",
	[SMW_CONFIG_HASH_ALGO_ID_SHA3_512] = "SHA3_512",
	[SMW_CONFIG_HASH_ALGO_ID_SM3] = "SM3"
};

int read_hash_algo_strings(char **start, char *end, unsigned long *bitmap)
{
	int status =
		smw_config_read_strings(start, end, bitmap, hash_algo_strings,
					SMW_CONFIG_HASH_ALGO_ID_NB);
	if (status == SMW_STATUS_UNKNOWN_NAME)
		status = SMW_STATUS_UNKNOWN_ALGO_NAME;

	return status;
}

static int hash_read_params(char **start, char *end, void **params)
{
	int status = SMW_STATUS_OK;
	char *cur = *start;

	char buffer[SMW_CONFIG_MAX_PARAMS_STRING_LENGTH + 1] = { 0 };
	size_t length = 0;

	unsigned long algo_bitmap = SMW_ALL_ONES;

	struct hash_params *p = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	while ((cur < end) && (open_square_bracket != *cur)) {
		status = read_params_string(&cur, end, buffer);
		if (status != SMW_STATUS_OK)
			goto end;
		SMW_DBG_PRINTF(INFO, "Parameter: %s\n", buffer);
		length = SMW_UTILS_STRLEN(buffer);

		skip_insignificant_chars(&cur, end);

		if (!SMW_UTILS_STRNCMP(buffer, hash_algo_values, length)) {
			status =
				read_hash_algo_strings(&cur, end, &algo_bitmap);
			if (status != SMW_STATUS_OK)
				goto end;
		} else {
			status = skip_param(&cur, end);
			if (status != SMW_STATUS_OK)
				goto end;
		}

		skip_insignificant_chars(&cur, end);
	}

	p = SMW_UTILS_MALLOC(sizeof(*p));
	if (!p) {
		status = SMW_STATUS_ALLOC_FAILURE;
		goto end;
	}

	p->algo_bitmap = algo_bitmap;

	*params = p;

	*start = cur;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static void hash_merge_params(void *caps, void *params)
{
	struct hash_params *hash_caps = caps;
	struct hash_params *hash_params = params;

	SMW_DBG_TRACE_FUNCTION_CALL;

	hash_caps->algo_bitmap |= hash_params->algo_bitmap;
}

__weak void hash_print_params(void *params)
{
	(void)params;
}

static int hash_check_subsystem_caps(void *args, void *node)
{
	int status = SMW_STATUS_OK;

	struct smw_crypto_hash_args *hash_args = args;
	struct hash_params *hash_params = smw_utils_list_get_data(node);

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!check_id(hash_args->algo_id, hash_params->algo_bitmap))
		status = SMW_STATUS_OPERATION_NOT_CONFIGURED;

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int hash_check_key_usable(unsigned int *ref,
				 enum smw_config_key_type_id key_type_id,
				 smw_attr_algo_t permitted_algo)
{
	(void)ref;
	(void)key_type_id;
	(void)permitted_algo;

	return SMW_STATUS_OK;
}

DEFINE_CONFIG_OPERATION_FUNC(hash);

__export enum smw_status_code smw_config_check_digest(smw_subsystem_t subsystem,
						      smw_hash_algo_t algo)
{
	int status = SMW_STATUS_INVALID_PARAM;
	enum subsystem_id id = SUBSYSTEM_ID_INVALID;
	enum smw_config_hash_algo_id algo_id = SMW_CONFIG_HASH_ALGO_ID_INVALID;
	struct hash_params params = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (algo == SMW_HASH_ALGO_NAME_NONE)
		return status;

	status = smw_config_get_subsystem_id(subsystem, &id);
	if (status != SMW_STATUS_OK)
		return status;

	status = smw_utils_get_hash_algo_id(algo, &algo_id);
	if (status != SMW_STATUS_OK)
		return status;

	status = get_operation_params_lock(OPERATION_ID_HASH, id, &params);
	if (status != SMW_STATUS_OK)
		return status;

	if (!check_id(algo_id, params.algo_bitmap))
		return SMW_STATUS_OPERATION_NOT_CONFIGURED;

	return SMW_STATUS_OK;
}
