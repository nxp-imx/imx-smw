// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020 NXP
 */

#include "smw_status.h"
#include "smw_crypto.h"

#include "smw_osal.h"
#include "global.h"
#include "debug.h"
#include "utils.h"
#include "operations.h"
#include "subsystems.h"
#include "config.h"
#include "crypto.h"

#include "common.h"

const char *hash_algo_values = "HASH_ALGO_VALUES";

static const char *const hash_algo_names[] = {
	[SMW_CONFIG_HASH_ALGO_ID_MD5] = "MD5",
	[SMW_CONFIG_HASH_ALGO_ID_SHA1] = "SHA1",
	[SMW_CONFIG_HASH_ALGO_ID_SHA224] = "SHA224",
	[SMW_CONFIG_HASH_ALGO_ID_SHA256] = "SHA256",
	[SMW_CONFIG_HASH_ALGO_ID_SHA384] = "SHA384",
	[SMW_CONFIG_HASH_ALGO_ID_SHA512] = "SHA512",
	[SMW_CONFIG_HASH_ALGO_ID_SM3] = "SM3"
};

int read_hash_algo_names(char **start, char *end, unsigned long *bitmap)
{
	return read_names(start, end, bitmap, hash_algo_names,
			  SMW_CONFIG_HASH_ALGO_ID_NB);
}

static int hash_read_params(char **start, char *end, void **params)
{
	int status = SMW_STATUS_OK;
	char *cur = *start;

	char buffer[SMW_CONFIG_MAX_PARAMS_NAME_LENGTH + 1];
	int length;

	unsigned long algo_bitmap = SMW_ALL_ONES;

	struct hash_params *p;

	SMW_DBG_TRACE_FUNCTION_CALL;

	while ((cur < end) && (open_square_bracket != *cur)) {
		status = read_params_name(&cur, end, buffer);
		if (status != SMW_STATUS_OK)
			goto end;
		SMW_DBG_PRINTF(INFO, "Parameter: %s\n", buffer);
		length = SMW_UTILS_STRLEN(buffer);

		skip_insignificant_chars(&cur, end);

		if (!SMW_UTILS_STRNCMP(buffer, hash_algo_values, length)) {
			status = read_hash_algo_names(&cur, end, &algo_bitmap);
			if (status != SMW_STATUS_OK)
				goto end;
		} else {
			status = skip_param(&cur, end);
			if (status != SMW_STATUS_OK)
				goto end;
		}

		skip_insignificant_chars(&cur, end);
	}

	p = SMW_UTILS_MALLOC(sizeof(struct hash_params));
	if (!p) {
		status = SMW_STATUS_ALLOC_FAILURE;
		goto end;
	}

	p->operation_id = OPERATION_ID_HASH;
	p->algo_bitmap = algo_bitmap;

	*params = p;

	*start = cur;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

__attribute__((weak)) void hash_print_params(void *params)
{
}

static int hash_check_subsystem_caps(void *args, void *params)
{
	int status = SMW_STATUS_OK;

	struct smw_crypto_hash_args *hash_args =
		(struct smw_crypto_hash_args *)args;
	struct hash_params *hash_params = (struct hash_params *)params;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!check_id(hash_args->algo_id, hash_params->algo_bitmap))
		status = SMW_STATUS_OPERATION_NOT_CONFIGURED;

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

DEFINE_CONFIG_OPERATION_FUNC(hash);

int smw_config_get_hash_algo_id(const char *name,
				enum smw_config_hash_algo_id *id)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	return get_id(name, hash_algo_names, SMW_CONFIG_HASH_ALGO_ID_NB, id);
}
