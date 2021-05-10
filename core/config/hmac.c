// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021 NXP
 */

#include "smw_status.h"
#include "smw_crypto.h"

#include "compiler.h"
#include "smw_osal.h"
#include "global.h"
#include "debug.h"
#include "utils.h"
#include "operations.h"
#include "subsystems.h"
#include "config.h"
#include "keymgr.h"
#include "hmac.h"
#include "name.h"

#include "common.h"
#include "tag.h"

static const char *const hmac_algo_names[] = {
	[SMW_CONFIG_HMAC_ALGO_ID_MD5] = "MD5",
	[SMW_CONFIG_HMAC_ALGO_ID_SHA1] = "SHA1",
	[SMW_CONFIG_HMAC_ALGO_ID_SHA224] = "SHA224",
	[SMW_CONFIG_HMAC_ALGO_ID_SHA256] = "SHA256",
	[SMW_CONFIG_HMAC_ALGO_ID_SHA384] = "SHA384",
	[SMW_CONFIG_HMAC_ALGO_ID_SHA512] = "SHA512",
	[SMW_CONFIG_HMAC_ALGO_ID_SM3] = "SM3"
};

int read_hmac_algo_names(char **start, char *end, unsigned long *bitmap)
{
	return read_names(start, end, bitmap, hmac_algo_names,
			  SMW_CONFIG_HMAC_ALGO_ID_NB);
}

static int hmac_read_params(char **start, char *end, void **params)
{
	int status = SMW_STATUS_OK;
	char *cur = *start;

	char buffer[SMW_CONFIG_MAX_PARAMS_NAME_LENGTH + 1];
	int length;

	unsigned long algo_bitmap = SMW_ALL_ONES;
	unsigned long key_type_bitmap = SMW_ALL_ONES;

	unsigned int key_size_min = 0;
	unsigned int key_size_max = UINT_MAX;

	struct hmac_params *p;

	SMW_DBG_TRACE_FUNCTION_CALL;

	while ((cur < end) && (open_square_bracket != *cur)) {
		status = read_params_name(&cur, end, buffer);
		if (status != SMW_STATUS_OK)
			goto end;
		SMW_DBG_PRINTF(INFO, "Parameter: %s\n", buffer);
		length = SMW_UTILS_STRLEN(buffer);

		skip_insignificant_chars(&cur, end);

		if (!SMW_UTILS_STRNCMP(buffer, hmac_algo_values, length)) {
			status = read_hmac_algo_names(&cur, end, &algo_bitmap);
			if (status != SMW_STATUS_OK)
				goto end;
		} else if (!SMW_UTILS_STRNCMP(buffer, key_type_values,
					      length)) {
			status = read_key_type_names(&cur, end,
						     &key_type_bitmap);
			if (status != SMW_STATUS_OK)
				goto end;
		} else if (!SMW_UTILS_STRNCMP(buffer, key_size_range, length)) {
			status = read_range(&cur, end, &key_size_min,
					    &key_size_max);
			if (status != SMW_STATUS_OK)
				goto end;
		} else {
			status = skip_param(&cur, end);
			if (status != SMW_STATUS_OK)
				goto end;
		}

		skip_insignificant_chars(&cur, end);
	}

	p = SMW_UTILS_MALLOC(sizeof(struct hmac_params));
	if (!p) {
		status = SMW_STATUS_ALLOC_FAILURE;
		goto end;
	}

	p->operation_id = OPERATION_ID_HMAC;
	p->algo_bitmap = algo_bitmap;
	p->key_type_bitmap = key_type_bitmap;
	p->key_size_min = key_size_min;
	p->key_size_max = key_size_max;

	*params = p;

	*start = cur;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

__weak void hmac_print_params(void *params)
{
	(void)params;
}

static int hmac_check_subsystem_caps(void *args, void *params)
{
	int status = SMW_STATUS_OK;

	struct smw_crypto_hmac_args *hmac_args = args;
	struct hmac_params *hmac_params = params;

	enum smw_config_key_type_id key_type_id =
		hmac_args->key_descriptor.identifier.type_id;
	unsigned int security_size =
		hmac_args->key_descriptor.identifier.security_size;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!check_id(hmac_args->algo_id, hmac_params->algo_bitmap) ||
	    !check_id(key_type_id, hmac_params->key_type_bitmap) ||
	    !check_security_size(security_size, hmac_params->key_size_min,
				 hmac_params->key_size_max))
		status = SMW_STATUS_OPERATION_NOT_CONFIGURED;

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

DEFINE_CONFIG_OPERATION_FUNC(hmac);

int smw_config_get_hmac_algo_id(const char *name,
				enum smw_config_hmac_algo_id *id)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	return smw_utils_get_string_index(name, hmac_algo_names,
					  SMW_CONFIG_HASH_ALGO_ID_NB, id);
}
