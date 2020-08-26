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
#include "keymgr.h"
#include "sign_verify.h"

#include "common.h"

static int sign_verify_read_params(char **start, char *end,
				   enum operation_id operation_id,
				   void **params)
{
	int status = SMW_STATUS_OK;
	char *cur = *start;

	char buffer[SMW_CONFIG_MAX_PARAMS_NAME_LENGTH + 1];
	int length;

	unsigned long algo_bitmap = SMW_ALL_ONES;
	unsigned long key_type_bitmap = SMW_ALL_ONES;

	unsigned int key_size_min = 0;
	unsigned int key_size_max = UINT_MAX;

	struct sign_verify_params *p;

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
		} else if (!SMW_UTILS_STRNCMP(buffer, key_type_values,
					      length)) {
			status = read_key_type_names(&cur, end,
						     &key_type_bitmap);
			if (status != SMW_STATUS_OK)
				goto end;
		} else if (!SMW_UTILS_STRNCMP(buffer, key_size_range, length)) {
			status = read_key_size_range(&cur, end, &key_size_min,
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

	p = SMW_UTILS_MALLOC(sizeof(struct sign_verify_params));
	if (!p) {
		status = SMW_STATUS_ALLOC_FAILURE;
		goto end;
	}

	p->operation_id = operation_id;
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

static int sign_read_params(char **start, char *end, void **params)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	return sign_verify_read_params(start, end, OPERATION_ID_SIGN, params);
}

static int verify_read_params(char **start, char *end, void **params)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	return sign_verify_read_params(start, end, OPERATION_ID_VERIFY, params);
}

__attribute__((weak)) void sign_verify_print_params(void *params)
{
}

static void sign_print_params(void *params)
{
	sign_verify_print_params(params);
}

static void verify_print_params(void *params)
{
	sign_verify_print_params(params);
}

static int sign_check_subsystem_caps(void *args, void *params)
{
	int status = SMW_STATUS_OK;

	struct smw_crypto_sign_args *sign_args = args;
	struct sign_verify_params *sign_params = params;

	enum smw_config_key_type_id key_type_id =
		sign_args->key_descriptor.identifier.type_id;
	unsigned int security_size =
		sign_args->key_descriptor.identifier.security_size;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!check_id(sign_args->algo_id, sign_params->algo_bitmap) ||
	    !check_id(key_type_id, sign_params->key_type_bitmap) ||
	    !check_security_size(security_size, sign_params->key_size_min,
				 sign_params->key_size_max))
		status = SMW_STATUS_OPERATION_NOT_CONFIGURED;

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int verify_check_subsystem_caps(void *args, void *params)
{
	int status = SMW_STATUS_OK;

	struct smw_crypto_verify_args *verify_args = args;
	struct sign_verify_params *verify_params = params;

	enum smw_config_key_type_id key_type_id =
		verify_args->key_descriptor.identifier.type_id;
	unsigned int security_size =
		verify_args->key_descriptor.identifier.security_size;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!check_id(verify_args->algo_id, verify_params->algo_bitmap) ||
	    !check_id(key_type_id, verify_params->key_type_bitmap) ||
	    !check_security_size(security_size, verify_params->key_size_min,
				 verify_params->key_size_max))
		status = SMW_STATUS_OPERATION_NOT_CONFIGURED;

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

DEFINE_CONFIG_OPERATION_FUNC(sign);
DEFINE_CONFIG_OPERATION_FUNC(verify);
