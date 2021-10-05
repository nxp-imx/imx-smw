// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2021 NXP
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
#include "sign_verify.h"
#include "name.h"

#include "common.h"
#include "tag.h"

static const char *const sign_type_names[] = {
	[SMW_CONFIG_SIGN_TYPE_ID_DEFAULT] = "DEFAULT",
	[SMW_CONFIG_SIGN_TYPE_ID_RSASSA_PKCS1_V1_5] = RSASSA_PKCS1_V1_5_STR,
	[SMW_CONFIG_SIGN_TYPE_ID_RSASSA_PSS] = RSASSA_PSS_STR
};

static const char *const tls_finish_label_names[] = {
	[SMW_CONFIG_TLS_FINISH_ID_CLIENT] = TLS_FINISH_CLIENT_STR,
	[SMW_CONFIG_TLS_FINISH_ID_SERVER] = TLS_FINISH_SERVER_STR
};

static int read_signature_type_names(char **start, char *end,
				     unsigned long *bitmap)
{
	return read_names(start, end, bitmap, sign_type_names,
			  SMW_CONFIG_SIGN_TYPE_ID_NB);
}

static int sign_verify_read_params(char **start, char *end,
				   enum operation_id operation_id,
				   void **params)
{
	int status = SMW_STATUS_OK;
	char *cur = *start;

	char buffer[SMW_CONFIG_MAX_PARAMS_NAME_LENGTH + 1];
	unsigned int length;

	struct sign_verify_params *p;
	unsigned long key_size_range_bitmap = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	p = SMW_UTILS_CALLOC(1, sizeof(*p));
	if (!p) {
		status = SMW_STATUS_ALLOC_FAILURE;
		goto end;
	}

	p->operation_id = operation_id;
	init_key_params(&p->key);
	p->sign_type_bitmap = SMW_ALL_ONES;

	while ((cur < end) && (open_square_bracket != *cur)) {
		status = read_params_name(&cur, end, buffer);
		if (status != SMW_STATUS_OK)
			goto end;
		SMW_DBG_PRINTF(INFO, "Parameter: %s\n", buffer);
		length = SMW_UTILS_STRLEN(buffer);

		skip_insignificant_chars(&cur, end);

		if (!SMW_UTILS_STRNCMP(buffer, hash_algo_values, length)) {
			status = read_hash_algo_names(&cur, end,
						      &p->algo_bitmap);
			if (status != SMW_STATUS_OK)
				goto end;
		} else if (!SMW_UTILS_STRNCMP(buffer, sign_type_values,
					      length)) {
			status =
				read_signature_type_names(&cur, end,
							  &p->sign_type_bitmap);
			if (status != SMW_STATUS_OK)
				goto end;
		} else if (read_key(buffer, length, &cur, end,
				    &key_size_range_bitmap, &p->key, &status)) {
			if (status != SMW_STATUS_OK)
				goto end;
		} else {
			status = skip_param(&cur, end);
			if (status != SMW_STATUS_OK)
				goto end;
		}

		skip_insignificant_chars(&cur, end);
	}

	if (!p->algo_bitmap)
		p->algo_bitmap = SMW_ALL_ONES;

	if (!p->key.type_bitmap)
		p->key.type_bitmap = SMW_ALL_ONES;

	*params = p;

	*start = cur;

end:
	if (p && status != SMW_STATUS_OK)
		SMW_UTILS_FREE(p);

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

__weak void sign_verify_print_params(void *params)
{
	(void)params;
}

static void sign_print_params(void *params)
{
	sign_verify_print_params(params);
}

static void verify_print_params(void *params)
{
	sign_verify_print_params(params);
}

static int check_subsystem_caps(void *args, void *params)
{
	int status = SMW_STATUS_OK;

	struct smw_crypto_sign_verify_args *sign_verify_args = args;
	struct sign_verify_params *sign_verify_params = params;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!check_id(sign_verify_args->algo_id,
		      sign_verify_params->algo_bitmap) ||
	    !check_key(&sign_verify_args->key_descriptor.identifier,
		       &sign_verify_params->key) ||
	    !check_id(sign_verify_args->attributes.signature_type,
		      sign_verify_params->sign_type_bitmap))
		status = SMW_STATUS_OPERATION_NOT_CONFIGURED;

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int sign_check_subsystem_caps(void *args, void *params)
{
	return check_subsystem_caps(args, params);
}

static int verify_check_subsystem_caps(void *args, void *params)
{
	return check_subsystem_caps(args, params);
}

DEFINE_CONFIG_OPERATION_FUNC(sign);
DEFINE_CONFIG_OPERATION_FUNC(verify);

int smw_config_get_signature_type_id(const char *name,
				     enum smw_config_sign_type_id *id)
{
	int status = SMW_STATUS_OK;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!name)
		*id = SMW_CONFIG_SIGN_TYPE_ID_DEFAULT;
	else
		status = smw_utils_get_string_index(name, sign_type_names,
						    SMW_CONFIG_SIGN_TYPE_ID_NB,
						    id);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int smw_config_get_tls_label_id(const char *name,
				enum smw_config_tls_finish_label_id *id)
{
	int status = SMW_STATUS_OK;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!name)
		*id = SMW_CONFIG_TLS_FINISH_ID_INVALID;
	else
		status =
			smw_utils_get_string_index(name, tls_finish_label_names,
						   SMW_CONFIG_TLS_FINISH_ID_NB,
						   id);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}
