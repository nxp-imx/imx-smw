// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2021, 2023 NXP
 */

#include "smw_status.h"
#include "smw_config.h"
#include "smw_crypto.h"

#include "compiler.h"
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
	return smw_config_read_names(start, end, bitmap, sign_type_names,
				     SMW_CONFIG_SIGN_TYPE_ID_NB);
}

static int sign_verify_read_params(char **start, char *end, void **params)
{
	int status = SMW_STATUS_OK;
	char *cur = *start;

	char buffer[SMW_CONFIG_MAX_PARAMS_NAME_LENGTH + 1] = { 0 };
	size_t length = 0;

	struct sign_verify_params *p = NULL;
	unsigned long key_size_range_bitmap = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	p = SMW_UTILS_CALLOC(1, sizeof(*p));
	if (!p) {
		status = SMW_STATUS_ALLOC_FAILURE;
		goto end;
	}

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
			status = smw_utils_hash_algo_names(&cur, end,
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
	return sign_verify_read_params(start, end, params);
}

static int verify_read_params(char **start, char *end, void **params)
{
	return sign_verify_read_params(start, end, params);
}

static void sign_verify_merge_params(void *caps, void *params)
{
	struct sign_verify_params *sign_verify_caps = caps;
	struct sign_verify_params *sign_verify_params = params;

	SMW_DBG_TRACE_FUNCTION_CALL;

	sign_verify_caps->algo_bitmap |= sign_verify_params->algo_bitmap;
	sign_verify_caps->sign_type_bitmap |=
		sign_verify_params->sign_type_bitmap;
	merge_key_params(&sign_verify_caps->key, &sign_verify_params->key);
}

static void sign_merge_params(void *caps, void *params)
{
	sign_verify_merge_params(caps, params);
}

static void verify_merge_params(void *caps, void *params)
{
	sign_verify_merge_params(caps, params);
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

static int check_sign_verify_common(smw_subsystem_t subsystem,
				    struct smw_signature_info *info,
				    enum operation_id op_id)
{
	int status = SMW_STATUS_INVALID_PARAM;
	enum subsystem_id id = SUBSYSTEM_ID_INVALID;
	enum smw_config_key_type_id key_type_id =
		SMW_CONFIG_KEY_TYPE_ID_INVALID;
	enum smw_config_hash_algo_id algo_id = SMW_CONFIG_HASH_ALGO_ID_INVALID;
	enum smw_config_sign_type_id sign_type_id =
		SMW_CONFIG_SIGN_TYPE_ID_INVALID;
	struct sign_verify_params params = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!info || !info->key_type_name)
		return status;

	status = smw_config_get_subsystem_id(subsystem, &id);
	if (status != SMW_STATUS_OK)
		return status;

	status = smw_config_get_key_type_id(info->key_type_name, &key_type_id);
	if (status != SMW_STATUS_OK)
		return status;

	status = get_operation_params(op_id, id, &params);
	if (status != SMW_STATUS_OK)
		return status;

	/* Check key type */
	if (!check_id(key_type_id, params.key.type_bitmap))
		return SMW_STATUS_OPERATION_NOT_CONFIGURED;

	/* Check hash algorithm if set */
	if (info->hash_algo) {
		status = smw_utils_get_hash_algo_id(info->hash_algo, &algo_id);
		if (status != SMW_STATUS_OK)
			return status;

		if (!check_id(algo_id, params.algo_bitmap))
			return SMW_STATUS_OPERATION_NOT_CONFIGURED;
	}

	/* Check signature type if set */
	if (info->signature_type) {
		status = smw_config_get_signature_type_id(info->signature_type,
							  &sign_type_id);
		if (status != SMW_STATUS_OK)
			return status;

		if (!check_id(sign_type_id, params.sign_type_bitmap))
			return SMW_STATUS_OPERATION_NOT_CONFIGURED;
	}

	return SMW_STATUS_OK;
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

__export enum smw_status_code
smw_config_check_sign(smw_subsystem_t subsystem,
		      struct smw_signature_info *info)
{
	return check_sign_verify_common(subsystem, info, OPERATION_ID_SIGN);
}

__export enum smw_status_code
smw_config_check_verify(smw_subsystem_t subsystem,
			struct smw_signature_info *info)
{
	return check_sign_verify_common(subsystem, info, OPERATION_ID_VERIFY);
}
