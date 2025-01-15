// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2021, 2023-2025 NXP
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
#include "list.h"

#include "common.h"
#include "tag.h"

/*
 * Ordering must be the same for internal values and public values.
 * This way the offset between the internal values and the public values
 * can be used for conversion, and no conversion table is required.
 *
 * The offset between the internal values and the public values is
 * given by the first public value.
 */

#define SMW_CONFIG_SIGN_ALGO_ID_OFFSET                                         \
	(SMW_SIGNATURE_ALGO_NAME_DEFAULT - SMW_CONFIG_SIGN_ALGO_ID_DEFAULT)

#define SMW_CONFIG_SIGN_TYPE_ID_OFFSET                                         \
	(SMW_SIGNATURE_TYPE_NAME_DEFAULT - SMW_CONFIG_SIGN_TYPE_ID_DEFAULT)

static const char *const sign_algo_strings[] = {
	[SMW_CONFIG_SIGN_ALGO_ID_DEFAULT] = DEFAULT_STR,
	[SMW_CONFIG_SIGN_ALGO_ID_ECDSA] = ECDSA_STR,
	[SMW_CONFIG_SIGN_ALGO_ID_EDDSA] = EDDSA_STR,
	[SMW_CONFIG_SIGN_ALGO_ID_DSA] = DSA_STR,
	[SMW_CONFIG_SIGN_ALGO_ID_RSA] = RSA_STR,
	[SMW_CONFIG_SIGN_ALGO_ID_TLS_1_2] = TLS_1_2_STR,
};

static unsigned int sign_algo_attrs[] = {
	[SMW_CONFIG_SIGN_ALGO_ID_ECDSA] = SMW_ATTR_ALGO_ECDSA,
	[SMW_CONFIG_SIGN_ALGO_ID_EDDSA] = SMW_ATTR_ALGO_EDDSA,
	[SMW_CONFIG_SIGN_ALGO_ID_DSA] = SMW_ATTR_ALGO_DSA,
	[SMW_CONFIG_SIGN_ALGO_ID_RSA] = SMW_ATTR_ALGO_RSA,
	[SMW_CONFIG_SIGN_ALGO_ID_TLS_1_2] = SMW_ATTR_ALGO_TLS_1_2,
	[SMW_CONFIG_CIPHER_MODE_ID_NB] = 0,
};

static const char *const sign_type_strings[] = {
	[SMW_CONFIG_SIGN_TYPE_ID_DEFAULT] = DEFAULT_STR,
	[SMW_CONFIG_SIGN_TYPE_ID_PKCS1_1_5] = PKCS1_1_5_STR,
	[SMW_CONFIG_SIGN_TYPE_ID_PSS] = PSS_STR,
	[SMW_CONFIG_SIGN_TYPE_ID_CLIENT] = CLIENT_STR,
	[SMW_CONFIG_SIGN_TYPE_ID_SERVER] = SERVER_STR,
	[SMW_CONFIG_SIGN_TYPE_ID_CMAC] = CMAC_STR,
};

static int read_signature_algo_strings(char **start, char *end,
				       unsigned long *bitmap)
{
	int status =
		smw_config_read_strings(start, end, bitmap, sign_algo_strings,
					SMW_CONFIG_SIGN_ALGO_ID_NB);
	if (status == SMW_STATUS_UNKNOWN_NAME)
		status = SMW_STATUS_UNKNOWN_SIGN_ALGO_NAME;

	return status;
}

static int read_signature_type_strings(char **start, char *end,
				       unsigned long *bitmap)
{
	int status =
		smw_config_read_strings(start, end, bitmap, sign_type_strings,
					SMW_CONFIG_SIGN_TYPE_ID_NB);
	if (status == SMW_STATUS_UNKNOWN_NAME)
		status = SMW_STATUS_UNKNOWN_SIGN_TYPE_NAME;

	return status;
}

static int sign_verify_read_params(char **start, char *end, void **params)
{
	int status = SMW_STATUS_OK;
	char *cur = *start;

	char buffer[SMW_CONFIG_MAX_PARAMS_STRING_LENGTH + 1] = { 0 };
	size_t length = 0;

	struct sign_verify_params *p = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	p = SMW_UTILS_CALLOC(1, sizeof(*p));
	if (!p) {
		status = SMW_STATUS_ALLOC_FAILURE;
		goto end;
	}

	while ((cur < end) && (open_square_bracket != *cur)) {
		status = read_params_string(&cur, end, buffer);
		if (status != SMW_STATUS_OK)
			goto end;
		SMW_DBG_PRINTF(INFO, "Parameter: %s\n", buffer);
		length = SMW_UTILS_STRLEN(buffer);

		skip_insignificant_chars(&cur, end);

		if (!SMW_UTILS_STRNCMP(buffer, sign_algo_values, length)) {
			status = read_signature_algo_strings(&cur, end,
							     &p->algo_bitmap);
			if (status != SMW_STATUS_OK)
				goto end;
		} else if (!SMW_UTILS_STRNCMP(buffer, sign_type_values,
					      length)) {
			status = read_signature_type_strings(&cur, end,
							     &p->type_bitmap);
			if (status != SMW_STATUS_OK)
				goto end;
		} else if (!SMW_UTILS_STRNCMP(buffer, hash_algo_values,
					      length)) {
			status = read_hash_algo_strings(&cur, end,
							&p->hash_bitmap);
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
	else
		set_bit(&p->algo_bitmap, sizeof(p->algo_bitmap) << 3,
			SMW_CONFIG_SIGN_ALGO_ID_DEFAULT);

	if (!p->type_bitmap)
		p->type_bitmap = SMW_ALL_ONES;
	else
		set_bit(&p->type_bitmap, sizeof(p->type_bitmap) << 3,
			SMW_CONFIG_SIGN_TYPE_ID_DEFAULT);

	if (!p->hash_bitmap)
		p->hash_bitmap = SMW_ALL_ONES;

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
	sign_verify_caps->type_bitmap |= sign_verify_params->type_bitmap;
	sign_verify_caps->hash_bitmap |= sign_verify_params->hash_bitmap;
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

static int sign_verify_check_subsystem_caps(void *args, void *node)
{
	int status = SMW_STATUS_OK;

	struct smw_crypto_sign_verify_args *sign_verify_args = args;
	struct sign_verify_params *sign_verify_params =
		smw_utils_list_get_data(node);

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!check_id(sign_verify_args->attributes.algo_id,
		      sign_verify_params->algo_bitmap) ||
	    !check_id(sign_verify_args->attributes.type_id,
		      sign_verify_params->type_bitmap) ||
	    !check_id(sign_verify_args->attributes.hash_id,
		      sign_verify_params->hash_bitmap))
		status = SMW_STATUS_OPERATION_NOT_CONFIGURED;

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int sign_check_subsystem_caps(void *args, void *node)
{
	return sign_verify_check_subsystem_caps(args, node);
}

static int verify_check_subsystem_caps(void *args, void *node)
{
	return sign_verify_check_subsystem_caps(args, node);
}

static int check_sign_verify_common(smw_subsystem_t subsystem,
				    struct smw_signature_info *info,
				    enum operation_id op_id)
{
	int status = SMW_STATUS_INVALID_PARAM;
	enum subsystem_id id = SUBSYSTEM_ID_INVALID;
	enum smw_config_sign_algo_id algo_id = SMW_CONFIG_SIGN_ALGO_ID_INVALID;
	enum smw_config_sign_type_id type_id = SMW_CONFIG_SIGN_TYPE_ID_INVALID;
	enum smw_config_hash_algo_id hash_id = SMW_CONFIG_HASH_ALGO_ID_INVALID;
	struct sign_verify_params params = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!info || info->algo_name == SMW_SIGNATURE_ALGO_NAME_NONE)
		return status;

	status = smw_config_get_subsystem_id(subsystem, &id);
	if (status != SMW_STATUS_OK)
		return status;

	status = get_operation_params_lock(op_id, id, &params);
	if (status != SMW_STATUS_OK)
		return status;

	/* Check signature algo */
	status = smw_config_get_signature_algo_id(info->algo_name, &algo_id);
	if (status != SMW_STATUS_OK)
		return status;

	if (!check_id(algo_id, params.algo_bitmap))
		return SMW_STATUS_OPERATION_NOT_CONFIGURED;

	/* Check signature type if set */
	if (info->type_name != SMW_SIGNATURE_TYPE_NAME_NONE) {
		status = smw_config_get_signature_type_id(info->type_name,
							  &type_id);
		if (status != SMW_STATUS_OK)
			return status;

		if (!check_id(type_id, params.type_bitmap))
			return SMW_STATUS_OPERATION_NOT_CONFIGURED;
	}

	/* Check hash algorithm if set */
	if (info->hash_algo_name != SMW_HASH_ALGO_NAME_NONE) {
		status = smw_utils_get_hash_algo_id(info->hash_algo_name,
						    &hash_id);
		if (status != SMW_STATUS_OK)
			return status;

		if (!check_id(hash_id, params.hash_bitmap))
			return SMW_STATUS_OPERATION_NOT_CONFIGURED;
	}

	return SMW_STATUS_OK;
}

static int check_common_key_usable(enum operation_id operation_id,
				   unsigned int *ref,
				   enum smw_config_key_type_id key_type_id,
				   smw_attr_algo_t permitted_algo)
{
	int status = SMW_STATUS_OK;
	struct sign_verify_params params = { 0 };
	smw_attr_algo_t algo = SMW_ATTR_ALGO_NONE;
	smw_attr_algo_t curve = SMW_ATTR_CURVE_NONE;
	size_t idx = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	status = get_operation_params(operation_id, ref, &params);
	if (status != SMW_STATUS_OK)
		goto end;

	curve = SMW_ATTR_GET_CURVE(permitted_algo);
	if (curve == SMW_ATTR_CURVE_NONE || curve == SMW_ATTR_CURVE_ANY) {
		status = SMW_STATUS_OK;
		goto end;
	}

	algo = SMW_ATTR_GET_ALGO(permitted_algo);
	status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	if (!check_id(key_type_id, params.type_bitmap))
		goto end;

	for (; idx < ARRAY_SIZE(sign_algo_attrs); idx++) {
		if ((algo == SMW_ATTR_ALGO_NONE ||
		     algo == sign_algo_attrs[idx]) &&
		    check_id(idx, params.algo_bitmap)) {
			status = SMW_STATUS_OK;
			break;
		}
	}

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

DEFINE_CONFIG_OPERATION_FUNC(sign);
DEFINE_CONFIG_OPERATION_FUNC(verify);

int sign_key_usable(unsigned int *ref, enum smw_config_key_type_id key_type_id,
		    struct smw_key_attributes *attributes)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
	bool check_sign = false;
	bool check_verify = false;
	smw_attr_usage_t usages = attributes->usage_flags;
	smw_attr_usage_t mask_usages =
		SMW_ATTR_USAGE_CACHE | SMW_ATTR_USAGE_COPY |
		SMW_ATTR_USAGE_EXPORT | SMW_ATTR_USAGE_DERIVE;

	/*
	 * If key usage is not set check both sign and verify operations,
	 * else check operation(s) corresponding to the key usage set.
	 */
	CLEAR_BITS(usages, mask_usages);

	if (usages) {
		if (SMW_ATTR_USAGE_IS_SIGN_MESSAGE(usages) ||
		    SMW_ATTR_USAGE_IS_SIGN_HASH(usages))
			check_sign = true;

		if (SMW_ATTR_USAGE_IS_VERIFY_MESSAGE(usages) ||
		    SMW_ATTR_USAGE_IS_VERIFY_HASH(usages))
			check_verify = true;
	} else if (!usages) {
		check_sign = true;
		check_verify = true;
	}

	if (check_sign) {
		status = check_common_key_usable(OPERATION_ID_SIGN, ref,
						 key_type_id,
						 attributes->permitted_algo);

		if (usages && status == SMW_STATUS_OPERATION_NOT_SUPPORTED)
			goto end;
	}

	if (check_verify)
		status = check_common_key_usable(OPERATION_ID_VERIFY, ref,
						 key_type_id,
						 attributes->permitted_algo);

end:
	return status;
}

int smw_config_get_signature_algo_id(smw_signature_algo_t name,
				     enum smw_config_sign_algo_id *id)
{
	int status = SMW_STATUS_UNKNOWN_SIGN_ALGO_NAME;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (name == SMW_SIGNATURE_ALGO_NAME_NONE) {
		status = SMW_STATUS_INVALID_PARAM;
	} else if (name < SMW_SIGNATURE_ALGO_NAME_NB) {
		if (!SUB_OVERFLOW(name, SMW_CONFIG_SIGN_ALGO_ID_OFFSET,
				  (int *)id))
			status = SMW_STATUS_OK;
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int smw_config_get_signature_type_id(smw_signature_type_t name,
				     enum smw_config_sign_type_id *id)
{
	int status = SMW_STATUS_UNKNOWN_SIGN_TYPE_NAME;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (name == SMW_SIGNATURE_TYPE_NAME_NONE) {
		status = SMW_STATUS_INVALID_PARAM;
	} else if (name < SMW_SIGNATURE_TYPE_NAME_NB) {
		if (!SUB_OVERFLOW(name, SMW_CONFIG_SIGN_TYPE_ID_OFFSET,
				  (int *)id))
			status = SMW_STATUS_OK;
	}

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
