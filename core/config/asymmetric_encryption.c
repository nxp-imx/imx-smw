// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include "smw_status.h"
#include "smw_config.h"
#include "smw_crypto.h"

#include "compiler.h"
#include "global.h"
#include "debug.h"
#include "utils.h"
#include "subsystems.h"
#include "config.h"
#include "keymgr.h"
#include "asymmetric_encryption.h"
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

#define SMW_CONFIG_ASYMM_ENC_ALGO_ID_OFFSET                                    \
	(SMW_ASYMMETRIC_ENCRYPTION_ALGO_NAME_RSA -                             \
	 SMW_CONFIG_ASYMM_ENC_ALGO_ID_RSA)

#define SMW_CONFIG_ASYMM_ENC_MODE_ID_OFFSET                                    \
	(SMW_ASYMMETRIC_ENCRYPTION_MODE_NAME_PKCS1_1_5 -                       \
	 SMW_CONFIG_ASYMM_ENC_MODE_ID_PKCS1_1_5)

static const char *const asymm_enc_algo_strings[] = {
	[SMW_CONFIG_ASYMM_ENC_ALGO_ID_RSA] = "RSA"
};

static const char *const asymm_enc_mode_strings[] = {
	[SMW_CONFIG_ASYMM_ENC_MODE_ID_PKCS1_1_5] = "PKCS1_1_5",
	[SMW_CONFIG_ASYMM_ENC_MODE_ID_OAEP] = "OAEP",
	[SMW_CONFIG_ASYMM_ENC_MODE_ID_NO_PAD] = "NO_PAD",
};

static int read_asymm_enc_algo_strings(char **start, char *end,
				       unsigned long *bitmap)
{
	int status = smw_config_read_strings(start, end, bitmap,
					     asymm_enc_algo_strings,
					     SMW_CONFIG_ASYMM_ENC_ALGO_ID_NB);
	if (status == SMW_STATUS_UNKNOWN_NAME)
		status = SMW_STATUS_UNKNOWN_ALGO_NAME;

	return status;
}

static int read_asymm_enc_mode_strings(char **start, char *end,
				       unsigned long *bitmap)
{
	int status = smw_config_read_strings(start, end, bitmap,
					     asymm_enc_mode_strings,
					     SMW_CONFIG_ASYMM_ENC_MODE_ID_NB);
	if (status == SMW_STATUS_UNKNOWN_NAME)
		status = SMW_STATUS_UNKNOWN_MODE_NAME;

	return status;
}

static int asymm_enc_dec_read_params(char **start, char *end, void **params)
{
	int status = SMW_STATUS_OK;
	char *cur = *start;

	char buffer[SMW_CONFIG_MAX_PARAMS_STRING_LENGTH + 1] = { 0 };
	size_t length = 0;

	struct asymmetric_encryption_params *p = NULL;

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

		if (!SMW_UTILS_STRNCMP(buffer, enc_algo_values, length)) {
			status = read_asymm_enc_algo_strings(&cur, end,
							     &p->algo_bitmap);
			if (status != SMW_STATUS_OK)
				goto end;
		} else if (!SMW_UTILS_STRNCMP(buffer, mode_values, length)) {
			status = read_asymm_enc_mode_strings(&cur, end,
							     &p->mode_bitmap);
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

	if (!p->mode_bitmap)
		p->mode_bitmap = SMW_ALL_ONES;

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

static int asymm_encrypt_read_params(char **start, char *end, void **params)
{
	return asymm_enc_dec_read_params(start, end, params);
}

static int asymm_decrypt_read_params(char **start, char *end, void **params)
{
	return asymm_enc_dec_read_params(start, end, params);
}

static void asymm_enc_dec_merge_params(void *caps, void *params)
{
	struct asymmetric_encryption_params *asymm_enc_caps = caps;
	struct asymmetric_encryption_params *asymm_enc_params = params;

	SMW_DBG_TRACE_FUNCTION_CALL;

	asymm_enc_caps->algo_bitmap |= asymm_enc_params->algo_bitmap;
	asymm_enc_caps->mode_bitmap |= asymm_enc_params->mode_bitmap;
	asymm_enc_caps->hash_bitmap |= asymm_enc_params->hash_bitmap;
}

static void asymm_encrypt_merge_params(void *caps, void *params)
{
	asymm_enc_dec_merge_params(caps, params);
}

static void asymm_decrypt_merge_params(void *caps, void *params)
{
	asymm_enc_dec_merge_params(caps, params);
}

static void asymm_enc_dec_print_params(void *params)
{
	(void)params;
}

static void asymm_encrypt_print_params(void *params)
{
	asymm_enc_dec_print_params(params);
}

static void asymm_decrypt_print_params(void *params)
{
	asymm_enc_dec_print_params(params);
}

static int common_check_subsystem_caps(void *args, void *node)
{
	int status = SMW_STATUS_OK;

	struct smw_crypto_asymm_enc_args *asymm_enc_args = args;
	struct asymmetric_encryption_params *asymm_enc_params =
		smw_utils_list_get_data(node);

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!check_id(asymm_enc_args->attrs.algo_id,
		      asymm_enc_params->algo_bitmap) ||
	    !check_id(asymm_enc_args->attrs.mode_id,
		      asymm_enc_params->mode_bitmap) ||
	    !check_id(asymm_enc_args->attrs.hash_id,
		      asymm_enc_params->hash_bitmap))
		status = SMW_STATUS_OPERATION_NOT_CONFIGURED;

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int asymm_encrypt_check_subsystem_caps(void *args, void *node)
{
	return common_check_subsystem_caps(args, node);
}

static int asymm_decrypt_check_subsystem_caps(void *args, void *node)
{
	return common_check_subsystem_caps(args, node);
}

static int check_asymm_enc_dec(smw_subsystem_t subsystem,
			       struct smw_asymmetric_encrypt_info *info,
			       enum operation_id op_id)
{
	int status = SMW_STATUS_INVALID_PARAM;

	enum subsystem_id id = SUBSYSTEM_ID_INVALID;
	enum smw_config_asymm_enc_algo_id algo_id =
		SMW_CONFIG_ASYMM_ENC_ALGO_ID_INVALID;
	enum smw_config_asymm_enc_mode_id mode_id =
		SMW_CONFIG_ASYMM_ENC_MODE_ID_INVALID;
	enum smw_config_hash_algo_id hash_id = SMW_CONFIG_HASH_ALGO_ID_INVALID;
	struct asymmetric_encryption_params params = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!info ||
	    info->algo_name == SMW_ASYMMETRIC_ENCRYPTION_ALGO_NAME_NONE)
		return status;

	status = smw_config_get_subsystem_id(subsystem, &id);
	if (status != SMW_STATUS_OK)
		return status;

	status = get_operation_params_lock(op_id, id, &params);
	if (status != SMW_STATUS_OK)
		return status;

	/* Check asymmetric encryption algo */
	status =
		smw_config_get_asymm_encrypt_algo_id(info->algo_name, &algo_id);
	if (status != SMW_STATUS_OK)
		return status;

	if (!check_id(algo_id, params.algo_bitmap))
		return SMW_STATUS_OPERATION_NOT_CONFIGURED;

	/* Check asymmetric encryption mode, if set */
	if (info->mode_name != SMW_ASYMMETRIC_ENCRYPTION_MODE_NAME_NONE) {
		status = smw_config_get_asymm_encrypt_mode_id(info->mode_name,
							      &mode_id);
		if (status != SMW_STATUS_OK)
			return status;

		if (!check_id(mode_id, params.mode_bitmap))
			return SMW_STATUS_OPERATION_NOT_CONFIGURED;
	}

	/* Check hash algorithm, if set */
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
				   smw_attr_algo_t permitted_algo)
{
	int status = SMW_STATUS_OK;
	struct asymmetric_encryption_params params = { 0 };
	smw_attr_algo_t algo = SMW_ATTR_ALGO_NONE;
	smw_attr_algo_t mode = SMW_ATTR_MODE_NONE;

	enum smw_config_asymm_enc_algo_id algo_id =
		SMW_CONFIG_ASYMM_ENC_ALGO_ID_INVALID;
	enum smw_config_asymm_enc_mode_id mode_id =
		SMW_CONFIG_ASYMM_ENC_MODE_ID_INVALID;

	SMW_DBG_TRACE_FUNCTION_CALL;

	status = get_operation_params(operation_id, ref, &params);
	if (status != SMW_STATUS_OK)
		goto end;

	mode = SMW_ATTR_GET_MODE(permitted_algo);
	algo = SMW_ATTR_GET_ALGO(permitted_algo);

	status = smw_utils_asymm_enc_attr_to_ids(permitted_algo, &algo_id,
						 &mode_id);
	if (status != SMW_STATUS_OK &&
	    status != SMW_STATUS_OPERATION_NOT_SUPPORTED)
		goto end;

	if ((algo == SMW_ATTR_ALGO_NONE ||
	     check_id(algo_id, params.algo_bitmap)) &&
	    ((mode == SMW_ATTR_MODE_NONE || mode == SMW_ATTR_MODE_ANY) ||
	     check_id(mode_id, params.mode_bitmap)))
		status = SMW_STATUS_OK;
	else
		status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

DEFINE_CONFIG_OPERATION_FUNC(asymm_encrypt);
DEFINE_CONFIG_OPERATION_FUNC(asymm_decrypt);

int asymm_encrypt_key_usable(unsigned int *ref,
			     struct smw_key_attributes *attributes)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
	smw_attr_usage_t usages = attributes->usage_flags;

	if (SMW_ATTR_USAGE_IS_ENCRYPT(usages)) {
		status =
			check_common_key_usable(OPERATION_ID_ASYMM_ENCRYPT, ref,
						attributes->permitted_algo);
		if (status != SMW_STATUS_OK)
			goto end;
	}

	if (SMW_ATTR_USAGE_IS_DECRYPT(usages))
		status =
			check_common_key_usable(OPERATION_ID_ASYMM_DECRYPT, ref,
						attributes->permitted_algo);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int smw_config_get_asymm_encrypt_algo_id(smw_asymmetric_encryption_algo_t name,
					 enum smw_config_asymm_enc_algo_id *id)
{
	int status = SMW_STATUS_UNKNOWN_ALGO_NAME;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (name == SMW_ASYMMETRIC_ENCRYPTION_ALGO_NAME_NONE) {
		status = SMW_STATUS_INVALID_PARAM;
	} else if (name < SMW_ASYMMETRIC_ENCRYPTION_ALGO_NAME_NB) {
		if (!SUB_OVERFLOW(name, SMW_CONFIG_ASYMM_ENC_ALGO_ID_OFFSET,
				  (int *)id))
			status = SMW_STATUS_OK;
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int smw_config_get_asymm_encrypt_mode_id(smw_asymmetric_encryption_mode_t name,
					 enum smw_config_asymm_enc_mode_id *id)
{
	int status = SMW_STATUS_UNKNOWN_MODE_NAME;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (name == SMW_ASYMMETRIC_ENCRYPTION_MODE_NAME_NONE) {
		*id = SMW_CONFIG_ASYMM_ENC_MODE_ID_INVALID;
		status = SMW_STATUS_OK;
	} else if (name < SMW_ASYMMETRIC_ENCRYPTION_MODE_NAME_NB) {
		if (!SUB_OVERFLOW(name, SMW_CONFIG_ASYMM_ENC_MODE_ID_OFFSET,
				  (int *)id))
			status = SMW_STATUS_OK;
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

__export enum smw_status_code
smw_config_check_asymmetric_encrypt(smw_subsystem_t subsystem,
				    struct smw_asymmetric_encrypt_info *info)
{
	return check_asymm_enc_dec(subsystem, info, OPERATION_ID_ASYMM_ENCRYPT);
}

__export enum smw_status_code
smw_config_check_asymmetric_decrypt(smw_subsystem_t subsystem,
				    struct smw_asymmetric_encrypt_info *info)
{
	return check_asymm_enc_dec(subsystem, info, OPERATION_ID_ASYMM_DECRYPT);
}
