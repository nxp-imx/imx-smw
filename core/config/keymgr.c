// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2021 NXP
 */

#include "smw_status.h"

#include "compiler.h"
#include "smw_osal.h"
#include "global.h"
#include "debug.h"
#include "utils.h"
#include "list.h"
#include "operations.h"
#include "subsystems.h"
#include "config.h"
#include "keymgr.h"
#include "keymgr_derive.h"
#include "name.h"

#include "common.h"
#include "tag.h"

static const char *const key_type_names[] = {
	[SMW_CONFIG_KEY_TYPE_ID_ECDSA_NIST] = "NIST",
	[SMW_CONFIG_KEY_TYPE_ID_ECDSA_BRAINPOOL_R1] = "BRAINPOOL_R1",
	[SMW_CONFIG_KEY_TYPE_ID_ECDSA_BRAINPOOL_T1] = "BRAINPOOL_T1",
	[SMW_CONFIG_KEY_TYPE_ID_ECDH_NIST] = "ECDH_NIST",
	[SMW_CONFIG_KEY_TYPE_ID_ECDH_BRAINPOOL_R1] = "ECDH_BRAINPOOL_R1",
	[SMW_CONFIG_KEY_TYPE_ID_ECDH_BRAINPOOL_T1] = "ECDH_BRAINPOOL_T1",
	[SMW_CONFIG_KEY_TYPE_ID_AES] = "AES",
	[SMW_CONFIG_KEY_TYPE_ID_DES] = "DES",
	[SMW_CONFIG_KEY_TYPE_ID_DES3] = "DES3",
	[SMW_CONFIG_KEY_TYPE_ID_DSA_SM2_FP] = "DSA_SM2_FP",
	[SMW_CONFIG_KEY_TYPE_ID_SM4] = "SM4",
	[SMW_CONFIG_KEY_TYPE_ID_HMAC_MD5] = "HMAC_MD5",
	[SMW_CONFIG_KEY_TYPE_ID_HMAC_SHA1] = "HMAC_SHA1",
	[SMW_CONFIG_KEY_TYPE_ID_HMAC_SHA224] = "HMAC_SHA224",
	[SMW_CONFIG_KEY_TYPE_ID_HMAC_SHA256] = "HMAC_SHA256",
	[SMW_CONFIG_KEY_TYPE_ID_HMAC_SHA384] = "HMAC_SHA384",
	[SMW_CONFIG_KEY_TYPE_ID_HMAC_SHA512] = "HMAC_SHA512",
	[SMW_CONFIG_KEY_TYPE_ID_HMAC_SM3] = "HMAC_SM3",
	[SMW_CONFIG_KEY_TYPE_ID_RSA] = "RSA",
	[SMW_CONFIG_KEY_TYPE_ID_DH] = "DH",
	[SMW_CONFIG_KEY_TYPE_ID_TLS_MASTER_KEY] = "TLS_MASTER_KEY"
};

static const char *const key_derive_op_names[] = {
	[SMW_CONFIG_KDF_TLS12_KEY_EXCHANGE] = "TLS12_KEY_EXCHANGE"
};

int read_key_type_names(char **start, char *end, unsigned long *bitmap)
{
	return read_names(start, end, bitmap, key_type_names,
			  SMW_CONFIG_KEY_TYPE_ID_NB);
}

static int read_key_op_names(char **start, char *end, enum operation_id op_id,
			     unsigned long *bitmap)
{
	const char *const *op_names;
	unsigned int nb_op_names;

	switch (op_id) {
	case OPERATION_ID_DERIVE_KEY:
		op_names = key_derive_op_names;
		nb_op_names = SMW_CONFIG_KDF_ID_NB;
		break;

	default:
		return SMW_STATUS_UNKNOWN_NAME;
	}

	return read_names(start, end, bitmap, op_names, nb_op_names);
}

static int read_params(char **start, char *end, enum operation_id operation_id,
		       void **params)
{
	int status = SMW_STATUS_OK;
	char *cur = *start;

	char buffer[SMW_CONFIG_MAX_PARAMS_NAME_LENGTH + 1];
	int length;

	unsigned long key_type_bitmap = SMW_ALL_ONES;
	unsigned long op_bitmap = 0;

	unsigned int key_size_min = 0;
	unsigned int key_size_max = UINT_MAX;

	struct key_operation_params *p;

	SMW_DBG_TRACE_FUNCTION_CALL;

	while ((cur < end) && (open_square_bracket != *cur)) {
		status = read_params_name(&cur, end, buffer);
		if (status != SMW_STATUS_OK)
			goto end;
		SMW_DBG_PRINTF(INFO, "Parameter: %s\n", buffer);
		length = SMW_UTILS_STRLEN(buffer);

		skip_insignificant_chars(&cur, end);

		if (!SMW_UTILS_STRNCMP(buffer, key_type_values, length)) {
			status = read_key_type_names(&cur, end,
						     &key_type_bitmap);
			if (status != SMW_STATUS_OK)
				goto end;
		} else if (!SMW_UTILS_STRNCMP(buffer, key_size_range, length)) {
			status = read_range(&cur, end, &key_size_min,
					    &key_size_max);
			if (status != SMW_STATUS_OK)
				goto end;
		} else if (!SMW_UTILS_STRNCMP(buffer, op_type_values, length)) {
			status = read_key_op_names(&cur, end, operation_id,
						   &op_bitmap);
			if (status != SMW_STATUS_OK)
				goto end;
		} else {
			status = skip_param(&cur, end);
			if (status != SMW_STATUS_OK)
				goto end;
		}

		skip_insignificant_chars(&cur, end);
	}

	p = SMW_UTILS_MALLOC(sizeof(struct key_operation_params));
	if (!p) {
		status = SMW_STATUS_ALLOC_FAILURE;
		goto end;
	}

	p->operation_id = operation_id;
	p->key_type_bitmap = key_type_bitmap;
	p->op_bitmap = op_bitmap;
	p->key_size_min = key_size_min;
	p->key_size_max = key_size_max;

	*params = p;

	*start = cur;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int generate_key_read_params(char **start, char *end, void **params)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	return read_params(start, end, OPERATION_ID_GENERATE_KEY, params);
}

static int derive_key_read_params(char **start, char *end, void **params)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	return read_params(start, end, OPERATION_ID_DERIVE_KEY, params);
}

static int update_key_read_params(char **start, char *end, void **params)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	return read_params(start, end, OPERATION_ID_UPDATE_KEY, params);
}

static int import_key_read_params(char **start, char *end, void **params)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	return read_params(start, end, OPERATION_ID_IMPORT_KEY, params);
}

static int export_key_read_params(char **start, char *end, void **params)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	return read_params(start, end, OPERATION_ID_EXPORT_KEY, params);
}

static int delete_key_read_params(char **start, char *end, void **params)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	return read_params(start, end, OPERATION_ID_DELETE_KEY, params);
}

__weak void print_key_params(void *params)
{
	(void)params;
}

bool check_security_size(unsigned int security_size, unsigned int key_size_min,
			 unsigned int key_size_max)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	return ((security_size >= key_size_min) &&
		(security_size <= key_size_max)) ?
		       true :
		       false;
}

static int check_subsystem_caps(struct smw_keymgr_descriptor *key_descriptor,
				struct key_operation_params *params)
{
	int status = SMW_STATUS_OK;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!check_id(key_descriptor->identifier.type_id,
		      params->key_type_bitmap) ||
	    !check_security_size(key_descriptor->identifier.security_size,
				 params->key_size_min, params->key_size_max))
		status = SMW_STATUS_OPERATION_NOT_CONFIGURED;

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int generate_key_check_subsystem_caps(void *args, void *params)
{
	int status = SMW_STATUS_OK;

	struct smw_keymgr_descriptor *key_descriptor =
		&((struct smw_keymgr_generate_key_args *)args)->key_descriptor;

	SMW_DBG_TRACE_FUNCTION_CALL;

	status = check_subsystem_caps(key_descriptor, params);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int derive_key_check_subsystem_caps(void *args, void *params)
{
	int status = SMW_STATUS_OK;

	struct smw_keymgr_derive_key_args *derive_args = args;
	struct key_operation_params *op_params = params;

	SMW_DBG_TRACE_FUNCTION_CALL;

	status = check_subsystem_caps(&derive_args->key_base, op_params);

	/*
	 * Check if the Key Derivation Function if specified is
	 * supported by the subsystem.
	 */
	if (status == SMW_STATUS_OK &&
	    derive_args->kdf_id != SMW_CONFIG_KDF_ID_INVALID) {
		if (!check_id(derive_args->kdf_id, op_params->op_bitmap))
			status = SMW_STATUS_OPERATION_NOT_CONFIGURED;
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int update_key_check_subsystem_caps(void *args, void *params)
{
	(void)args;
	(void)params;

	int status = SMW_STATUS_OK;

	//struct smw_keymgr_update_key_args *update_key_args = args;
	//struct key_operation_params *update_key_params = params;

	SMW_DBG_TRACE_FUNCTION_CALL;

	//TODO: implement update_key_check_subsystem_caps()

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int import_key_check_subsystem_caps(void *args, void *params)
{
	int status = SMW_STATUS_OK;

	struct smw_keymgr_descriptor *key_descriptor =
		&((struct smw_keymgr_import_key_args *)args)->key_descriptor;

	SMW_DBG_TRACE_FUNCTION_CALL;

	status = check_subsystem_caps(key_descriptor, params);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int export_key_check_subsystem_caps(void *args, void *params)
{
	int status = SMW_STATUS_OK;

	struct smw_keymgr_descriptor *key_descriptor =
		&((struct smw_keymgr_export_key_args *)args)->key_descriptor;

	SMW_DBG_TRACE_FUNCTION_CALL;

	status = check_subsystem_caps(key_descriptor, params);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int delete_key_check_subsystem_caps(void *args, void *params)
{
	int status = SMW_STATUS_OK;

	struct smw_keymgr_descriptor *key_descriptor =
		&((struct smw_keymgr_delete_key_args *)args)->key_descriptor;

	SMW_DBG_TRACE_FUNCTION_CALL;

	status = check_subsystem_caps(key_descriptor, params);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

#define DEFINE_KEYMGR_OPERATION_FUNC(operation)                                \
	struct operation_func operation##_func = {                             \
		.read = operation##_read_params,                               \
		.print = print_key_params,                                     \
		.check_subsystem_caps = operation##_check_subsystem_caps,      \
	};                                                                     \
	struct operation_func *smw_##operation##_get_func(void)                \
	{                                                                      \
		return &operation##_func;                                      \
	}

DEFINE_KEYMGR_OPERATION_FUNC(generate_key);
DEFINE_KEYMGR_OPERATION_FUNC(derive_key);
DEFINE_KEYMGR_OPERATION_FUNC(update_key);
DEFINE_KEYMGR_OPERATION_FUNC(import_key);
DEFINE_KEYMGR_OPERATION_FUNC(export_key);
DEFINE_KEYMGR_OPERATION_FUNC(delete_key);

void smw_config_get_key_type_name(enum smw_config_key_type_id id,
				  const char **name)
{
	unsigned int index = id;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (id < SMW_CONFIG_KEY_TYPE_ID_NB &&
	    id != SMW_CONFIG_KEY_TYPE_ID_INVALID)
		*name = key_type_names[index];
	else
		*name = NULL;
}

int smw_config_get_key_type_id(const char *name,
			       enum smw_config_key_type_id *id)
{
	int status = SMW_STATUS_OK;

	SMW_DBG_TRACE_FUNCTION_CALL;

	/* name == NULL is an acceptable input from caller.
	 * Just set *id to invalid and return status OK.
	 */
	*id = SMW_CONFIG_KEY_TYPE_ID_INVALID;

	if (name)
		status = smw_utils_get_string_index(name, key_type_names,
						    SMW_CONFIG_KEY_TYPE_ID_NB,
						    id);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int smw_config_get_kdf_id(const char *name, enum smw_config_kdf_id *id)
{
	int status = SMW_STATUS_OK;

	SMW_DBG_TRACE_FUNCTION_CALL;

	/* It's not an error to have a @name parameter NULL */
	*id = SMW_CONFIG_KDF_ID_INVALID;

	if (name)
		status = smw_utils_get_string_index(name, key_derive_op_names,
						    SMW_CONFIG_KDF_ID_NB, id);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);

	return status;
}
