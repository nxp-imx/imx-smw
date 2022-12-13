// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2023 NXP
 */

#include "smw_status.h"

#include "compiler.h"
#include "global.h"
#include "debug.h"
#include "utils.h"
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
	[SMW_CONFIG_KEY_TYPE_ID_HMAC] = "HMAC",
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

static int read_key_size_range(char **start, char *end, const char *type_name,
			       unsigned long *size_range_bitmap,
			       struct op_key *key)
{
	int status = SMW_STATUS_OK;
	char *cur = *start;

	enum smw_config_key_type_id id;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_ASSERT(size_range_bitmap);

	status = smw_config_get_key_type_id(type_name, &id);
	if (status != SMW_STATUS_OK)
		goto end;

	/* Key size range cannot be defined twice */
	if (check_id(id, *size_range_bitmap)) {
		status = SMW_STATUS_RANGE_DUPLICATE;
		goto end;
	}

	/* Key type must be listed before size range is defined */
	if (!check_id(id, key->type_bitmap)) {
		status = SMW_STATUS_ALGO_NOT_CONFIGURED;
		goto end;
	}

	status = read_range(&cur, end, &key->size_range[id]);
	if (status != SMW_STATUS_OK)
		goto end;

	set_bit(size_range_bitmap, sizeof(*size_range_bitmap) << 3, id);

	*start = cur;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
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

bool read_key(char *tag, unsigned int length, char **start, char *end,
	      unsigned long *key_size_range_bitmap, struct op_key *key,
	      int *status)
{
	bool match = false;
	char *cur = *start;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!SMW_UTILS_STRNCMP(tag, key_type_values, length)) {
		match = true;
		*status = read_key_type_names(&cur, end, &key->type_bitmap);
	} else if (get_tag_prefix(tag, length, _size_range)) {
		match = true;
		*status = read_key_size_range(&cur, end, tag,
					      key_size_range_bitmap, key);
	}

	if (match && *status == SMW_STATUS_OK)
		*start = cur;

	SMW_DBG_PRINTF(VERBOSE, "%s returned %s\n", __func__,
		       match ? "true" : "false");
	return match;
}

static int read_params(char **start, char *end, enum operation_id operation_id,
		       void **params)
{
	int status = SMW_STATUS_OK;
	char *cur = *start;

	char buffer[SMW_CONFIG_MAX_PARAMS_NAME_LENGTH + 1];
	unsigned int length;

	struct key_operation_params *p;
	unsigned long key_size_range_bitmap = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	p = SMW_UTILS_CALLOC(1, sizeof(*p));
	if (!p) {
		status = SMW_STATUS_ALLOC_FAILURE;
		goto end;
	}

	init_key_params(&p->key);

	while ((cur < end) && (open_square_bracket != *cur)) {
		status = read_params_name(&cur, end, buffer);
		if (status != SMW_STATUS_OK)
			goto end;
		SMW_DBG_PRINTF(INFO, "Parameter: %s\n", buffer);
		length = SMW_UTILS_STRLEN(buffer);

		skip_insignificant_chars(&cur, end);

		if (!SMW_UTILS_STRNCMP(buffer, op_type_values, length)) {
			status = read_key_op_names(&cur, end, operation_id,
						   &p->op_bitmap);
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

	if (!p->op_bitmap)
		p->op_bitmap = SMW_ALL_ONES;

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

static void merge_params(void *caps, void *params)
{
	struct key_operation_params *key_operation_caps = caps;
	struct key_operation_params *key_operation_params = params;

	SMW_DBG_TRACE_FUNCTION_CALL;

	key_operation_caps->op_bitmap |= key_operation_params->op_bitmap;
	merge_key_params(&key_operation_caps->key, &key_operation_params->key);
}

__weak void print_key_operation_params(void *params)
{
	(void)params;
}

static int check_subsystem_caps(struct smw_keymgr_descriptor *key_descriptor,
				struct key_operation_params *params)
{
	int status = SMW_STATUS_OK;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!check_key(&key_descriptor->identifier, &params->key))
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
		.merge = merge_params,                                         \
		.print = print_key_operation_params,                           \
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
