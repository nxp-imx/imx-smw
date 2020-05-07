// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020 NXP
 */

#include "smw_status.h"

#include "smw_osal.h"
#include "global.h"
#include "debug.h"
#include "utils.h"
#include "list.h"
#include "operations.h"
#include "subsystems.h"
#include "config.h"
#include "keymgr.h"

#include "common.h"

const char *key_type_values = "KEY_TYPE_VALUES";
const char *key_size_range = "KEY_SIZE_RANGE";

static const char *const key_type_names[] = {
	[SMW_CONFIG_KEY_TYPE_ID_ECDSA_NIST] = "NIST",
	[SMW_CONFIG_KEY_TYPE_ID_ECDSA_BRAINPOOL_R1] = "BRAINPOOL_R1",
	[SMW_CONFIG_KEY_TYPE_ID_ECDSA_BRAINPOOL_T1] = "BRAINPOOL_T1",
	[SMW_CONFIG_KEY_TYPE_ID_AES] = "AES",
	[SMW_CONFIG_KEY_TYPE_ID_DES] = "DES",
	[SMW_CONFIG_KEY_TYPE_ID_DES3] = "DES3",
	[SMW_CONFIG_KEY_TYPE_ID_DSA_SM2_FP] = "DSA_SM2_FP",
	[SMW_CONFIG_KEY_TYPE_ID_SM4] = "SM4"
};

int read_key_type_names(char **start, char *end, unsigned long *bitmap)
{
	return read_names(start, end, bitmap, key_type_names,
			  SMW_CONFIG_KEY_TYPE_ID_NB);
}

int read_key_size_range(char **start, char *end, unsigned int *min,
			unsigned int *max)
{
	int status = SMW_STATUS_OK;
	char *cur = *start;

	unsigned int m;

	SMW_DBG_TRACE_FUNCTION_CALL;

	while ((cur < end) && (semicolon != *cur)) {
		m = 0;
		if (colon != *cur) {
			status = read_unsigned_integer(&cur, end, &m);
			if (status != SMW_STATUS_OK)
				goto end;
		}
		SMW_DBG_PRINTF(INFO, "Min: %d\n", m);

		*min = m;

		skip_insignificant_chars(&cur, end);

		if (colon != *cur) {
			status = SMW_STATUS_SYNTAX_ERROR;
			goto end;
		}
		cur++;

		skip_insignificant_chars(&cur, end);

		m = UINT_MAX;
		if (semicolon != *cur) {
			status = read_unsigned_integer(&cur, end, &m);
			if (status != SMW_STATUS_OK)
				goto end;
		}
		SMW_DBG_PRINTF(INFO, "Max: %d\n", m);

		*max = m;

		skip_insignificant_chars(&cur, end);
	}

	if (semicolon == *cur)
		cur++;

	*start = cur;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int read_params(char **start, char *end, enum operation_id operation_id,
		       void **params)
{
	int status = SMW_STATUS_OK;
	char *cur = *start;

	char buffer[SMW_CONFIG_MAX_PARAMS_NAME_LENGTH + 1];
	int length;

	unsigned long key_type_bitmap = SMW_ALL_ONES;

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

	p = SMW_UTILS_MALLOC(sizeof(struct key_operation_params));
	if (!p) {
		status = SMW_STATUS_ALLOC_FAILURE;
		goto end;
	}

	p->operation_id = operation_id;
	p->key_type_bitmap = key_type_bitmap;
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

__attribute__((weak)) void print_key_params(void *params)
{
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

static int generate_key_check_subsystem_caps(void *args, void *params)
{
	int status = SMW_STATUS_OK;

	struct smw_keymgr_generate_key_args *generate_key_args =
		(struct smw_keymgr_generate_key_args *)args;
	struct key_operation_params *generate_key_params =
		(struct key_operation_params *)params;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!check_id(generate_key_args->key_type_id,
		      generate_key_params->key_type_bitmap) ||
	    !check_security_size(generate_key_args->security_size,
				 generate_key_params->key_size_min,
				 generate_key_params->key_size_max))
		status = SMW_STATUS_OPERATION_NOT_CONFIGURED;

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int derive_key_check_subsystem_caps(void *args, void *params)
{
	int status = SMW_STATUS_OK;

	struct smw_keymgr_derive_key_args *derive_key_args =
		(struct smw_keymgr_derive_key_args *)args;
	struct key_operation_params *derive_key_params =
		(struct key_operation_params *)params;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!check_id(derive_key_args->key_type_id,
		      derive_key_params->key_type_bitmap) ||
	    !check_security_size(derive_key_args->security_size,
				 derive_key_params->key_size_min,
				 derive_key_params->key_size_max))
		status = SMW_STATUS_OPERATION_NOT_CONFIGURED;

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int update_key_check_subsystem_caps(void *args, void *params)
{
	int status = SMW_STATUS_OK;

	//struct smw_keymgr_update_key_args *update_key_args =
	//	(struct smw_keymgr_update_key_args *)args;
	//struct key_operation_params *update_key_params =
	//	(struct key_operation_params *)params;

	SMW_DBG_TRACE_FUNCTION_CALL;

	//TODO: implement update_key_check_subsystem_caps()

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int import_key_check_subsystem_caps(void *args, void *params)
{
	int status = SMW_STATUS_OK;

	struct smw_keymgr_import_key_args *import_key_args =
		(struct smw_keymgr_import_key_args *)args;
	struct key_operation_params *import_key_params =
		(struct key_operation_params *)params;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!check_id(import_key_args->key_type_id,
		      import_key_params->key_type_bitmap) ||
	    !check_security_size(import_key_args->input_buffer_length,
				 import_key_params->key_size_min,
				 import_key_params->key_size_max))
		status = SMW_STATUS_OPERATION_NOT_CONFIGURED;

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int export_key_check_subsystem_caps(void *args, void *params)
{
	int status = SMW_STATUS_OK;

	struct smw_keymgr_export_key_args *export_key_args =
		(struct smw_keymgr_export_key_args *)args;
	struct key_operation_params *export_key_params =
		(struct key_operation_params *)params;
	struct smw_key_identifier *key_identifier =
		export_key_args->key_identifier;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!check_id(key_identifier->key_type_id,
		      export_key_params->key_type_bitmap) ||
	    !check_security_size(key_identifier->security_size,
				 export_key_params->key_size_min,
				 export_key_params->key_size_max))
		status = SMW_STATUS_OPERATION_NOT_CONFIGURED;

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int delete_key_check_subsystem_caps(void *args, void *params)
{
	int status = SMW_STATUS_OK;

	struct smw_keymgr_delete_key_args *delete_key_args =
		(struct smw_keymgr_delete_key_args *)args;
	struct key_operation_params *delete_key_params =
		(struct key_operation_params *)params;
	struct smw_key_identifier *key_identifier =
		delete_key_args->key_identifier;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!check_id(key_identifier->key_type_id,
		      delete_key_params->key_type_bitmap) ||
	    !check_security_size(key_identifier->security_size,
				 delete_key_params->key_size_min,
				 delete_key_params->key_size_max))
		status = SMW_STATUS_OPERATION_NOT_CONFIGURED;

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

#define DEFINE_KEYMGR_OPERATION_FUNC(operation)                                \
	struct operation_func operation##_func = {                             \
		.read = operation##_read_params,                               \
		.destroy = NULL,                                               \
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

int smw_config_get_key_type_id(const char *name,
			       enum smw_config_key_type_id *id)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	return get_id(name, key_type_names, SMW_CONFIG_KEY_TYPE_ID_NB, id);
}
