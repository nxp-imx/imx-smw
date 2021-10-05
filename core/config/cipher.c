// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021 NXP
 */

#include "smw_status.h"

#include "compiler.h"
#include "smw_osal.h"
#include "global.h"
#include "debug.h"
#include "utils.h"
#include "operations.h"
#include "subsystems.h"
#include "name.h"
#include "cipher.h"
#include "tag.h"

#include "common.h"

static const char *const cipher_mode_names[] = {
	[SMW_CONFIG_CIPHER_MODE_ID_CBC] = "CBC",
	[SMW_CONFIG_CIPHER_MODE_ID_CCM] = "CCM",
	[SMW_CONFIG_CIPHER_MODE_ID_CTR] = "CTR",
	[SMW_CONFIG_CIPHER_MODE_ID_CTS] = "CTS",
	[SMW_CONFIG_CIPHER_MODE_ID_ECB] = "ECB",
	[SMW_CONFIG_CIPHER_MODE_ID_GCM] = "GCM",
	[SMW_CONFIG_CIPHER_MODE_ID_XTS] = "XTS"
};

static const char *const cipher_op_type_names[] = {
	[SMW_CONFIG_CIPHER_OP_ID_ENCRYPT] = "ENCRYPT",
	[SMW_CONFIG_CIPHER_OP_ID_DECRYPT] = "DECRYPT"
};

/**
 * read_cipher_op_type_names() - Read a list of cipher operation types names
 * @start: Address of the pointer to the current char.
 * @end: Pointer to the last char of the buffer being parsed.
 * @bitmap: Bitmap representing the configured names.
 *
 * This function reads a list of names from the current char of the buffer being
 * parsed until a semicolon is detected.
 * The pointer to the current char is moved to the next char after the
 * semicolon.
 * Insignificant chars are skipped if any.
 *
 * Names are compared with values set in @cipher_op_type_names.
 * @bitmap is set with enum smw_config_cipher_op_type_id values.
 *
 * Return:
 * error code.
 */
static int read_cipher_op_type_names(char **start, char *end,
				     unsigned long *bitmap)
{
	return read_names(start, end, bitmap, cipher_op_type_names,
			  SMW_CONFIG_CIPHER_OP_ID_NB);
}

/**
 * read_cipher_mode_names() - Read a list of cipher mode names
 * @start: Address of the pointer to the current char.
 * @end: Pointer to the last char of the buffer being parsed.
 * @bitmap: Bitmap representing the configured names.
 *
 * This function reads a list of names from the current char of the buffer being
 * parsed until a semicolon is detected.
 * The pointer to the current char is moved to the next char after the
 * semicolon.
 * Insignificant chars are skipped if any.
 *
 * Names are compared with values set in @cipher_mode_names.
 * @bitmap is set with enum smw_config_cipher_mode_id values.
 *
 * Return:
 * error code.
 */
static int read_cipher_mode_names(char **start, char *end,
				  unsigned long *bitmap)
{
	return read_names(start, end, bitmap, cipher_mode_names,
			  SMW_CONFIG_CIPHER_MODE_ID_NB);
}

/**
 * cipher_common_read_params() - Read common cipher parameters
 * @start: Address of the pointer to the current char.
 * @end: Pointer to the last char of the buffer being parsed.
 * @operation_id: Operation ID.
 * @params: Pointer to cipher parameter structure to update and fill.
 *
 * Parameters are key type, operation mode and operation type.
 *
 * Return:
 * error code.
 */
static int cipher_common_read_params(char **start, char *end,
				     enum operation_id operation_id,
				     void **params)
{
	int status = SMW_STATUS_OK;
	char *cur = *start;

	char buffer[SMW_CONFIG_MAX_PARAMS_NAME_LENGTH + 1];
	unsigned int length;

	struct cipher_params *p;
	unsigned long key_size_range_bitmap = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	p = SMW_UTILS_CALLOC(1, sizeof(*p));
	if (!p) {
		status = SMW_STATUS_ALLOC_FAILURE;
		goto end;
	}

	p->operation_id = operation_id;
	init_key_params(&p->key);

	while ((cur < end) && (open_square_bracket != *cur)) {
		status = read_params_name(&cur, end, buffer);
		if (status != SMW_STATUS_OK)
			goto end;
		SMW_DBG_PRINTF(INFO, "Parameter: %s\n", buffer);
		length = SMW_UTILS_STRLEN(buffer);

		skip_insignificant_chars(&cur, end);

		if (!SMW_UTILS_STRNCMP(buffer, mode_values, length)) {
			status = read_cipher_mode_names(&cur, end,
							&p->mode_bitmap);
			if (status != SMW_STATUS_OK)
				goto end;
		} else if (!SMW_UTILS_STRNCMP(buffer, op_type_values, length)) {
			status = read_cipher_op_type_names(&cur, end,
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

	if (!p->mode_bitmap)
		p->mode_bitmap = SMW_ALL_ONES;

	if (!p->key.type_bitmap)
		p->key.type_bitmap = SMW_ALL_ONES;

	if (!p->op_bitmap)
		p->op_bitmap = SMW_ALL_ONES;

	*params = p;

	*start = cur;

end:
	if (p && status != SMW_STATUS_OK)
		SMW_UTILS_FREE(p);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int cipher_read_params(char **start, char *end, void **params)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	return cipher_common_read_params(start, end, OPERATION_ID_CIPHER,
					 params);
}

static int cipher_multi_part_read_params(char **start, char *end, void **params)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	return cipher_common_read_params(start, end,
					 OPERATION_ID_CIPHER_MULTI_PART,
					 params);
}

__weak void cipher_common_print_params(void *params)
{
	(void)params;
}

static void cipher_print_params(void *params)
{
	cipher_common_print_params(params);
}

static void cipher_multi_part_print_params(void *params)
{
	cipher_common_print_params(params);
}

/**
 * check_common_subsystem_caps() - Check subsystem capabilities for cipher
 *                                 one-shot and multi-part operations
 * @args: Internal cipher arguments.
 * @params: Cipher operation subsystem parameters.
 *
 * This function checks if mode and operation type set in @args are supported
 * by the subsystem.
 * It also checks that all keys set in @args are supported.
 *
 * Return:
 * SMW_STATUS_OK			- Success
 * SMW_STATUS_OPERATION_NOT_CONFIGURED	- Operation not configured
 */
static int check_common_subsystem_caps(void *args, void *params)
{
	int status = SMW_STATUS_OPERATION_NOT_CONFIGURED;
	unsigned int i;
	struct smw_crypto_cipher_args *cipher_args = args;
	struct cipher_params *cipher_params = params;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!check_id(cipher_args->mode_id, cipher_params->mode_bitmap) ||
	    !check_id(cipher_args->op_id, cipher_params->op_bitmap))
		goto end;

	for (i = 0; i < cipher_args->nb_keys; i++)
		if (!check_key(&cipher_args->keys_desc[i]->identifier,
			       &cipher_params->key))
			goto end;

	status = SMW_STATUS_OK;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int cipher_check_subsystem_caps(void *args, void *params)
{
	return check_common_subsystem_caps(args, params);
}

static int cipher_multi_part_check_subsystem_caps(void *args, void *params)
{
	/* This function is only called by cipher initialization */

	return check_common_subsystem_caps(args, params);
}

DEFINE_CONFIG_OPERATION_FUNC(cipher);
DEFINE_CONFIG_OPERATION_FUNC(cipher_multi_part);

int smw_config_get_cipher_mode_id(const char *name,
				  enum smw_config_cipher_mode_id *id)
{
	int status = SMW_STATUS_OK;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!name)
		*id = SMW_CONFIG_CIPHER_MODE_ID_INVALID;
	else
		status =
			smw_utils_get_string_index(name, cipher_mode_names,
						   SMW_CONFIG_CIPHER_MODE_ID_NB,
						   id);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int smw_config_get_cipher_op_type_id(const char *name,
				     enum smw_config_cipher_op_type_id *id)
{
	int status = SMW_STATUS_OK;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!name)
		*id = SMW_CONFIG_CIPHER_OP_ID_INVALID;
	else
		status = smw_utils_get_string_index(name, cipher_op_type_names,
						    SMW_CONFIG_CIPHER_OP_ID_NB,
						    id);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}
