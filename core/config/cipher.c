// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021, 2023 NXP
 */

#include "smw_config.h"
#include "smw_status.h"

#include "compiler.h"
#include "global.h"
#include "debug.h"
#include "utils.h"
#include "operations.h"
#include "subsystems.h"
#include "cipher.h"
#include "tag.h"

#include "common.h"

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
static int cipher_common_read_params(char **start, char *end, void **params)
{
	int status = SMW_STATUS_OK;
	char *cur = *start;

	char buffer[SMW_CONFIG_MAX_PARAMS_NAME_LENGTH + 1] = { 0 };
	size_t length = 0;

	struct cipher_params *p;
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

		if (!SMW_UTILS_STRNCMP(buffer, mode_values, length)) {
			status = smw_utils_cipher_mode_names(&cur, end,
							     &p->mode_bitmap);
			if (status != SMW_STATUS_OK)
				goto end;
		} else if (!SMW_UTILS_STRNCMP(buffer, op_type_values, length)) {
			status = smw_utils_cipher_op_type_names(&cur, end,
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
	return cipher_common_read_params(start, end, params);
}

static int cipher_multi_part_read_params(char **start, char *end, void **params)
{
	return cipher_common_read_params(start, end, params);
}

static void cipher_common_merge_params(void *caps, void *params)
{
	struct cipher_params *cipher_caps = caps;
	struct cipher_params *cipher_params = params;

	SMW_DBG_TRACE_FUNCTION_CALL;

	cipher_caps->mode_bitmap |= cipher_params->mode_bitmap;
	cipher_caps->op_bitmap |= cipher_params->op_bitmap;
	merge_key_params(&cipher_caps->key, &cipher_params->key);
}

static void cipher_merge_params(void *caps, void *params)
{
	return cipher_common_merge_params(caps, params);
}

static void cipher_multi_part_merge_params(void *caps, void *params)
{
	return cipher_common_merge_params(caps, params);
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
	unsigned int i = 0;
	struct smw_crypto_cipher_args *cipher_args = args;
	struct cipher_params *cipher_params = params;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!check_id(cipher_args->mode_id, cipher_params->mode_bitmap) ||
	    !check_id(cipher_args->op_id, cipher_params->op_bitmap))
		goto end;

	for (; i < cipher_args->nb_keys; i++)
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

__export enum smw_status_code
smw_config_check_cipher(smw_subsystem_t subsystem, struct smw_cipher_info *info)
{
	int status = SMW_STATUS_INVALID_PARAM;
	enum subsystem_id id = SUBSYSTEM_ID_INVALID;
	enum smw_config_key_type_id key_type_id =
		SMW_CONFIG_KEY_TYPE_ID_INVALID;
	enum smw_config_cipher_op_type_id op_type_id =
		SMW_CONFIG_CIPHER_OP_ID_INVALID;
	enum smw_config_cipher_mode_id mode_id =
		SMW_CONFIG_CIPHER_MODE_ID_INVALID;
	enum operation_id op_id = OPERATION_ID_CIPHER;
	struct cipher_params params = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!info || !info->key_type_name || !info->mode || !info->op_type)
		return status;

	status = smw_config_get_subsystem_id(subsystem, &id);
	if (status != SMW_STATUS_OK)
		return status;

	status = smw_config_get_key_type_id(info->key_type_name, &key_type_id);
	if (status != SMW_STATUS_OK)
		return status;

	status = smw_utils_get_cipher_mode_id(info->mode, &mode_id);
	if (status != SMW_STATUS_OK)
		return status;

	status = smw_utils_get_cipher_op_type_id(info->op_type, &op_type_id);
	if (status != SMW_STATUS_OK)
		return status;

	if (info->multipart)
		op_id = OPERATION_ID_CIPHER_MULTI_PART;

	status = get_operation_params(op_id, id, &params);
	if (status != SMW_STATUS_OK)
		return status;

	/* Check key type */
	if (!check_id(key_type_id, params.key.type_bitmap))
		return SMW_STATUS_OPERATION_NOT_CONFIGURED;

	/* Check operation mode*/
	if (!check_id(mode_id, params.mode_bitmap))
		return SMW_STATUS_OPERATION_NOT_CONFIGURED;

	/* Check operation type */
	if (!check_id(op_type_id, params.op_bitmap))
		return SMW_STATUS_OPERATION_NOT_CONFIGURED;

	return SMW_STATUS_OK;
}
