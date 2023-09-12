// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include "smw_status.h"

#include "compiler.h"
#include "debug.h"
#include "utils.h"
#include "storage.h"
#include "tag.h"

#include "common.h"

static int storage_store_read_params(char **start, char *end, void **params)
{
	int status = SMW_STATUS_OK;
	char *cur = *start;

	SMW_DBG_TRACE_FUNCTION_CALL;

	char buffer[SMW_CONFIG_MAX_PARAMS_NAME_LENGTH + 1] = { 0 };
	size_t length = 0;

	struct storage_store_params *p = NULL;
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
		} else if (!SMW_UTILS_STRNCMP(buffer, hash_algo_values,
					      length)) {
			status = smw_utils_hash_algo_names(&cur, end,
							   &p->hash_bitmap);
			if (status != SMW_STATUS_OK)
				goto end;
		} else if (!SMW_UTILS_STRNCMP(buffer, mac_algo_values,
					      length)) {
			status =
				read_mac_algo_names(&cur, end, &p->algo_bitmap);
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

	if (!p->algo_bitmap)
		p->algo_bitmap = SMW_ALL_ONES;

	if (!p->hash_bitmap)
		p->hash_bitmap = SMW_ALL_ONES;

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

static int storage_retrieve_read_params(char **start, char *end, void **params)
{
	(void)params;

	int status = SMW_STATUS_OK;
	char *cur = *start;

	SMW_DBG_TRACE_FUNCTION_CALL;

	while ((cur < end) && (open_square_bracket != *cur)) {
		status = skip_param(&cur, end);
		if (status != SMW_STATUS_OK)
			goto end;

		skip_insignificant_chars(&cur, end);
	}

	*start = cur;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int storage_delete_read_params(char **start, char *end, void **params)
{
	(void)params;

	int status = SMW_STATUS_OK;
	char *cur = *start;

	SMW_DBG_TRACE_FUNCTION_CALL;

	while ((cur < end) && (open_square_bracket != *cur)) {
		status = skip_param(&cur, end);
		if (status != SMW_STATUS_OK)
			goto end;

		skip_insignificant_chars(&cur, end);
	}

	*start = cur;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static void storage_store_merge_params(void *caps, void *params)
{
	struct storage_store_params *store_caps = caps;
	struct storage_store_params *store_params = params;

	SMW_DBG_TRACE_FUNCTION_CALL;

	store_caps->mode_bitmap |= store_params->mode_bitmap;
	store_caps->algo_bitmap |= store_params->algo_bitmap;
	store_caps->hash_bitmap |= store_params->hash_bitmap;
	merge_key_params(&store_caps->key, &store_params->key);
}

static void storage_retrieve_merge_params(void *caps, void *params)
{
	(void)caps;
	(void)params;

	SMW_DBG_TRACE_FUNCTION_CALL;
}

static void storage_delete_merge_params(void *caps, void *params)
{
	(void)caps;
	(void)params;

	SMW_DBG_TRACE_FUNCTION_CALL;
}

__weak void storage_store_print_params(void *params)
{
	(void)params;
}

static void storage_retrieve_print_params(void *params)
{
	(void)params;
}

static void storage_delete_print_params(void *params)
{
	(void)params;
}

static int storage_store_check_subsystem_caps(void *args, void *params)
{
	int status = SMW_STATUS_OPERATION_NOT_CONFIGURED;
	unsigned int i = 0;
	struct smw_storage_store_data_args *storage_args = args;
	struct smw_storage_enc_args *enc_args = &storage_args->enc_args;
	struct smw_storage_sign_args *sign_args = &storage_args->sign_args;
	struct storage_store_params *store_params = params;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (enc_args->mode_id != SMW_CONFIG_CIPHER_MODE_ID_INVALID &&
	    !check_id(enc_args->mode_id, store_params->mode_bitmap))
		goto end;

	if (sign_args->algo_id != SMW_CONFIG_MAC_ALGO_ID_INVALID &&
	    !check_id(sign_args->algo_id, store_params->algo_bitmap))
		goto end;

	if (sign_args->hash_id != SMW_CONFIG_HASH_ALGO_ID_INVALID &&
	    !check_id(sign_args->algo_id, store_params->hash_bitmap))
		goto end;

	if (sign_args->key_descriptor.identifier.type_id !=
		    SMW_CONFIG_KEY_TYPE_ID_INVALID &&
	    !check_key(&sign_args->key_descriptor.identifier,
		       &store_params->key))
		goto end;

	for (; i < enc_args->nb_keys; i++)
		if (!check_key(&enc_args->keys_desc[i]->identifier,
			       &store_params->key))
			goto end;

	status = SMW_STATUS_OK;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int storage_retrieve_check_subsystem_caps(void *args, void *params)
{
	(void)args;
	(void)params;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, SMW_STATUS_OK);
	return SMW_STATUS_OK;
}

static int storage_delete_check_subsystem_caps(void *args, void *params)
{
	(void)args;
	(void)params;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, SMW_STATUS_OK);
	return SMW_STATUS_OK;
}

DEFINE_CONFIG_OPERATION_FUNC(storage_store);
DEFINE_CONFIG_OPERATION_FUNC(storage_retrieve);
DEFINE_CONFIG_OPERATION_FUNC(storage_delete);
