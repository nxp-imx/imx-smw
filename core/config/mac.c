// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2024 NXP
 */

#include "smw_config.h"
#include "smw_crypto.h"

#include "compiler.h"
#include "debug.h"
#include "mac.h"
#include "tag.h"
#include "utils.h"
#include "list.h"

#include "common.h"

static const char *const mac_algo_strings[] = {
	[SMW_CONFIG_MAC_ALGO_ID_CMAC] = "CMAC",
	[SMW_CONFIG_MAC_ALGO_ID_CMAC_TRUNCATED] = "CMAC_TRUNCATED",
	[SMW_CONFIG_MAC_ALGO_ID_HMAC] = "HMAC",
	[SMW_CONFIG_MAC_ALGO_ID_HMAC_TRUNCATED] = "HMAC_TRUNCATED",
};

static unsigned int mac_algo_attrs[] = {
	[SMW_CONFIG_MAC_ALGO_ID_CMAC] = SMW_ATTR_ALGO_AES,
	[SMW_CONFIG_MAC_ALGO_ID_CMAC_TRUNCATED] = SMW_ATTR_ALGO_AES,
	[SMW_CONFIG_MAC_ALGO_ID_HMAC] = SMW_ATTR_ALGO_HMAC,
	[SMW_CONFIG_MAC_ALGO_ID_HMAC_TRUNCATED] = SMW_ATTR_ALGO_HMAC,
	[SMW_CONFIG_MAC_ALGO_ID_NB] = 0,
};

int read_mac_algo_strings(char **start, char *end, unsigned long *bitmap)
{
	int status =
		smw_config_read_strings(start, end, bitmap, mac_algo_strings,
					SMW_CONFIG_MAC_ALGO_ID_NB);
	if (status == SMW_STATUS_UNKNOWN_NAME)
		status = SMW_STATUS_UNKNOWN_ALGO_NAME;

	return status;
}

static int mac_read_params(char **start, char *end, void **params)
{
	int status = SMW_STATUS_OK;
	char *cur = *start;

	char buffer[SMW_CONFIG_MAX_PARAMS_STRING_LENGTH + 1] = { 0 };
	size_t length = 0;

	struct mac_params *p = NULL;
	unsigned long key_size_range_bitmap = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	p = SMW_UTILS_CALLOC(1, sizeof(*p));
	if (!p) {
		status = SMW_STATUS_ALLOC_FAILURE;
		goto end;
	}

	init_key_params(&p->key);

	while ((cur < end) && (open_square_bracket != *cur)) {
		status = read_params_string(&cur, end, buffer);
		if (status != SMW_STATUS_OK)
			goto end;

		SMW_DBG_PRINTF(INFO, "Parameter: %s\n", buffer);
		length = SMW_UTILS_STRLEN(buffer);

		skip_insignificant_chars(&cur, end);

		if (!SMW_UTILS_STRNCMP(buffer, mac_algo_values, length)) {
			status = read_mac_algo_strings(&cur, end,
						       &p->algo_bitmap);
			if (status != SMW_STATUS_OK)
				goto end;

		} else if (!SMW_UTILS_STRNCMP(buffer, hash_algo_values,
					      length)) {
			status = read_hash_algo_strings(&cur, end,
							&p->hash_bitmap);
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

static void mac_merge_params(void *caps, void *params)
{
	struct mac_params *mac_caps = caps;
	struct mac_params *mac_params = params;

	SMW_DBG_TRACE_FUNCTION_CALL;

	mac_caps->algo_bitmap |= mac_params->algo_bitmap;
	merge_key_params(&mac_caps->key, &mac_params->key);
}

__weak void mac_print_params(void *params)
{
	(void)params;
}

static int mac_check_subsystem_caps(void *args, void *node)
{
	int status = SMW_STATUS_OPERATION_NOT_CONFIGURED;
	struct smw_crypto_mac_args *mac_args = args;
	struct mac_params *mac_params = smw_utils_list_get_data(node);

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (check_id(mac_args->algo_id, mac_params->algo_bitmap) &&
	    check_key(&mac_args->key_descriptor.identifier, &mac_params->key))
		status = SMW_STATUS_OK;

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int mac_check_key_usable(unsigned int *ref,
				enum smw_config_key_type_id key_type_id,
				smw_attr_algo_t permitted_algo)
{
	int status = SMW_STATUS_OK;
	struct mac_params params = { 0 };
	smw_attr_algo_t algo = SMW_ATTR_ALGO_NONE;
	size_t idx = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	status = get_operation_params(OPERATION_ID_MAC, ref, &params);
	if (status != SMW_STATUS_OK)
		goto end;

	algo = SMW_ATTR_GET_ALGO(permitted_algo);

	status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	if (!check_id(key_type_id, params.key.type_bitmap))
		goto end;

	for (; idx < ARRAY_SIZE(mac_algo_attrs); idx++) {
		if ((algo == SMW_ATTR_ALGO_NONE ||
		     algo == mac_algo_attrs[idx]) &&
		    check_id(idx, params.algo_bitmap)) {
			status = SMW_STATUS_OK;
			break;
		}
	}

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

DEFINE_CONFIG_OPERATION_FUNC(mac);

__export enum smw_status_code smw_config_check_mac(smw_subsystem_t subsystem,
						   struct smw_mac_info *info)
{
	int status = SMW_STATUS_INVALID_PARAM;
	enum subsystem_id id = SUBSYSTEM_ID_INVALID;
	enum smw_config_key_type_id key_type_id =
		SMW_CONFIG_KEY_TYPE_ID_INVALID;
	enum smw_config_mac_algo_id mac_id = SMW_CONFIG_MAC_ALGO_ID_INVALID;
	enum smw_config_hash_algo_id hash_id = SMW_CONFIG_HASH_ALGO_ID_INVALID;
	struct mac_params params = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!info || info->key_type_name == SMW_KEY_TYPE_NAME_NONE)
		return status;

	status = smw_config_get_subsystem_id(subsystem, &id);
	if (status != SMW_STATUS_OK)
		return status;

	status = smw_config_get_key_type_id(info->key_type_name, &key_type_id);
	if (status != SMW_STATUS_OK)
		return status;

	status = get_operation_params_lock(OPERATION_ID_MAC, id, &params);
	if (status != SMW_STATUS_OK)
		return status;

	/* Check key type */
	if (!check_id(key_type_id, params.key.type_bitmap))
		return SMW_STATUS_OPERATION_NOT_CONFIGURED;

	/* Check MAC algorithm if set */
	if (info->mac_algo_name != SMW_MAC_ALGO_NAME_NONE) {
		status =
			smw_utils_get_mac_algo_id(info->mac_algo_name, &mac_id);
		if (status != SMW_STATUS_OK)
			return status;

		if (!check_id(mac_id, params.algo_bitmap))
			return SMW_STATUS_OPERATION_NOT_CONFIGURED;
	}

	/* Check hash algorithm if set */
	if (info->hash_algo_name != SMW_HASH_ALGO_NAME_NONE) {
		status = smw_utils_get_hash_algo_id(info->hash_algo_name,
						    &hash_id);
		if (status != SMW_STATUS_OK)
			return status;

		if (!check_id(hash_id, params.algo_bitmap))
			return SMW_STATUS_OPERATION_NOT_CONFIGURED;
	}

	return SMW_STATUS_OK;
}
