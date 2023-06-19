// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include "smw_crypto.h"

#include "compiler.h"
#include "debug.h"
#include "mac.h"
#include "name.h"
#include "tag.h"
#include "utils.h"

#include "common.h"

static const char *const mac_algo_names[] = {
	[SMW_CONFIG_MAC_ALGO_ID_CMAC] = "CMAC",
	[SMW_CONFIG_MAC_ALGO_ID_CMAC_TRUNCATED] = "CMAC_TRUNCATED",
	[SMW_CONFIG_MAC_ALGO_ID_HMAC] = "HMAC",
	[SMW_CONFIG_MAC_ALGO_ID_HMAC_TRUNCATED] = "HMAC_TRUNCATED",
};

static int read_mac_algo_names(char **start, char *end, unsigned long *bitmap)
{
	return read_names(start, end, bitmap, mac_algo_names,
			  SMW_CONFIG_MAC_ALGO_ID_NB);
}

static int mac_read_params(char **start, char *end, void **params)
{
	int status = SMW_STATUS_OK;
	char *cur = *start;

	char buffer[SMW_CONFIG_MAX_PARAMS_NAME_LENGTH + 1] = { 0 };
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
		status = read_params_name(&cur, end, buffer);
		if (status != SMW_STATUS_OK)
			goto end;
		SMW_DBG_PRINTF(INFO, "Parameter: %s\n", buffer);
		length = SMW_UTILS_STRLEN(buffer);

		skip_insignificant_chars(&cur, end);

		if (!SMW_UTILS_STRNCMP(buffer, mac_algo_values, length)) {
			status =
				read_mac_algo_names(&cur, end, &p->algo_bitmap);
			if (status != SMW_STATUS_OK)
				goto end;

		} else if (!SMW_UTILS_STRNCMP(buffer, hash_algo_values,
					      length)) {
			status = read_hash_algo_names(&cur, end,
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

static int mac_check_subsystem_caps(void *args, void *params)
{
	int status = SMW_STATUS_OPERATION_NOT_CONFIGURED;
	struct smw_crypto_mac_args *mac_args = args;
	struct mac_params *mac_params = params;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (check_id(mac_args->algo_id, mac_params->algo_bitmap) &&
	    check_key(&mac_args->key_descriptor.identifier, &mac_params->key))
		status = SMW_STATUS_OK;

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

DEFINE_CONFIG_OPERATION_FUNC(mac);

int smw_config_get_mac_algo_id(const char *name,
			       enum smw_config_mac_algo_id *id)
{
	int status = SMW_STATUS_OK;

	SMW_DBG_TRACE_FUNCTION_CALL;
	if (!name)
		*id = SMW_CONFIG_MAC_ALGO_ID_INVALID;
	else
		status = smw_utils_get_string_index(name, mac_algo_names,
						    SMW_CONFIG_MAC_ALGO_ID_NB,
						    id);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}
