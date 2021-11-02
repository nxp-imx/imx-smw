// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2022 NXP
 */

#include <util.h>
#include <string.h>
#include <tee_internal_api.h>

#include "tee_subsystem.h"
#include "keymgr.h"
#include "hmac.h"

#define ALGORITHM_ID(_algorithm_id)                                            \
	{                                                                      \
		.ca_id = TEE_ALGORITHM_ID_##_algorithm_id,                     \
		.ta_id = TEE_ALG_HMAC_##_algorithm_id                          \
	}

/* Algorithm IDs must be ordered from lowest to highest. */
struct {
	enum tee_algorithm_id ca_id;
	uint32_t ta_id;
} algorithm_ids[] = { ALGORITHM_ID(MD5),    ALGORITHM_ID(SHA1),
		      ALGORITHM_ID(SHA224), ALGORITHM_ID(SHA256),
		      ALGORITHM_ID(SHA384), ALGORITHM_ID(SHA512),
		      ALGORITHM_ID(SM3) };

static TEE_Result get_algorithm_id(enum tee_algorithm_id ca_id, uint32_t *ta_id)
{
	unsigned int i;
	unsigned int size = ARRAY_SIZE(algorithm_ids);

	FMSG("Executing %s", __func__);

	if (!ta_id)
		return TEE_ERROR_BAD_PARAMETERS;

	for (i = 0; i < size; i++) {
		if (algorithm_ids[i].ca_id < ca_id)
			continue;
		if (algorithm_ids[i].ca_id > ca_id)
			return TEE_ERROR_NOT_SUPPORTED;

		*ta_id = algorithm_ids[i].ta_id;
		break;
	}

	return TEE_SUCCESS;
}

TEE_Result hmac(uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	TEE_OperationHandle operation = TEE_HANDLE_NULL;
	TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
	uint32_t param0_type = TEE_PARAM_TYPE_GET(param_types, 0);
	struct hmac_shared_params *shared_params = NULL;
	unsigned char *priv_key = NULL;
	unsigned int priv_key_len = 0;
	uint32_t hmac_algo_id = 0;
	void *message;
	uint32_t message_len;
	void *mac;
	uint32_t mac_len;

	bool persistent = false;

	FMSG("Executing %s", __func__);

	/*
	 * params[0] = Key ID or Key buffer
	 * params[1] = Key type ID / HMAC algorithm ID and Security size
	 * params[2] = Message buffer and message length
	 * params[3] = MAC buffer and MAC length
	 */
	if ((TEE_PARAM_TYPE_GET(param_types, 1) !=
	     TEE_PARAM_TYPE_MEMREF_INPUT) ||
	    params[1].memref.size != sizeof(*shared_params) ||
	    !params[1].memref.buffer ||
	    (TEE_PARAM_TYPE_GET(param_types, 2) !=
	     TEE_PARAM_TYPE_MEMREF_INPUT) ||
	    (TEE_PARAM_TYPE_GET(param_types, 3) !=
	     TEE_PARAM_TYPE_MEMREF_OUTPUT))
		return res;

	shared_params = params[1].memref.buffer;

	switch (param0_type) {
	case TEE_PARAM_TYPE_MEMREF_INPUT:
		priv_key = params[0].memref.buffer;
		priv_key_len = params[0].memref.size;
		res = ta_import_key(&key_handle, shared_params->tee_key_type,
				    shared_params->security_size, priv_key,
				    priv_key_len, NULL, 0, NULL, 0);
		if (res) {
			EMSG("Failed to import key: 0x%x", res);
			goto exit;
		}

		break;

	case TEE_PARAM_TYPE_VALUE_INPUT:
		res = ta_get_key_handle(&key_handle, params[0].value.a,
					&persistent);
		if (res) {
			EMSG("Key not found: 0x%x", res);
			goto exit;
		}
		break;

	default:
		return res;
	}

	/* Get TEE algorithm ID */
	res = get_algorithm_id(shared_params->tee_algorithm_id, &hmac_algo_id);
	if (res) {
		EMSG("Failed to get algorithm ID: 0x%x", res);
		goto exit;
	}

	message = params[2].memref.buffer;
	message_len = params[2].memref.size;
	mac = params[3].memref.buffer;
	mac_len = params[3].memref.size;

	res = TEE_AllocateOperation(&operation, hmac_algo_id, TEE_MODE_MAC,
				    shared_params->security_size);
	if (res) {
		EMSG("Failed to alloc operation: 0x%x", res);
		goto exit;
	}

	res = TEE_SetOperationKey(operation, key_handle);
	if (res) {
		EMSG("Failed to set operation key: 0x%x", res);
		goto exit;
	}

	TEE_MACInit(operation, NULL, 0);

	res = TEE_MACComputeFinal(operation, message, message_len, mac,
				  &mac_len);
	if (res) {
		EMSG("Failed to compute MAC: 0x%x", res);
		goto exit;
	}

	/* Update the MAC length */
	params[3].memref.size = mac_len;

exit:
	if (key_handle != TEE_HANDLE_NULL) {
		if (persistent)
			TEE_CloseObject(key_handle);
		else if (param0_type == TEE_PARAM_TYPE_MEMREF_INPUT)
			TEE_FreeTransientObject(key_handle);
	}

	if (operation != TEE_HANDLE_NULL)
		TEE_FreeOperation(operation);

	return res;
}
