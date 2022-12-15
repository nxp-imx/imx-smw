// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2023 NXP
 */

#include <util.h>
#include <string.h>

#include "common.h"
#include "tee_subsystem.h"
#include "keymgr.h"
#include "mac.h"

#define ALGO_HMAC_ID(_algorithm_id)                                            \
	{                                                                      \
		.ca_id = TEE_ALGORITHM_ID_##_algorithm_id,                     \
		.ta_id = TEE_ALG_HMAC_##_algorithm_id                          \
	}

#define ALGO_CMAC_ID(_algorithm_id)                                            \
	{                                                                      \
		.ca_id = TEE_ALGORITHM_ID_##_algorithm_id,                     \
		.ta_id = TEE_ALG_AES_##_algorithm_id                           \
	}

/* Algorithm IDs must be ordered from lowest to highest. */
static const struct algo_info {
	enum tee_algorithm_id ca_id;
	uint32_t ta_id;
} alg_infos[] = { ALGO_HMAC_ID(MD5),	ALGO_HMAC_ID(SHA1),
		  ALGO_HMAC_ID(SHA224), ALGO_HMAC_ID(SHA256),
		  ALGO_HMAC_ID(SHA384), ALGO_HMAC_ID(SHA512),
		  ALGO_HMAC_ID(SM3),	ALGO_CMAC_ID(CMAC) };

static const struct algo_info *get_algo_info(enum tee_algorithm_id ca_id)
{
	const struct algo_info *alg = NULL;
	unsigned int i;
	unsigned int size = ARRAY_SIZE(alg_infos);

	FMSG("Executing %s", __func__);

	for (i = 0; i < size; i++) {
		if (alg_infos[i].ca_id == ca_id) {
			alg = &alg_infos[i];
			break;
		}
	}

	return alg;
}

static TEE_Result mac_operate(uint32_t param_types,
			      TEE_Param params[TEE_NUM_PARAMS], bool verify)
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	TEE_OperationHandle operation = TEE_HANDLE_NULL;
	TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
	TEE_ObjectInfo key_info = { 0 };
	uint32_t key_param_type = TEE_PARAM_TYPE_GET(param_types, 0);
	struct mac_shared_params *shared_params = NULL;
	unsigned char *priv_key = NULL;
	unsigned int priv_key_len = 0;
	void *message;
	uint32_t message_len;
	void *mac;
	uint32_t mac_len;
	const struct algo_info *alg = NULL;

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
	    (TEE_PARAM_TYPE_GET(param_types, 2) != TEE_PARAM_TYPE_MEMREF_INPUT))
		return res;

	shared_params = params[1].memref.buffer;

	switch (key_param_type) {
	case TEE_PARAM_TYPE_MEMREF_INPUT:
		priv_key = params[0].memref.buffer;
		priv_key_len = params[0].memref.size;
		res = ta_import_key(&key_handle, shared_params->tee_key_type,
				    shared_params->security_size, TEE_USAGE_MAC,
				    priv_key, priv_key_len, NULL, 0, NULL, 0);
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
	alg = get_algo_info(shared_params->tee_algorithm_id);
	FMSG("%s get_algo_info %p", __func__, alg);
	if (!alg) {
		EMSG("Failed to get algorithm info: 0x%x", res);
		goto exit;
	}

	message = params[2].memref.buffer;
	message_len = params[2].memref.size;
	mac = params[3].memref.buffer;
	mac_len = params[3].memref.size;

	res = TEE_AllocateOperation(&operation, alg->ta_id, TEE_MODE_MAC,
				    shared_params->security_size);
	if (res) {
		EMSG("Failed to alloc operation: 0x%x", res);
		goto exit;
	}

	res = TEE_GetObjectInfo1(key_handle, &key_info);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to get key info (0x%x)", res);
		goto exit;
	}

	res = check_operation_keys_usage(operation, &key_info, 1);
	if (res)
		goto exit;

	res = TEE_SetOperationKey(operation, key_handle);
	if (res) {
		EMSG("Failed to set operation key: 0x%x", res);
		goto exit;
	}

	TEE_MACInit(operation, NULL, 0);

	if (verify)
		res = TEE_MACCompareFinal(operation, message, message_len, mac,
					  mac_len);
	else
		res = TEE_MACComputeFinal(operation, message, message_len, mac,
					  &mac_len);
	/* Update the MAC length */
	if (!verify && (res == TEE_ERROR_SHORT_BUFFER || res == TEE_SUCCESS)) {
		params[3].memref.size = mac_len;

		/* User requested the size of the MAC */
		if (res == TEE_ERROR_SHORT_BUFFER && !mac)
			res = TEE_SUCCESS;
	}

	if (res) {
		EMSG("Failed to compute MAC: 0x%x", res);
		goto exit;
	}

exit:
	if (key_handle != TEE_HANDLE_NULL) {
		if (persistent)
			TEE_CloseObject(key_handle);
		else if (key_param_type == TEE_PARAM_TYPE_MEMREF_INPUT)
			TEE_FreeTransientObject(key_handle);
	}

	if (operation != TEE_HANDLE_NULL)
		TEE_FreeOperation(operation);

	return res;
}

TEE_Result mac_compute(uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;

	/*
	 * Verify the mac buffer parameter type is output in case of
	 * MAC computation
	 */
	if (TEE_PARAM_TYPE_GET(param_types, 3) == TEE_PARAM_TYPE_MEMREF_OUTPUT)
		res = mac_operate(param_types, params, false);

	return res;
}

TEE_Result mac_verify(uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;

	/*
	 * Verify the mac buffer parameter type is input in case of
	 * MAC verification
	 */
	if (TEE_PARAM_TYPE_GET(param_types, 3) == TEE_PARAM_TYPE_MEMREF_INPUT)
		res = mac_operate(param_types, params, true);

	return res;
}
