// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include "smw_status.h"

#include "debug.h"
#include "mac.h"
#include "utils.h"

#include "common.h"

#include "ele_crypto_mac.h"
#include "ele_crypto_hash.h"

struct mac_algo {
	unsigned int ele_id;
	unsigned int max_length;
};

#define ELE_MAC_LENGTH_SHIFT 16U
#define ELE_MAC_LENGTH_MASK  0x3FU
#define ELE_MAC_MIN_LENGTH   8U
#define ELE_CMAC_MAX_LENGTH  16U
#define ELE_HMAC_HASH_SHIFT  0U
#define ELE_HMAC_HASH_MASK   0xFFU
#define PERMITTED_HMAC	     (PERMITTED_HMAC_SHA256 & ~ELE_HMAC_HASH_MASK)

static unsigned int mac_algo_truncated_length(size_t algo, size_t length,
					      size_t max_length)
{
	size_t trunc_length = length;

	if (trunc_length < ELE_MAC_MIN_LENGTH)
		trunc_length = ELE_MAC_MIN_LENGTH;
	else if (trunc_length > max_length)
		trunc_length = max_length;

	return (SET_CLEAR_MASK(algo, trunc_length << ELE_MAC_LENGTH_SHIFT,
			       ELE_MAC_LENGTH_MASK << ELE_MAC_LENGTH_SHIFT) &
		UINT32_MAX);
}

static int get_cmac_algo(struct mac_algo *alg, struct smw_crypto_mac_args *args)
{
	alg->ele_id = PERMITTED_CMAC;
	alg->max_length = ELE_CMAC_MAX_LENGTH;

	if (args->algo_id == SMW_CONFIG_MAC_ALGO_ID_CMAC_TRUNCATED)
		alg->ele_id =
			mac_algo_truncated_length(PERMITTED_CMAC,
						  smw_mac_get_mac_length(args),
						  ELE_CMAC_MAX_LENGTH);

	return SMW_STATUS_OK;
}

static int get_hmac_algo(struct mac_algo *alg, struct smw_crypto_mac_args *args)
{
	const struct ele_hash_algo *hash_alg = NULL;

	hash_alg = ele_get_hash_algo(args->hash_id);
	if (!hash_alg)
		return SMW_STATUS_INVALID_PARAM;

	alg->ele_id = SET_CLEAR_MASK(PERMITTED_HMAC,
				     hash_alg->ele_algo << ELE_HMAC_HASH_SHIFT,
				     ELE_HMAC_HASH_MASK << ELE_HMAC_HASH_SHIFT);
	alg->max_length = hash_alg->length;

	if (args->algo_id == SMW_CONFIG_MAC_ALGO_ID_HMAC_TRUNCATED)
		alg->ele_id =
			mac_algo_truncated_length(alg->ele_id,
						  smw_mac_get_mac_length(args),
						  alg->max_length);

	return SMW_STATUS_OK;
}

static int get_mac_algo(struct mac_algo *alg, struct smw_crypto_mac_args *args)
{
	int status = SMW_STATUS_INVALID_PARAM;

	switch (args->algo_id) {
	case SMW_CONFIG_MAC_ALGO_ID_CMAC:
	case SMW_CONFIG_MAC_ALGO_ID_CMAC_TRUNCATED:
		status = get_cmac_algo(alg, args);
		break;

	case SMW_CONFIG_MAC_ALGO_ID_HMAC:
	case SMW_CONFIG_MAC_ALGO_ID_HMAC_TRUNCATED:
		status = get_hmac_algo(alg, args);
		break;

	default:
		break;
	}

	return status;
}

static int get_private_key_buffer(ele_mac_t *mac_gen,
				  struct smw_keymgr_descriptor *key_desc)
{
	int status = SMW_STATUS_INVALID_PARAM;

	unsigned int private_buf_len = smw_keymgr_get_private_length(key_desc);
	unsigned char *private_buffer = smw_keymgr_get_private_data(key_desc);
	unsigned int hex_private_len = 0;

	if (!private_buf_len || !private_buffer)
		goto end;

	status = smw_utils_key_set_hex_buffer(key_desc->format_id,
					      private_buffer, private_buf_len,
					      &mac_gen->key, &hex_private_len);
	if (status != SMW_STATUS_OK)
		goto end;

	if (SET_OVERFLOW(hex_private_len, mac_gen->key_size))
		status = SMW_STATUS_INVALID_PARAM;

end:
	return status;
}

static int mac(struct hdl *hdl, void *args)
{
	int status = SMW_STATUS_OK;

	status_t err = STATUS_SUCCESS;
	ele_mac_t mac_gen = { 0 };
	uint16_t out_mac_size = 0;

	struct smw_crypto_mac_args *mac_args = args;
	struct mac_algo alg = { 0 };
	struct smw_keymgr_descriptor *key_desc = &mac_args->key_descriptor;
	struct smw_keymgr_identifier *key_identifier = &key_desc->identifier;

	SMW_DBG_TRACE_FUNCTION_CALL;

	status = get_mac_algo(&alg, mac_args);
	if (status != SMW_STATUS_OK)
		goto end;

	if (key_identifier->s_id) {
		mac_gen.key_id = key_identifier->s_id;
	} else {
		/* MAC using plaintext key buffer */
		mac_gen.mode = MAC_USE_PLAIN_KEY_BUFFER;
		status = ele_get_key_type(key_identifier->type_id,
					  &mac_gen.key_type);
		if (status != SMW_STATUS_OK)
			goto end;

		status = get_private_key_buffer(&mac_gen, key_desc);
		if (status != SMW_STATUS_OK)
			goto end;
	}

	mac_gen.payload = smw_mac_get_input_data(mac_args);
	mac_gen.payload_size = smw_mac_get_input_length(mac_args);
	mac_gen.mac = smw_mac_get_mac_data(mac_args);

	if (SET_OVERFLOW(smw_mac_get_mac_length(mac_args), mac_gen.mac_size)) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	if (SET_OVERFLOW(alg.ele_id, mac_gen.alg)) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	if (mac_args->op_id == SMW_CONFIG_MAC_OP_ID_COMPUTE) {
		if (!mac_gen.mac) {
			smw_mac_set_mac_length(mac_args, alg.max_length);
			status = SMW_STATUS_OK;
			goto end;
		}

		mac_gen.mode |= MAC_GENERATE;
	} else {
		mac_gen.mode |= MAC_VERIFY;
	}

	status = ele_open_key_store_service(hdl);
	if (status != SMW_STATUS_OK)
		goto end;

	err = ele_open_mac_service(hdl->mu_base, hdl->key_store,
				   &mac_gen.mac_handle_id);
	if (err != STATUS_SUCCESS) {
		status = ele_convert_err(err);
		goto end;
	}

	SMW_DBG_PRINTF(VERBOSE,
		       "[%s (%d)] Call ele_mac()\n"
		       "op_mac_one_go_args_t %s\n"
		       "    key_identifier: 0x%X\n"
		       "    algo: 0x%08X\n"
		       "    flags: 0x%X\n"
		       "    Payload\n"
		       "      - buffer: %p\n"
		       "      - size: %d\n"
		       "    Mac\n"
		       "      - buffer: %p\n"
		       "      - size: %d\n",
		       __func__, __LINE__,
		       (mac_args->op_id == SMW_CONFIG_MAC_OP_ID_COMPUTE) ?
			       "COMPUTE" :
			       "VERIFY",
		       mac_gen.key_id, mac_gen.alg, mac_gen.mode,
		       mac_gen.payload, mac_gen.payload_size, mac_gen.mac,
		       mac_gen.mac_size);

	err = ele_mac(hdl->mu_base, &mac_gen, &out_mac_size);
	SMW_DBG_PRINTF(DEBUG, "%s ele_mac returned %d\n", __func__, err);

	ele_close_mac_service(hdl->mu_base, mac_gen.mac_handle_id);

	if (mac_args->op_id == SMW_CONFIG_MAC_OP_ID_COMPUTE)
		smw_mac_set_mac_length(mac_args, out_mac_size);

	status = ele_convert_err(err);

end:
	if (key_desc->format_id == SMW_KEYMGR_FORMAT_ID_BASE64 && mac_gen.key)
		SMW_UTILS_FREE(mac_gen.key);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);

	// coverity[missing_unlock]
	return status;
}

bool ele_mac_handle(struct hdl *hdl, enum operation_id operation_id, void *args,
		    int *status)
{
	switch (operation_id) {
	case OPERATION_ID_MAC:
		*status = mac(hdl, args);
		break;
	default:
		return false;
	}

	// coverity[missing_unlock]
	return true;
}
