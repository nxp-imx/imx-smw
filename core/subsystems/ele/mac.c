// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include "smw_status.h"

#include "debug.h"
#include "mac.h"
#include "utils.h"

#include "common.h"

struct mac_algo {
	hsm_op_mac_one_go_algo_t ele_id;
	int max_length;
};

#define ELE_MAC_LENGTH_SHIFT 16
#define ELE_MAC_LENGTH_MASK  0x3F
#define ELE_MAC_MIN_LENGTH   8
#define ELE_CMAC_MAX_LENGTH  16
#define ELE_HMAC_HASH_SHIFT  0
#define ELE_HMAC_HASH_MASK   0xFF
#define PERMITTED_ALGO_HMAC  (PERMITTED_ALGO_HMAC_SHA256 & ~ELE_HMAC_HASH_MASK)

static unsigned int mac_algo_truncated_length(hsm_op_mac_one_go_algo_t algo,
					      int length, int max_length)
{
	int trunc_length = length;

	if (trunc_length < ELE_MAC_MIN_LENGTH)
		trunc_length = ELE_MAC_MIN_LENGTH;
	else if (trunc_length > max_length)
		trunc_length = max_length;

	return SET_CLEAR_MASK(algo, trunc_length << ELE_MAC_LENGTH_SHIFT,
			      ELE_MAC_LENGTH_MASK << ELE_MAC_LENGTH_SHIFT);
}

static int get_cmac_algo(struct mac_algo *alg, struct smw_crypto_mac_args *args)
{
	alg->ele_id = PERMITTED_ALGO_CMAC;
	alg->max_length = ELE_CMAC_MAX_LENGTH;

	if (args->algo_id == SMW_CONFIG_MAC_ALGO_ID_CMAC_TRUNCATED)
		alg->ele_id =
			mac_algo_truncated_length(PERMITTED_ALGO_CMAC,
						  smw_mac_get_mac_length(args),
						  ELE_CMAC_MAX_LENGTH);

	return SMW_STATUS_OK;
}

static int get_hmac_algo(struct mac_algo *alg, struct smw_crypto_mac_args *args)
{
	const struct ele_hash_algo *hash_alg;

	hash_alg = ele_get_hash_algo(args->hash_id);
	if (!hash_alg)
		return SMW_STATUS_INVALID_PARAM;

	alg->ele_id = SET_CLEAR_MASK(PERMITTED_ALGO_HMAC,
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

static int mac(struct hdl *hdl, void *args)
{
	int status = SMW_STATUS_INVALID_PARAM;

	hsm_err_t err = HSM_NO_ERROR;
	op_mac_one_go_args_t op_args = { 0 };

	struct smw_crypto_mac_args *mac_args = args;
	struct mac_algo alg = { 0 };
	struct smw_keymgr_descriptor *key_descriptor;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!mac_args)
		goto end;

	status = get_mac_algo(&alg, mac_args);
	if (status != SMW_STATUS_OK)
		goto end;

	key_descriptor = &mac_args->key_descriptor;

	if (key_descriptor->format_id != SMW_KEYMGR_FORMAT_ID_INVALID) {
		//TODO: first import key, then generate mac
		//      for now import is not supported by ELE
		status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
		goto end;
	}

	op_args.key_identifier = key_descriptor->identifier.id;
	op_args.payload = smw_mac_get_input_data(mac_args);
	op_args.payload_size = smw_mac_get_input_length(mac_args);
	op_args.mac = smw_mac_get_mac_data(mac_args);
	op_args.mac_size = smw_mac_get_mac_length(mac_args);
	op_args.algorithm = alg.ele_id;

	if (mac_args->op_id == SMW_CONFIG_MAC_OP_ID_COMPUTE) {
		if (!op_args.mac) {
			smw_mac_set_mac_length(mac_args, alg.max_length);
			status = SMW_STATUS_OK;
			goto end;
		}

		op_args.flags = HSM_OP_MAC_ONE_GO_FLAGS_MAC_GENERATION;
	} else {
		op_args.flags = HSM_OP_MAC_ONE_GO_FLAGS_MAC_VERIFICATION;
	}

	SMW_DBG_PRINTF(VERBOSE,
		       "[%s (%d)] Call hsm_mac_one_go()\n"
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
		       op_args.key_identifier, op_args.algorithm, op_args.flags,
		       op_args.payload, op_args.payload_size, op_args.mac,
		       op_args.mac_size);

	err = hsm_do_mac(hdl->key_store, &op_args);
	SMW_DBG_PRINTF(DEBUG, "%s hsm_mac_one_go returned %d\n", __func__, err);

	status = ele_convert_err(err);

	if (mac_args->op_id == SMW_CONFIG_MAC_OP_ID_COMPUTE)
		smw_mac_set_mac_length(mac_args, op_args.exp_mac_size);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
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

	return true;
}
