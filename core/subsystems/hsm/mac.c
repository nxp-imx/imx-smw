// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include "smw_status.h"

#include "debug.h"
#include "mac.h"
#include "utils.h"

#include "common.h"

#define HMAC_ALGO(_id, _hsm_id, _size)                                         \
	{                                                                      \
		.hash_id = SMW_CONFIG_HASH_ALGO_ID_##_id,                      \
		.hsm_algo = HSM_OP_MAC_ONE_GO_ALGO_HMAC_##_hsm_id,             \
		.mac_size = _size                                              \
	}

static const struct hmac_algo {
	enum smw_config_hash_algo_id hash_id;
	hsm_op_mac_one_go_algo_t hsm_algo;
	unsigned int mac_size;
} hmac_algos[] = { HMAC_ALGO(SHA224, SHA_224, 28),
		   HMAC_ALGO(SHA256, SHA_256, 32),
		   HMAC_ALGO(SHA384, SHA_384, 48),
		   HMAC_ALGO(SHA512, SHA_512, 64) };

struct mac_algo {
	hsm_op_mac_one_go_algo_t hsm_id;
	unsigned int mac_size;
};

static int get_mac_algo(struct mac_algo *alg, struct smw_crypto_mac_args *args)
{
	int status = SMW_STATUS_INVALID_PARAM;

	SMW_DBG_TRACE_FUNCTION_CALL;

	switch (args->algo_id) {
	case SMW_CONFIG_MAC_ALGO_ID_CMAC:
		alg->hsm_id = HSM_OP_MAC_ONE_GO_ALGO_AES_CMAC;
		alg->mac_size = 16;
		status = SMW_STATUS_OK;
		break;

	case SMW_CONFIG_MAC_ALGO_ID_HMAC:
		for (size_t i = 0; i < ARRAY_SIZE(hmac_algos); i++) {
			if (hmac_algos[i].hash_id == args->hash_id) {
				alg->hsm_id = hmac_algos[i].hsm_algo;
				alg->mac_size = hmac_algos[i].mac_size;
				status = SMW_STATUS_OK;
				break;
			}
		}
		break;

	default:
		break;
	}

	return status;
}

static hsm_err_t open_mac_service(struct hdl *hdl, hsm_hdl_t *mac_hdl)
{
	hsm_err_t err = HSM_NO_ERROR;
	open_svc_mac_args_t svc_args = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	err = hsm_open_mac_service(hdl->key_store, &svc_args, mac_hdl);
	if (err != HSM_NO_ERROR) {
		SMW_DBG_PRINTF(DEBUG, "%s - err: %d\n", __func__, err);
		return err;
	}

	SMW_DBG_PRINTF(DEBUG, "mac_hdl: %u\n", *mac_hdl);

	return err;
}

static hsm_err_t close_mac_service(hsm_hdl_t mac_hdl)
{
	hsm_err_t err = HSM_NO_ERROR;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_PRINTF(DEBUG, "mac_hdl: %u\n", mac_hdl);
	err = hsm_close_mac_service(mac_hdl);
	SMW_DBG_PRINTF(DEBUG, "%s - returned: %d\n", __func__, err);

	return err;
}

static int mac(struct hdl *hdl, void *args)
{
	int status = SMW_STATUS_INVALID_PARAM;

	hsm_err_t err = HSM_NO_ERROR;
	hsm_hdl_t mac_hdl = 0;
	hsm_mac_verification_status_t verif_status = 0;
	op_mac_one_go_args_t op_args = { 0 };

	struct smw_crypto_mac_args *mac_args = args;
	struct mac_algo alg = { 0 };
	struct smw_keymgr_descriptor *key_descriptor = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!mac_args)
		goto end;

	status = get_mac_algo(&alg, mac_args);
	if (status != SMW_STATUS_OK)
		goto end;

	key_descriptor = &mac_args->key_descriptor;

	if (key_descriptor->format_id != SMW_KEYMGR_FORMAT_ID_INVALID) {
		//TODO: first import key, then generate mac
		//      for now import is not supported by HSM
		status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
		goto end;
	}

	op_args.key_identifier = key_descriptor->identifier.id;
	op_args.algorithm = alg.hsm_id;
	op_args.payload = smw_mac_get_input_data(mac_args);
	op_args.mac = smw_mac_get_mac_data(mac_args);

	if (SET_OVERFLOW(smw_mac_get_input_length(mac_args),
			 op_args.payload_size)) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	if (SET_OVERFLOW(smw_mac_get_mac_length(mac_args), op_args.mac_size)) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	if (mac_args->op_id == SMW_CONFIG_MAC_OP_ID_COMPUTE) {
		if (!op_args.mac) {
			smw_mac_set_mac_length(mac_args, alg.mac_size);
			status = SMW_STATUS_OK;
			goto end;
		}

		if (op_args.mac_size < alg.mac_size) {
			smw_mac_set_mac_length(mac_args, alg.mac_size);
			status = SMW_STATUS_OUTPUT_TOO_SHORT;
			goto end;
		}

		op_args.flags = HSM_OP_MAC_ONE_GO_FLAGS_MAC_GENERATION;
	} else {
		op_args.flags = HSM_OP_MAC_ONE_GO_FLAGS_MAC_VERIFICATION;
	}

	err = open_mac_service(hdl, &mac_hdl);
	if (err != HSM_NO_ERROR) {
		status = convert_hsm_err(err);
		goto end;
	}

	SMW_DBG_PRINTF(VERBOSE,
		       "[%s (%d)] Call hsm_mac_one_go()\n"
		       "mac_hdl: %u\n"
		       "op_mac_one_go_args_t %s\n"
		       "    key_identifier: 0x%X\n"
		       "    Payload\n"
		       "      - buffer: %p\n"
		       "      - size: %d\n"
		       "    Mac\n"
		       "      - buffer: %p\n"
		       "      - size: %d\n"
		       "    algo: %x\n"
		       "    flags: %x\n",
		       __func__, __LINE__, mac_hdl,
		       (mac_args->op_id == SMW_CONFIG_MAC_OP_ID_COMPUTE) ?
			       "COMPUTE" :
			       "VERIFY",
		       op_args.key_identifier, op_args.payload,
		       op_args.payload_size, op_args.mac, op_args.mac_size,
		       op_args.algorithm, op_args.flags);

	err = hsm_mac_one_go(mac_hdl, &op_args, &verif_status);

	status = convert_hsm_err(err);

	if (status == SMW_STATUS_OK) {
		if (mac_args->op_id == SMW_CONFIG_MAC_OP_ID_COMPUTE) {
			smw_mac_set_mac_length(mac_args, op_args.mac_size);

			SMW_DBG_PRINTF(DEBUG, "MAC (%d):\n", op_args.mac_size);
			SMW_DBG_HEX_DUMP(DEBUG, op_args.mac, op_args.mac_size,
					 4);
		} else {
			if (verif_status != HSM_MAC_VERIFICATION_STATUS_SUCCESS)
				status = SMW_STATUS_SIGNATURE_INVALID;
		}

	} else {
		SMW_DBG_PRINTF(DEBUG, "%s hsm_mac_one_go returned %d\n",
			       __func__, err);
	}

	err = close_mac_service(mac_hdl);

	if (status == SMW_STATUS_OK)
		status = convert_hsm_err(err);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

bool hsm_mac_handle(struct hdl *hdl, enum operation_id operation_id, void *args,
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
