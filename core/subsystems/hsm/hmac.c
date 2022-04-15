// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022 NXP
 */

#include "hsm_api.h"

#include "smw_status.h"

#include "debug.h"
#include "keymgr.h"
#include "hmac.h"
#include "subsystems.h"
#include "utils.h"

#include "common.h"

#define HMAC_ALGO(_id, _hsm_id, _length)                                       \
	{                                                                      \
		.algo_id = SMW_CONFIG_HMAC_ALGO_ID_##_id,                      \
		.hsm_algo = HSM_OP_MAC_ONE_GO_ALGO_HMAC_##_hsm_id,             \
		.length = _length                                              \
	}

/*
 * Algo IDs must be ordered from lowest to highest.
 * This sorting is required to simplify the implementation of
 * get_hmac_algo_info().
 */
static struct hmac_algo_info {
	enum smw_config_hmac_algo_id algo_id;
	hsm_op_mac_one_go_algo_t hsm_algo;
	uint32_t length;
} hmac_algo_info[] = { HMAC_ALGO(SHA224, SHA_224, 28),
		       HMAC_ALGO(SHA256, SHA_256, 32),
		       HMAC_ALGO(SHA384, SHA_384, 48),
		       HMAC_ALGO(SHA512, SHA_512, 64) };

static struct hmac_algo_info *
get_hmac_algo_info(enum smw_config_hmac_algo_id algo_id)
{
	struct hmac_algo_info *info = NULL;

	unsigned int i;
	unsigned int size = ARRAY_SIZE(hmac_algo_info);

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (i = 0; i < size; i++) {
		if (hmac_algo_info[i].algo_id < algo_id)
			continue;
		if (hmac_algo_info[i].algo_id > algo_id)
			break;
		info = &hmac_algo_info[i];
		break;
	}

	return info;
}

static hsm_err_t open_hmac_service(struct hdl *hdl, hsm_hdl_t *mac_hdl)
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

static hsm_err_t close_hmac_service(hsm_hdl_t mac_hdl)
{
	hsm_err_t err;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_PRINTF(DEBUG, "mac_hdl: %u\n", mac_hdl);
	err = hsm_close_mac_service(mac_hdl);
	SMW_DBG_PRINTF(DEBUG, "%s - returned: %d\n", __func__, err);

	return err;
}

static int hmac(struct hdl *hdl, void *args)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	hsm_err_t err = HSM_NO_ERROR;
	hsm_hdl_t mac_hdl = 0;
	hsm_mac_verification_status_t verif_status = 0;
	op_mac_one_go_args_t op_hsm_args = { 0 };

	struct smw_crypto_hmac_args *hmac_args = args;
	struct hmac_algo_info *hmac_algo_info;
	struct smw_keymgr_descriptor *key_descriptor;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_ASSERT(hmac_args);

	hmac_algo_info = get_hmac_algo_info(hmac_args->algo_id);
	if (!hmac_algo_info)
		goto end;

	key_descriptor = &hmac_args->key_descriptor;

	if (key_descriptor->format_id != SMW_KEYMGR_FORMAT_ID_INVALID)
		//TODO: first import key, then generate mac
		//      for now import is not supported by HSM
		goto end;

	op_hsm_args.key_identifier = key_descriptor->identifier.id;
	op_hsm_args.algorithm = hmac_algo_info->hsm_algo;
	op_hsm_args.flags = HSM_OP_MAC_ONE_GO_FLAGS_MAC_GENERATION;
	op_hsm_args.payload = smw_hmac_get_input_data(hmac_args);
	op_hsm_args.payload_size = smw_hmac_get_input_length(hmac_args);
	op_hsm_args.mac = smw_hmac_get_output_data(hmac_args);

	if (!op_hsm_args.mac) {
		smw_hmac_set_output_length(hmac_args, hmac_algo_info->length);
		status = SMW_STATUS_OK;
		goto end;
	}

	if (smw_hmac_get_output_length(hmac_args) < hmac_algo_info->length) {
		smw_hmac_set_output_length(hmac_args, hmac_algo_info->length);
		status = SMW_STATUS_OUTPUT_TOO_SHORT;
		goto end;
	}

	op_hsm_args.mac_size = hmac_algo_info->length;

	err = open_hmac_service(hdl, &mac_hdl);
	if (err != HSM_NO_ERROR) {
		status = convert_hsm_err(err);
		goto end;
	}

	SMW_DBG_PRINTF(VERBOSE,
		       "[%s (%d)] Call hsm_hmac_one_go()\n"
		       "hmac_hdl: %u\n"
		       "op_hmac_one_go_args_t\n"
		       "    key_identifier: 0x%X\n"
		       "    payload: %p\n"
		       "    payload_size: %d\n"
		       "    mac: %p\n"
		       "    mac_size: %d\n"
		       "    algo: %x\n"
		       "    flags: %x\n",
		       __func__, __LINE__, mac_hdl, op_hsm_args.key_identifier,
		       op_hsm_args.payload, op_hsm_args.payload_size,
		       op_hsm_args.mac, op_hsm_args.mac_size,
		       op_hsm_args.algorithm, op_hsm_args.flags);

	err = hsm_mac_one_go(mac_hdl, &op_hsm_args, &verif_status);
	if (err == HSM_NO_ERROR) {
		smw_hmac_set_output_length(hmac_args, op_hsm_args.mac_size);

		SMW_DBG_PRINTF(DEBUG, "MAC (%d):\n", op_hsm_args.mac_size);
		SMW_DBG_HEX_DUMP(DEBUG, op_hsm_args.mac, op_hsm_args.mac_size,
				 4);
	} else {
		SMW_DBG_PRINTF(DEBUG, "%s hsm_mac_one_go returned %d\n",
			       __func__, err);
	}

	status = convert_hsm_err(err);

	err = close_hmac_service(mac_hdl);

	if (status == SMW_STATUS_OK)
		status = convert_hsm_err(err);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

bool hsm_hmac_handle(struct hdl *hdl, enum operation_id operation_id,
		     void *args, int *status)
{
	switch (operation_id) {
	case OPERATION_ID_HMAC:
		*status = hmac(hdl, args);
		break;
	default:
		return false;
	}

	return true;
}
