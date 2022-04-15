// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022 NXP
 */

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
		.hsm_algo = PERMITTED_ALGO_HMAC_##_hsm_id, .length = _length   \
	}

static struct hmac_algo {
	enum smw_config_hmac_algo_id algo_id;
	hsm_op_mac_one_go_algo_t hsm_algo;
	uint32_t length;
} hmac_algos[] = {
	HMAC_ALGO(SHA256, SHA256, 32),
	HMAC_ALGO(SHA384, SHA384, 48),
};

static struct hmac_algo *get_hmac_algo(enum smw_config_hmac_algo_id algo_id)
{
	struct hmac_algo *info = NULL;
	unsigned int i;

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (i = 0; i < ARRAY_SIZE(hmac_algos); i++) {
		if (hmac_algos[i].algo_id == algo_id) {
			info = &hmac_algos[i];
			break;
		}
	}

	return info;
}

static int hmac(struct hdl *hdl, void *args)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	hsm_err_t err = HSM_NO_ERROR;
	op_mac_one_go_args_t op_args = { 0 };

	struct smw_crypto_hmac_args *hmac_args = args;
	struct hmac_algo *hmac_algo;
	struct smw_keymgr_descriptor *key_descriptor;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_ASSERT(hmac_args);

	hmac_algo = get_hmac_algo(hmac_args->algo_id);
	if (!hmac_algo)
		goto end;

	key_descriptor = &hmac_args->key_descriptor;

	if (key_descriptor->format_id != SMW_KEYMGR_FORMAT_ID_INVALID)
		//TODO: first import key, then generate mac
		//      for now import is not supported by ELE
		goto end;

	op_args.key_identifier = key_descriptor->identifier.id;
	op_args.algorithm = hmac_algo->hsm_algo;
	op_args.flags = HSM_OP_MAC_ONE_GO_FLAGS_MAC_GENERATION;
	op_args.payload = smw_hmac_get_input_data(hmac_args);
	op_args.payload_size = smw_hmac_get_input_length(hmac_args);
	op_args.mac = smw_hmac_get_output_data(hmac_args);

	if (!op_args.mac) {
		smw_hmac_set_output_length(hmac_args, hmac_algo->length);
		status = SMW_STATUS_OK;
		goto end;
	}

	op_args.mac_size = smw_hmac_get_output_length(hmac_args);

	SMW_DBG_PRINTF(VERBOSE,
		       "[%s (%d)] Call hsm_hmac_one_go()\n"
		       "op_hmac_one_go_args_t\n"
		       "    key_identifier: 0x%X\n"
		       "    algo: 0x%08X\n"
		       "    flags: 0x%X\n"
		       "    Payload\n"
		       "      - buffer: %p\n"
		       "      - size: %d\n"
		       "    Mac\n"
		       "      - buffer: %p\n"
		       "      - size: %d\n",
		       __func__, __LINE__, op_args.key_identifier,
		       op_args.algorithm, op_args.flags, op_args.payload,
		       op_args.payload_size, op_args.mac, op_args.mac_size);

	err = hsm_do_mac(hdl->key_store, &op_args);
	SMW_DBG_PRINTF(DEBUG, "%s hsm_mac_one_go returned %d\n", __func__, err);

	status = ele_convert_err(err);

	smw_hmac_set_output_length(hmac_args, op_args.mac_size);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

bool ele_hmac_handle(struct hdl *hdl, enum operation_id operation_id,
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
