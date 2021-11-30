// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021 NXP
 */

#include "hsm_api.h"

#include "smw_status.h"
#include "smw_crypto.h"

#include "global.h"
#include "debug.h"
#include "operations.h"
#include "subsystems.h"
#include "config.h"
#include "keymgr.h"
#include "sign_verify.h"

#include "common.h"
#include "sign_verify_tls12.h"

static hsm_op_tls_finish_flags_t
get_hsm_finish_flag(enum smw_config_tls_finish_label_id label)
{
	switch (label) {
	case SMW_CONFIG_TLS_FINISH_ID_CLIENT:
		return HSM_OP_TLS_FINISH_FLAGS_CLIENT;

	case SMW_CONFIG_TLS_FINISH_ID_SERVER:
		return HSM_OP_TLS_FINISH_FLAGS_SERVER;

	default:
		return 0;
	}
}

static int get_hsm_finish_algo_id(hsm_op_tls_finish_algo_id_t *id,
				  enum smw_config_hash_algo_id hash_id)
{
	switch (hash_id) {
	case SMW_CONFIG_HASH_ALGO_ID_SHA256:
		*id = HSM_OP_TLS_FINISH_HASH_ALGO_SHA256;
		break;

	case SMW_CONFIG_HASH_ALGO_ID_SHA384:
		*id = HSM_OP_TLS_FINISH_HASH_ALGO_SHA384;
		break;

	default:
		return SMW_STATUS_OPERATION_NOT_SUPPORTED;
	}

	return SMW_STATUS_OK;
}

int tls_mac_finish(struct hdl *hdl, void *args)
{
	int status = SMW_STATUS_OK;

	hsm_err_t hsm_err = HSM_NO_ERROR;

	op_tls_finish_args_t op_tls_args = { 0 };

	struct smw_crypto_sign_verify_args *smw_args = args;
	struct smw_keymgr_descriptor *key_descriptor =
		&smw_args->key_descriptor;
	struct smw_keymgr_identifier *key_identifier =
		&key_descriptor->identifier;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_ASSERT(smw_args);

	status = get_hsm_finish_algo_id(&op_tls_args.hash_algorithm,
					smw_args->algo_id);
	if (status != SMW_STATUS_OK)
		return status;

	if (smw_sign_verify_get_sign_len(smw_args) <
	    TLS12_MAC_FINISH_DEFAULT_LEN)
		return SMW_STATUS_OUTPUT_TOO_SHORT;

	op_tls_args.verify_data_output_size = TLS12_MAC_FINISH_DEFAULT_LEN;

	op_tls_args.key_identifier = key_identifier->id;
	op_tls_args.handshake_hash_input =
		smw_sign_verify_get_msg_buf(smw_args);
	op_tls_args.handshake_hash_input_size =
		smw_sign_verify_get_msg_len(smw_args);
	op_tls_args.verify_data_output = smw_sign_verify_get_sign_buf(smw_args);
	op_tls_args.flags = get_hsm_finish_flag(smw_args->attributes.tls_label);

	SMW_DBG_PRINTF(VERBOSE,
		       "[%s (%d)] Call hsm_tls_finish()\n"
		       "key_management_hdl: %d\n"
		       "op_tls_finish_args_t\n"
		       "    key_identifier: %d\n"
		       "    handshake_hash_input: %p\n"
		       "    verify_data_output: %p\n"
		       "    handshake_hash_input_size: %d\n"
		       "    verify_data_output_size: %d\n"
		       "    flags: 0x%x\n"
		       "    hash_algorithm: 0x%x\n",
		       __func__, __LINE__, hdl->key_management,
		       op_tls_args.key_identifier,
		       op_tls_args.handshake_hash_input,
		       op_tls_args.verify_data_output,
		       op_tls_args.handshake_hash_input_size,
		       op_tls_args.verify_data_output_size, op_tls_args.flags,
		       op_tls_args.hash_algorithm);

	hsm_err = hsm_tls_finish(hdl->key_management, &op_tls_args);

	SMW_DBG_PRINTF(DEBUG, "hsm_tls_finish returned %d\n", hsm_err);
	status = convert_hsm_err(hsm_err);

	smw_sign_verify_set_sign_len(smw_args,
				     op_tls_args.verify_data_output_size);

	SMW_DBG_PRINTF(DEBUG, "Output (%d):\n",
		       op_tls_args.verify_data_output_size);
	SMW_DBG_HEX_DUMP(DEBUG, op_tls_args.verify_data_output,
			 op_tls_args.verify_data_output_size, 4);

	return status;
}
