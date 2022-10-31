// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2022 NXP
 */

#include "smw_status.h"
#include "smw_crypto.h"

#include "global.h"
#include "debug.h"
#include "utils.h"
#include "operations.h"
#include "subsystems.h"
#include "config.h"
#include "keymgr.h"
#include "sign_verify.h"

#include "common.h"
#include "sign_verify_tls12.h"

#define TLS_FINISH_FLAG(_label)                                                \
	{                                                                      \
		.tls_finish_label_id = SMW_CONFIG_TLS_FINISH_ID_##_label,      \
		.hsm_tls_finish_flag = HSM_OP_TLS_FINISH_FLAGS_##_label        \
	}

static const struct {
	enum smw_config_tls_finish_label_id tls_finish_label_id;
	hsm_op_tls_finish_flags_t hsm_tls_finish_flag;
} tls_finish_flags[] = { TLS_FINISH_FLAG(CLIENT), TLS_FINISH_FLAG(SERVER) };

static void
set_hsm_tls_finish_flag(enum smw_config_tls_finish_label_id tls_finish_label_id,
			hsm_op_tls_finish_flags_t *hsm_tls_finish_flag)
{
	unsigned int i;

	*hsm_tls_finish_flag = 0;

	for (i = 0; i < ARRAY_SIZE(tls_finish_flags); i++) {
		if (tls_finish_label_id ==
		    tls_finish_flags[i].tls_finish_label_id) {
			*hsm_tls_finish_flag =
				tls_finish_flags[i].hsm_tls_finish_flag;
			break;
		}
	}
}

#define TLS_FINISH_ALGO(_algo_id)                                              \
	{                                                                      \
		.hash_algo_id = SMW_CONFIG_HASH_ALGO_ID_##_algo_id,            \
		.hsm_tls_finish_algo_id =                                      \
			HSM_OP_TLS_FINISH_HASH_ALGO_##_algo_id                 \
	}

static const struct {
	enum smw_config_hash_algo_id hash_algo_id;
	hsm_op_tls_finish_algo_id_t hsm_tls_finish_algo_id;
} tls_finish_algos[] = { TLS_FINISH_ALGO(SHA256), TLS_FINISH_ALGO(SHA384) };

static int
set_hsm_tls_finish_algo_id(enum smw_config_hash_algo_id hash_algo_id,
			   hsm_op_tls_finish_algo_id_t *hsm_tls_finish_algo_id)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(tls_finish_algos); i++) {
		if (hash_algo_id == tls_finish_algos[i].hash_algo_id) {
			*hsm_tls_finish_algo_id =
				tls_finish_algos[i].hsm_tls_finish_algo_id;
			status = SMW_STATUS_OK;
			break;
		}
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
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

	status = set_hsm_tls_finish_algo_id(smw_args->algo_id,
					    &op_tls_args.hash_algorithm);
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
	set_hsm_tls_finish_flag(smw_args->attributes.tls_label,
				&op_tls_args.flags);

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
