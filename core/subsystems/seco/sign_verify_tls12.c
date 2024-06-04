// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2024 NXP
 */

#include <internal/hsm_tls_finish.h>

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
		.tls_finish_label_id = SMW_CONFIG_SIGN_TYPE_ID_##_label,       \
		.tls_finish_flag = HSM_OP_TLS_FINISH_FLAGS_##_label            \
	}

static const struct {
	enum smw_config_sign_type_id tls_finish_label_id;
	hsm_op_tls_finish_flags_t tls_finish_flag;
} tls_finish_flags[] = { TLS_FINISH_FLAG(CLIENT), TLS_FINISH_FLAG(SERVER) };

static void
set_tls_finish_flag(enum smw_config_sign_type_id tls_finish_label_id,
		    hsm_op_tls_finish_flags_t *tls_finish_flag)
{
	unsigned int i = 0;

	*tls_finish_flag = 0;

	for (; i < ARRAY_SIZE(tls_finish_flags); i++) {
		if (tls_finish_label_id ==
		    tls_finish_flags[i].tls_finish_label_id) {
			*tls_finish_flag = tls_finish_flags[i].tls_finish_flag;
			break;
		}
	}
}

#define TLS_FINISH_ALGO(_algo_id)                                              \
	{                                                                      \
		.hash_algo_id = SMW_CONFIG_HASH_ALGO_ID_##_algo_id,            \
		.tls_finish_algo_id = HSM_OP_TLS_FINISH_HASH_ALGO_##_algo_id   \
	}

static const struct {
	enum smw_config_hash_algo_id hash_algo_id;
	hsm_op_tls_finish_algo_id_t tls_finish_algo_id;
} tls_finish_algos[] = { TLS_FINISH_ALGO(SHA256), TLS_FINISH_ALGO(SHA384) };

static int
set_tls_finish_algo_id(enum smw_config_hash_algo_id hash_algo_id,
		       hsm_op_tls_finish_algo_id_t *tls_finish_algo_id)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
	unsigned int i = 0;

	for (; i < ARRAY_SIZE(tls_finish_algos); i++) {
		if (hash_algo_id == tls_finish_algos[i].hash_algo_id) {
			*tls_finish_algo_id =
				tls_finish_algos[i].tls_finish_algo_id;
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
	int tmp_status = SMW_STATUS_OK;

	hsm_err_t err = HSM_NO_ERROR;
	hsm_hdl_t key_mgt_hdl = 0;
	op_tls_finish_args_t op_tls_args = { 0 };

	struct smw_crypto_sign_verify_args *smw_args = args;
	struct smw_keymgr_descriptor *key_descriptor =
		&smw_args->key_descriptor;
	struct smw_keymgr_identifier *key_identifier =
		&key_descriptor->identifier;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_ASSERT(smw_args);

	status = set_tls_finish_algo_id(smw_args->attributes.hash_id,
					&op_tls_args.hash_algorithm);
	if (status != SMW_STATUS_OK)
		goto end;

	if (smw_sign_verify_get_sign_len(smw_args) <
	    TLS12_MAC_FINISH_DEFAULT_LEN) {
		status = SMW_STATUS_OUTPUT_TOO_SHORT;
		goto end;
	}

	op_tls_args.verify_data_output_size = TLS12_MAC_FINISH_DEFAULT_LEN;

	op_tls_args.key_identifier = key_identifier->id;
	op_tls_args.handshake_hash_input =
		smw_sign_verify_get_msg_buf(smw_args);
	op_tls_args.verify_data_output = smw_sign_verify_get_sign_buf(smw_args);
	set_tls_finish_flag(smw_args->attributes.type_id, &op_tls_args.flags);

	if (SET_OVERFLOW(smw_sign_verify_get_msg_len(smw_args),
			 op_tls_args.handshake_hash_input_size)) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	status = seco_open_key_mgmt_service(hdl, &key_mgt_hdl);
	if (status != SMW_STATUS_OK)
		goto end;

	SMW_DBG_PRINTF(VERBOSE,
		       "[%s (%d)] Call hsm_tls_finish()\n"
		       "op_tls_finish_args_t\n"
		       "    key_identifier: %d\n"
		       "    handshake_hash_input: %p\n"
		       "    verify_data_output: %p\n"
		       "    handshake_hash_input_size: %d\n"
		       "    verify_data_output_size: %d\n"
		       "    flags: 0x%x\n"
		       "    hash_algorithm: 0x%x\n",
		       __func__, __LINE__, op_tls_args.key_identifier,
		       op_tls_args.handshake_hash_input,
		       op_tls_args.verify_data_output,
		       op_tls_args.handshake_hash_input_size,
		       op_tls_args.verify_data_output_size, op_tls_args.flags,
		       op_tls_args.hash_algorithm);

	err = hsm_tls_finish(key_mgt_hdl, &op_tls_args);

	SMW_DBG_PRINTF(DEBUG, "hsm_tls_finish returned %d\n", err);
	status = seco_convert_err(err);

	smw_sign_verify_set_sign_len(smw_args,
				     op_tls_args.verify_data_output_size);

	SMW_DBG_PRINTF(DEBUG, "Output (%d):\n",
		       op_tls_args.verify_data_output_size);
	SMW_DBG_HEX_DUMP(DEBUG, op_tls_args.verify_data_output,
			 op_tls_args.verify_data_output_size, 4);

end:
	tmp_status = seco_close_key_mgt_service(key_mgt_hdl);
	if (status == SMW_STATUS_OK)
		status = tmp_status;

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);

	return status;
}
