// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2023 NXP
 */

#include "smw_status.h"

#include "global.h"
#include "debug.h"
#include "utils.h"
#include "operations.h"
#include "subsystems.h"
#include "cipher.h"

#include "common.h"

#define CIPHER_ALGO(_key_type_id, _cipher_mode_id)                                \
	{                                                                         \
		.key_type_id = SMW_CONFIG_KEY_TYPE_ID_##_key_type_id,             \
		.cipher_mode_id = SMW_CONFIG_CIPHER_MODE_ID_##_cipher_mode_id,    \
		.hsm_algo =                                                       \
			HSM_CIPHER_ONE_GO_ALGO_##_key_type_id##_##_cipher_mode_id \
	}

static const struct {
	enum smw_config_key_type_id key_type_id;
	enum smw_config_cipher_mode_id cipher_mode_id;
	hsm_op_cipher_one_go_algo_t hsm_algo;
} cipher_algos[] = { CIPHER_ALGO(AES, CBC), CIPHER_ALGO(AES, ECB) };

static int set_cipher_algo(enum smw_config_key_type_id key_type_id,
			   enum smw_config_cipher_mode_id cipher_mode_id,
			   hsm_op_cipher_one_go_algo_t *hsm_algo)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
	unsigned int i = 0;

	for (; i < ARRAY_SIZE(cipher_algos); i++) {
		if (key_type_id == cipher_algos[i].key_type_id &&
		    cipher_mode_id == cipher_algos[i].cipher_mode_id) {
			*hsm_algo = cipher_algos[i].hsm_algo;
			status = SMW_STATUS_OK;
			break;
		}
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

#define CIPHER_FLAG(_op_type_id)                                               \
	{                                                                      \
		.smw_op_type_id = SMW_CONFIG_CIPHER_OP_ID_##_op_type_id,       \
		.hsm_flags = HSM_CIPHER_ONE_GO_FLAGS_##_op_type_id             \
	}

static const struct {
	enum smw_config_cipher_op_type_id smw_op_type_id;
	hsm_op_cipher_one_go_flags_t hsm_flags;
} cipher_flags[] = { CIPHER_FLAG(ENCRYPT), CIPHER_FLAG(DECRYPT) };

static int set_cipher_flags(enum smw_config_cipher_op_type_id smw_op_type_id,
			    hsm_op_cipher_one_go_flags_t *hsm_flags)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
	unsigned int i = 0;

	for (; i < ARRAY_SIZE(cipher_flags); i++) {
		if (smw_op_type_id == cipher_flags[i].smw_op_type_id) {
			*hsm_flags = cipher_flags[i].hsm_flags;
			status = SMW_STATUS_OK;
			break;
		}
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int cipher(struct hdl *hdl, void *args)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	hsm_err_t err = HSM_NO_ERROR;
	op_cipher_one_go_args_t op_cipher_args = { 0 };
	struct smw_crypto_cipher_args *cipher_args = args;
	struct smw_keymgr_descriptor *key_desc = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (smw_crypto_get_cipher_nb_key_buffer(cipher_args)) {
		SMW_DBG_PRINTF(ERROR, "%s: HSM doesn't support keys buffer\n",
			       __func__);
		goto end;
	}

	/* Get 1st key type as reference */
	key_desc = cipher_args->keys_desc[0];

	/* Get HSM algorithm */
	status = set_cipher_algo(key_desc->identifier.type_id,
				 cipher_args->mode_id,
				 &op_cipher_args.cipher_algo);
	if (status != SMW_STATUS_OK)
		goto end;

	/* Get HSM operation */
	status = set_cipher_flags(cipher_args->op_id, &op_cipher_args.flags);
	if (status != SMW_STATUS_OK)
		goto end;

	op_cipher_args.output = smw_crypto_get_cipher_output(cipher_args);
	op_cipher_args.input_size =
		smw_crypto_get_cipher_input_len(cipher_args);

	/* Get output length feature */
	if (!op_cipher_args.output) {
		/* Cipher output length is equal to input length */
		smw_crypto_set_cipher_output_len(cipher_args,
						 op_cipher_args.input_size);
		status = SMW_STATUS_OK;
		goto end;
	}

	/*
	 * If output length is too short, update is done here (not supported by
	 * HSM)
	 */
	if (smw_crypto_get_cipher_output_len(cipher_args) <
	    op_cipher_args.input_size) {
		status = SMW_STATUS_OUTPUT_TOO_SHORT;
		smw_crypto_set_cipher_output_len(cipher_args,
						 op_cipher_args.input_size);
		goto end;
	}

	op_cipher_args.key_identifier =
		smw_crypto_get_cipher_key_id(cipher_args, 0);
	op_cipher_args.iv = smw_crypto_get_cipher_iv(cipher_args);
	op_cipher_args.input = smw_crypto_get_cipher_input(cipher_args);

	if (SET_OVERFLOW(smw_crypto_get_cipher_iv_len(cipher_args),
			 op_cipher_args.iv_size)) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	/*
	 * If output length is too big HSM returns HSM_INVALID_PARAM, which
	 * doesn't match SMW API behavior. Then set HSM argument to the correct
	 * value.
	 */
	op_cipher_args.output_size = op_cipher_args.input_size;

	SMW_DBG_PRINTF(VERBOSE,
		       "[%s (%d)] Call hsm_cipher_one_go()\n"
		       "cipher_hdl: %d\n"
		       "op_cipher_one_go_args_t\n"
		       "    key_identifier: %d\n"
		       "    iv: %p\n"
		       "    iv_size: %d\n"
		       "    cipher_algo: %d\n"
		       "    flags: %d\n"
		       "    input: %p\n"
		       "    output: %p\n"
		       "    input_size: %d\n"
		       "    output_size: %d\n",
		       __func__, __LINE__, hdl->cipher,
		       op_cipher_args.key_identifier, op_cipher_args.iv,
		       op_cipher_args.iv_size, op_cipher_args.cipher_algo,
		       op_cipher_args.flags, op_cipher_args.input,
		       op_cipher_args.output, op_cipher_args.input_size,
		       op_cipher_args.output_size);

	err = hsm_cipher_one_go(hdl->cipher, &op_cipher_args);
	if (err != HSM_NO_ERROR) {
		SMW_DBG_PRINTF(DEBUG, "hsm_cipher_one_go returned %d\n", err);
		status = SMW_STATUS_SUBSYSTEM_FAILURE;
	}

	/* Update output length */
	smw_crypto_set_cipher_output_len(cipher_args,
					 op_cipher_args.output_size);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

bool hsm_cipher_handle(struct hdl *hdl, enum operation_id operation_id,
		       void *args, int *status)
{
	switch (operation_id) {
	case OPERATION_ID_CIPHER:
		*status = cipher(hdl, args);
		break;

	default:
		return false;
	}

	return true;
}
