// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021 NXP
 */

#include "hsm_api.h"

#include "smw_status.h"

#include "global.h"
#include "debug.h"
#include "utils.h"
#include "operations.h"
#include "subsystems.h"
#include "cipher.h"

#include "common.h"

#define CIPHER_ONE_GO_ALGO_ID(_key_type, _cipher_mode)                         \
	{                                                                      \
		.key_type = SMW_CONFIG_KEY_TYPE_ID_##_key_type,                \
		.cipher_mode = SMW_CONFIG_CIPHER_MODE_ID_##_cipher_mode,       \
		.hsm_algo =                                                    \
			HSM_CIPHER_ONE_GO_ALGO_##_key_type##_##_cipher_mode    \
	}

static const struct {
	enum smw_config_key_type_id key_type;
	enum smw_config_cipher_mode_id cipher_mode;
	hsm_op_cipher_one_go_algo_t hsm_algo;
} CIPHER_ONE_GO_ALGO_ID[] = { CIPHER_ONE_GO_ALGO_ID(AES, CBC),
			      CIPHER_ONE_GO_ALGO_ID(AES, ECB) };

static int get_cipher_one_go_algo(enum smw_config_key_type_id key_type,
				  enum smw_config_cipher_mode_id cipher_mode,
				  hsm_op_cipher_one_go_algo_t *hsm_algo)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(CIPHER_ONE_GO_ALGO_ID); i++) {
		if (key_type == CIPHER_ONE_GO_ALGO_ID[i].key_type &&
		    cipher_mode == CIPHER_ONE_GO_ALGO_ID[i].cipher_mode) {
			*hsm_algo = CIPHER_ONE_GO_ALGO_ID[i].hsm_algo;
			return SMW_STATUS_OK;
		}
	}

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

static int get_cipher_one_go_flags(enum smw_config_cipher_op_type_id smw_op,
				   hsm_op_cipher_one_go_flags_t *hsm_op)
{
	switch (smw_op) {
	case SMW_CONFIG_CIPHER_OP_ID_ENCRYPT:
		*hsm_op = HSM_CIPHER_ONE_GO_FLAGS_ENCRYPT;
		break;

	case SMW_CONFIG_CIPHER_OP_ID_DECRYPT:
		*hsm_op = HSM_CIPHER_ONE_GO_FLAGS_DECRYPT;
		break;

	default:
		return SMW_STATUS_INVALID_PARAM;
	}

	return SMW_STATUS_OK;
}

static int cipher(struct hdl *hdl, void *args)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
	hsm_err_t err = HSM_NO_ERROR;
	op_cipher_one_go_args_t op_cipher_args = { 0 };
	enum smw_config_key_type_id key_type;
	struct smw_crypto_cipher_args *cipher_args = args;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (smw_crypto_get_cipher_nb_key_buffer(cipher_args)) {
		SMW_DBG_PRINTF(ERROR, "%s: HSM doesn't support keys buffer\n",
			       __func__);
		goto end;
	}

	/* Get 1st key type as reference */
	key_type = cipher_args->keys_desc[0]->identifier.type_id;

	/* Get HSM algorithm */
	status = get_cipher_one_go_algo(key_type, cipher_args->mode_id,
					&op_cipher_args.cipher_algo);
	if (status != SMW_STATUS_OK)
		goto end;

	/* Get HSM operation */
	status = get_cipher_one_go_flags(cipher_args->op_id,
					 &op_cipher_args.flags);
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
	op_cipher_args.iv_size = smw_crypto_get_cipher_iv_len(cipher_args);
	op_cipher_args.input = smw_crypto_get_cipher_input(cipher_args);

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
