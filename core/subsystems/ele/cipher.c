// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022 NXP
 */

#include "smw_status.h"

#include "global.h"
#include "debug.h"
#include "utils.h"
#include "subsystems.h"
#include "cipher.h"

#include "common.h"

#define CIPHER_ONE_GO_ALGO_ID(_key_type, _cipher_mode)                         \
	{                                                                      \
		.key_type = SMW_CONFIG_KEY_TYPE_ID_##_key_type,                \
		.cipher_mode = SMW_CONFIG_CIPHER_MODE_ID_##_cipher_mode,       \
		.hsm_algo = HSM_CIPHER_ONE_GO_ALGO_##_cipher_mode              \
	}

static struct {
	enum smw_config_key_type_id key_type;
	enum smw_config_cipher_mode_id cipher_mode;
	hsm_op_cipher_one_go_algo_t hsm_algo;
} cipher_algo[] = {
	CIPHER_ONE_GO_ALGO_ID(AES, CBC),
	CIPHER_ONE_GO_ALGO_ID(AES, ECB),
	CIPHER_ONE_GO_ALGO_ID(AES, CTR),
};

static int get_cipher_one_go_algo(enum smw_config_key_type_id key_type,
				  enum smw_config_cipher_mode_id cipher_mode,
				  hsm_op_cipher_one_go_algo_t *hsm_algo)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(cipher_algo); i++) {
		if (key_type == cipher_algo[i].key_type &&
		    cipher_mode == cipher_algo[i].cipher_mode) {
			*hsm_algo = cipher_algo[i].hsm_algo;
			status = SMW_STATUS_OK;
			break;
		}
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
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

	hsm_err_t err;
	op_cipher_one_go_args_t op_args = { 0 };
	enum smw_config_key_type_id key_type;
	struct smw_crypto_cipher_args *cipher_args = args;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (smw_crypto_get_cipher_nb_key_buffer(cipher_args)) {
		SMW_DBG_PRINTF(ERROR, "%s: ELE doesn't support keys buffer\n",
			       __func__);
		goto end;
	}

	/* Get 1st key type as reference */
	key_type = cipher_args->keys_desc[0]->identifier.type_id;

	/* Get ELE algorithm */
	status = get_cipher_one_go_algo(key_type, cipher_args->mode_id,
					&op_args.cipher_algo);
	if (status != SMW_STATUS_OK)
		goto end;

	/* Get ELE operation */
	status = get_cipher_one_go_flags(cipher_args->op_id, &op_args.flags);
	if (status != SMW_STATUS_OK)
		goto end;

	op_args.output = smw_crypto_get_cipher_output(cipher_args);

	/* Get output length feature */
	if (!op_args.output) {
		/* Cipher output length is equal to input length */
		smw_crypto_set_cipher_output_len(cipher_args,
						 op_args.input_size);
		status = SMW_STATUS_OK;
		goto end;
	}

	op_args.key_identifier = smw_crypto_get_cipher_key_id(cipher_args, 0);
	op_args.output_size = smw_crypto_get_cipher_output_len(cipher_args);
	op_args.input = smw_crypto_get_cipher_input(cipher_args);
	op_args.input_size = smw_crypto_get_cipher_input_len(cipher_args);
	op_args.iv = smw_crypto_get_cipher_iv(cipher_args);
	op_args.iv_size = smw_crypto_get_cipher_iv_len(cipher_args);

	SMW_DBG_PRINTF(VERBOSE,
		       "[%s (%d)] Call hsm_cipher_one_go()\n"
		       "op_cipher_one_go_args_t\n"
		       "    key_identifier: 0x%08X\n"
		       "    algo: 0x%08X\n"
		       "    flags: 0x%X\n"
		       "    IV\n"
		       "      - buffer: %p\n"
		       "      - size: %d\n"
		       "    Input\n"
		       "       - buffer: %p\n"
		       "       - size: %d\n"
		       "    Output\n"
		       "       - buffer: %p\n"
		       "       - size: %d\n",
		       __func__, __LINE__, op_args.key_identifier,
		       op_args.cipher_algo, op_args.flags, op_args.iv,
		       op_args.iv_size, op_args.input, op_args.input_size,
		       op_args.output, op_args.output_size);

	err = hsm_do_cipher(hdl->key_store, &op_args);
	SMW_DBG_PRINTF(DEBUG, "hsm_cipher_one_go returned %d\n", err);

	status = ele_convert_err(err);

	/* Update the output length  */
	smw_crypto_set_cipher_output_len(cipher_args, op_args.output_size);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

bool ele_cipher_handle(struct hdl *hdl, enum operation_id operation_id,
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
