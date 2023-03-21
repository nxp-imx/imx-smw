// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
 */

#include "smw_status.h"

#include "global.h"
#include "debug.h"
#include "utils.h"
#include "subsystems.h"
#include "config.h"
#include "hash.h"

#include "common.h"

#define HASH_ALGO(_id, _hsm_id, _length)                                       \
	{                                                                      \
		.algo_id = SMW_CONFIG_HASH_ALGO_ID_##_id,                      \
		.ele_algo = HSM_HASH_ALGO_##_hsm_id, .length = _length         \
	}

static const struct ele_hash_algo hash_algos[] = {
	HASH_ALGO(SHA224, SHA_224, 28), HASH_ALGO(SHA256, SHA_256, 32),
	HASH_ALGO(SHA384, SHA_384, 48), HASH_ALGO(SHA512, SHA_512, 64)
};

static int hash(struct hdl *hdl, void *args)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	hsm_err_t err;
	op_hash_one_go_args_t op_args = { 0 };

	struct smw_crypto_hash_args *hash_args = args;
	const struct ele_hash_algo *hash_algo = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	hash_algo = ele_get_hash_algo(hash_args->algo_id);
	if (!hash_algo)
		goto end;

	op_args.svc_flags = HSM_HASH_FLAG_ONE_SHOT;
	op_args.input = smw_crypto_get_hash_input_data(hash_args);
	op_args.output = smw_crypto_get_hash_output_data(hash_args);
	op_args.input_size = smw_crypto_get_hash_input_length(hash_args);
	op_args.output_size = smw_crypto_get_hash_output_length(hash_args);
	op_args.algo = hash_algo->ele_algo;

	/* Get output length feature */
	if (!op_args.output) {
		smw_crypto_set_hash_output_length(hash_args, hash_algo->length);
		status = SMW_STATUS_OK;
		goto end;
	}

	SMW_DBG_PRINTF(VERBOSE,
		       "[%s (%d)] Call hsm_do_hash()\n"
		       "op_args_t\n"
		       "    algo: 0x%08X\n"
		       "    flags: 0x%02X\n"
		       "    Input\n"
		       "      - buffer: %p\n"
		       "      - size: %d\n"
		       "    Output\n"
		       "      - buffer: %p\n"
		       "      - size: %d\n",
		       __func__, __LINE__, op_args.algo, op_args.svc_flags,
		       op_args.input, op_args.input_size, op_args.output,
		       op_args.output_size);

	err = hsm_do_hash(hdl->session, &op_args);
	SMW_DBG_PRINTF(DEBUG, "hsm_do_hash returned %d\n", err);

	status = ele_convert_err(err);

	/* Update Digest size */
	smw_crypto_set_hash_output_length(hash_args, op_args.exp_output_size);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

const struct ele_hash_algo *
ele_get_hash_algo(enum smw_config_hash_algo_id algo_id)
{
	const struct ele_hash_algo *hash_algo = NULL;
	unsigned int i;

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (i = 0; i < ARRAY_SIZE(hash_algos); i++) {
		if (hash_algos[i].algo_id == algo_id) {
			hash_algo = &hash_algos[i];
			break;
		}
	}

	return hash_algo;
}

bool ele_hash_handle(struct hdl *hdl, enum operation_id operation_id,
		     void *args, int *status)
{
	switch (operation_id) {
	case OPERATION_ID_HASH:
		*status = hash(hdl, args);
		break;
	default:
		return false;
	}

	return true;
}
