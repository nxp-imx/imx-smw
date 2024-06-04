// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2024 NXP
 */

#include "smw_status.h"

#include "global.h"
#include "debug.h"
#include "utils.h"
#include "operations.h"
#include "subsystems.h"
#include "config.h"
#include "hash.h"

#include "common.h"

#define HASH_ALGO(_id, _seco_id, _length)                                      \
	{                                                                      \
		.algo_id = SMW_CONFIG_HASH_ALGO_ID_##_id,                      \
		.hash_algo = HSM_HASH_ALGO_##_seco_id, .length = _length       \
	}

/* Algo IDs must be ordered from lowest to highest.
 * This sorting is required to simplify the implementation of get_hash_algo_info().
 */
static const struct hash_algo_info {
	enum smw_config_hash_algo_id algo_id;
	hsm_hash_algo_t hash_algo;
	uint32_t length;
} hash_algo_info[] = { HASH_ALGO(SHA224, SHA_224, 28),
		       HASH_ALGO(SHA256, SHA_256, 32),
		       HASH_ALGO(SHA384, SHA_384, 48),
		       HASH_ALGO(SHA512, SHA_512, 64) };

static const struct hash_algo_info *
get_hash_algo_info(enum smw_config_hash_algo_id algo_id)
{
	const struct hash_algo_info *info = NULL;

	unsigned int i = 0;
	unsigned int size = ARRAY_SIZE(hash_algo_info);

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (; i < size; i++) {
		if (hash_algo_info[i].algo_id < algo_id)
			continue;
		if (hash_algo_info[i].algo_id > algo_id)
			break;
		info = &hash_algo_info[i];
		break;
	}

	return info;
}

static int hash(struct hdl *hdl, void *args)
{
	int status = SMW_STATUS_OK;

	hsm_err_t err = HSM_NO_ERROR;

	op_hash_one_go_args_t op_args = { 0 };

	struct smw_crypto_hash_args *hash_args = args;
	const struct hash_algo_info *hash_algo_info = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	hash_algo_info = get_hash_algo_info(hash_args->algo_id);
	if (!hash_algo_info) {
		status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
		goto end;
	}

	op_args.svc_flags = HSM_HASH_FLAG_ONE_SHOT;
	op_args.input = smw_crypto_get_hash_input_data(hash_args);
	op_args.output = smw_crypto_get_hash_output_data(hash_args);
	op_args.input_size = smw_crypto_get_hash_input_length(hash_args);
	op_args.output_size = smw_crypto_get_hash_output_length(hash_args);
	op_args.algo = hash_algo_info->hash_algo;

	if (!op_args.output) {
		smw_crypto_set_hash_output_length(hash_args,
						  hash_algo_info->length);
		goto end;
	}

	if (op_args.output_size < hash_algo_info->length) {
		smw_crypto_set_hash_output_length(hash_args,
						  hash_algo_info->length);
		status = SMW_STATUS_OUTPUT_TOO_SHORT;
		goto end;
	}

	if (op_args.output_size > hash_algo_info->length)
		op_args.output_size = hash_algo_info->length;

	SMW_DBG_PRINTF(VERBOSE,
		       "[%s (%d)] Call hsm_do_hash()\n"
		       "op_hash_one_go_args_t\n"
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
	if (err != HSM_NO_ERROR) {
		SMW_DBG_PRINTF(DEBUG, "hsm_do_hash returned %d\n", err);
		status = SMW_STATUS_SUBSYSTEM_FAILURE;
		goto end;
	}

	smw_crypto_set_hash_output_length(hash_args, op_args.output_size);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

bool seco_hash_handle(struct hdl *hdl, enum operation_id operation_id,
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
