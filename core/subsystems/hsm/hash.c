// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2021 NXP
 */

#include "hsm_api.h"

#include "smw_status.h"

#include "smw_osal.h"
#include "global.h"
#include "debug.h"
#include "utils.h"
#include "operations.h"
#include "subsystems.h"
#include "config.h"
#include "hash.h"

#include "common.h"

#define HASH_ALGO(id, hsm_id)                                                  \
	{                                                                      \
		.algo_id = SMW_CONFIG_HASH_ALGO_ID_##id,                       \
		.hsm_hash_algo = HSM_HASH_ALGO_##hsm_id                        \
	}

/* Algo IDs must be ordered from lowest to highest.
 * This sorting is required to simplify the implementation of set_hash_algo().
 */
struct {
	enum smw_config_hash_algo_id algo_id;
	hsm_hash_algo_t hsm_hash_algo;
} hash_algo_ids[] = { HASH_ALGO(SHA224, SHA_224), HASH_ALGO(SHA256, SHA_256),
		      HASH_ALGO(SHA384, SHA_384), HASH_ALGO(SHA512, SHA_512) };

static int set_hash_algo(enum smw_config_hash_algo_id algo_id,
			 hsm_hash_algo_t *algo)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	unsigned int i;
	unsigned int size = ARRAY_SIZE(hash_algo_ids);

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (i = 0; i < size; i++) {
		if (hash_algo_ids[i].algo_id < algo_id)
			continue;
		if (hash_algo_ids[i].algo_id > algo_id)
			goto end;
		*algo = hash_algo_ids[i].hsm_hash_algo;
		status = SMW_STATUS_OK;
		break;
	}

	SMW_DBG_PRINTF(DEBUG, "HSM Algo: %x\n", *algo);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int hash(struct hdl *hdl, void *args)
{
	int status = SMW_STATUS_OK;

	hsm_err_t err = HSM_NO_ERROR;

	op_hash_one_go_args_t op_hash_one_go_args = { 0 };

	struct smw_crypto_hash_args *hash_args = args;

	SMW_DBG_TRACE_FUNCTION_CALL;

	op_hash_one_go_args.input = smw_crypto_get_hash_input_data(hash_args);
	op_hash_one_go_args.output = smw_crypto_get_hash_output_data(hash_args);
	op_hash_one_go_args.input_size =
		smw_crypto_get_hash_input_length(hash_args);
	op_hash_one_go_args.output_size =
		smw_crypto_get_hash_output_length(hash_args);
	status = set_hash_algo(hash_args->algo_id, &op_hash_one_go_args.algo);
	if (status != SMW_STATUS_OK)
		goto end;

	SMW_DBG_PRINTF(VERBOSE,
		       "[%s (%d)] Call hsm_hash_one_go()\n"
		       "hash_hdl: %d\n"
		       "op_hash_one_go_args_t\n"
		       "    input: %p\n"
		       "    output: %p\n"
		       "    input_size: %d\n"
		       "    output_size: %d\n"
		       "    algo: %x\n"
		       "    flags: %x\n",
		       __func__, __LINE__, hdl->hash, op_hash_one_go_args.input,
		       op_hash_one_go_args.output,
		       op_hash_one_go_args.input_size,
		       op_hash_one_go_args.output_size,
		       op_hash_one_go_args.algo, op_hash_one_go_args.flags);

	err = hsm_hash_one_go(hdl->hash, &op_hash_one_go_args);
	if (err != HSM_NO_ERROR) {
		SMW_DBG_PRINTF(DEBUG, "hsm_hash_one_go returned %d\n", err);
		status = SMW_STATUS_SUBSYSTEM_FAILURE;
		goto end;
	}

	smw_crypto_set_hash_output_length(hash_args,
					  op_hash_one_go_args.output_size);

	SMW_DBG_PRINTF(DEBUG, "Output (%d):\n",
		       op_hash_one_go_args.output_size);
	SMW_DBG_HEX_DUMP(DEBUG, op_hash_one_go_args.output,
			 op_hash_one_go_args.output_size, 4);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

bool hsm_hash_handle(struct hdl *hdl, enum operation_id operation_id,
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
