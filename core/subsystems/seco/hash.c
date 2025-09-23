// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2025 NXP
 */

#include "smw_status.h"

#include "debug.h"
#include "utils.h"
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

/**
 * struct hash_context - Hash context
 * @context: Hash operation context
 */
struct hash_context {
	struct smw_hash_context context;
};

static int set_hash_context(struct smw_op_context *op_context,
			    enum smw_config_hash_algo_id hash_id)
{
	int status = SMW_STATUS_INVALID_PARAM;

	struct hash_context *hash_context = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!op_context)
		goto end;

	op_context->op_id = SMW_CRYPTO_OP_ID_HASH_MULTI_PART;

	hash_context = SMW_UTILS_MALLOC(sizeof(*hash_context));
	if (!hash_context) {
		status = SMW_STATUS_ALLOC_FAILURE;
		SMW_DBG_PRINTF(DEBUG,
			       "Hash subsystem context allocation failure\n");
		goto end;
	}

	status = smw_utils_hash_init(hash_id, &hash_context->context);
	if (status != SMW_STATUS_OK)
		goto end;

	op_context->subsystem_context = hash_context;
	op_context->op_state = CTX_OP_STATE_INIT;

end:
	if (status != SMW_STATUS_OK && hash_context)
		SMW_UTILS_FREE(hash_context);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int hash_smw(struct smw_crypto_hash_args *args)
{
	int status = SMW_STATUS_OK;

	unsigned char *input = NULL;
	unsigned int input_length = 0;
	unsigned char *digest = NULL;
	unsigned int digest_length = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	input = smw_crypto_get_hash_input_data(args);
	input_length = smw_crypto_get_hash_input_length(args);
	digest = smw_crypto_get_hash_output_data(args);
	digest_length = smw_crypto_get_hash_output_length(args);

	status = smw_utils_hash(args->algo_id, input, input_length, digest,
				&digest_length);

	if (status == SMW_STATUS_OK || status == SMW_STATUS_OUTPUT_TOO_SHORT)
		smw_crypto_set_hash_output_length(args, digest_length);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
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
		status = hash_smw(hash_args);
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

static int hash_init(struct smw_op_context *op_context,
		     struct smw_crypto_hash_args *args)
{
	int status = SMW_STATUS_OK;

	struct hash_context *hash_context = NULL;
	unsigned char *input = NULL;
	unsigned int input_length = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	smw_crypto_set_ctx_subsystem_id(op_context, SUBSYSTEM_ID_SECO);

	status = set_hash_context(op_context, args->algo_id);
	if (status != SMW_STATUS_OK)
		goto end;

	hash_context = op_context->subsystem_context;
	if (!hash_context) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	input = smw_crypto_get_hash_input_data(args);
	input_length = smw_crypto_get_hash_input_length(args);

	status = smw_utils_hash_update(&hash_context->context, input,
				       input_length);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int hash_update(struct smw_op_context *op_context,
		       struct smw_crypto_hash_args *args)
{
	int status = SMW_STATUS_INVALID_PARAM;

	struct hash_context *hash_context = NULL;
	unsigned char *input = NULL;
	unsigned int input_length = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	hash_context = op_context->subsystem_context;
	if (!hash_context)
		goto end;

	input = smw_crypto_get_hash_input_data(args);
	input_length = smw_crypto_get_hash_input_length(args);

	status = smw_utils_hash_update(&hash_context->context, input,
				       input_length);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int hash_final(struct smw_op_context *op_context,
		      struct smw_crypto_hash_args *args)
{
	int status = SMW_STATUS_INVALID_PARAM;

	struct hash_context *hash_context = NULL;
	unsigned char *input = NULL;
	unsigned int input_length = 0;
	unsigned char *digest = NULL;
	unsigned int digest_length = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	hash_context = op_context->subsystem_context;
	if (!hash_context)
		goto end;

	input = smw_crypto_get_hash_input_data(args);
	input_length = smw_crypto_get_hash_input_length(args);

	digest = smw_crypto_get_hash_output_data(args);
	digest_length = smw_crypto_get_hash_output_length(args);

	status = smw_utils_hash_final(&hash_context->context, input,
				      input_length, digest, &digest_length);

	if (status == SMW_STATUS_OK || status == SMW_STATUS_OUTPUT_TOO_SHORT)
		smw_crypto_set_hash_output_length(args, digest_length);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int hash_multi_part(void *args)
{
	int status = SMW_STATUS_INVALID_PARAM;
	struct smw_crypto_hash_args *hash_args = args;
	struct smw_op_context *op_context =
		smw_crypto_get_hash_op_context(args);

	if (!op_context)
		goto end;

	switch (hash_args->op_step) {
	case SMW_OP_STEP_INIT:
		status = hash_init(op_context, hash_args);
		break;

	case SMW_OP_STEP_UPDATE:
		status = hash_update(op_context, hash_args);
		break;

	case SMW_OP_STEP_FINAL:
		status = hash_final(op_context, hash_args);
		break;

	default:
		status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
		break;
	}

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
	case OPERATION_ID_HASH_MULTI_PART:
		*status = hash_multi_part(args);
		break;
	default:
		return false;
	}

	return true;
}

int seco_copy_hash_context(struct smw_op_context *src_ctx,
			   struct smw_op_context *dst_ctx)
{
	int status = SMW_STATUS_ALLOC_FAILURE;

	struct hash_context *src_hash_ctx = NULL;
	struct hash_context *dst_hash_ctx = NULL;

	if (!src_ctx || !dst_ctx || !src_ctx->subsystem_context) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	src_hash_ctx = src_ctx->subsystem_context;

	dst_hash_ctx = SMW_UTILS_MALLOC(sizeof(*dst_hash_ctx));
	if (!dst_hash_ctx)
		goto end;

	*dst_hash_ctx = *src_hash_ctx;

	dst_ctx->subsystem_context = dst_hash_ctx;

	status = SMW_STATUS_OK;

end:
	return status;
}
