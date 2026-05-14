// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2026 NXP
 */

#include "smw_status.h"

#include "global.h"
#include "debug.h"
#include "utils.h"
#include "subsystems.h"
#include "cipher.h"

#include "common.h"

struct cipher_context {
	enum smw_config_cipher_op_type_id op_type_id;
	bool opaque_key;
	struct hdl *hdl;
	hsm_hdl_t cipher_hdl;
	uint8_t *ele_context;
	uint16_t ele_context_size;
	uint32_t ele_cipher_algo;
	unsigned int remaining_buffered_len;
};

static void set_cipher_flags(struct smw_crypto_cipher_args *cipher_args,
			     enum smw_config_cipher_op_type_id op_type_id,
			     hsm_op_cipher_flags_t *flags)
{
	switch (cipher_args->op_step) {
	case SMW_OP_STEP_ONESHOT:
		*flags = 0;
		break;

	case SMW_OP_STEP_INIT:
		*flags = HSM_CIPHER_FLAGS_INIT;
		break;

	case SMW_OP_STEP_UPDATE:
		*flags = HSM_CIPHER_FLAGS_UPDATE_DATA;
		break;

	case SMW_OP_STEP_FINAL:
		*flags = HSM_CIPHER_FLAGS_FINALIZE;
		break;

	default:
		break;
	}

	if (op_type_id == SMW_CONFIG_CIPHER_OP_TYPE_ID_ENCRYPT)
		*flags |= HSM_CIPHER_FLAGS_ENCRYPT;
	else
		*flags |= HSM_CIPHER_FLAGS_DECRYPT;
}

static int get_private_key_buffer(op_cipher_args_t *op_args,
				  struct smw_keymgr_descriptor *key_desc)
{
	int status = SMW_STATUS_INVALID_PARAM;

	unsigned int private_buf_len = smw_keymgr_get_private_length(key_desc);
	unsigned char *private_buffer = smw_keymgr_get_private_data(key_desc);
	unsigned int hex_private_len = 0;

	if (!private_buf_len || !private_buffer)
		goto end;

	status = smw_utils_key_set_hex_buffer(key_desc->format_id,
					      private_buffer, private_buf_len,
					      &op_args->key, &hex_private_len);
	if (status != SMW_STATUS_OK)
		goto end;

	if (SET_OVERFLOW(hex_private_len, op_args->key_size)) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

end:
	return status;
}

static int cipher(struct hdl *hdl, void *args)
{
	int status = SMW_STATUS_OK;

	hsm_err_t err = HSM_NO_ERROR;
	op_cipher_one_go_args_t op_args = { 0 };
	enum smw_config_key_type_id key_type_id = 0;
	struct smw_crypto_cipher_args *cipher_args = args;
	struct smw_keymgr_descriptor *key_desc = cipher_args->keys_desc[0];
	struct smw_keymgr_identifier *key_identifier = &key_desc->identifier;
	hsm_key_type_t ele_key_type = (hsm_key_type_t)0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	op_args.output = smw_crypto_get_cipher_output(cipher_args);
	op_args.input_size = smw_crypto_get_cipher_input_len(cipher_args);

	/* Get output length feature */
	if (!op_args.output) {
		/* Cipher output length is equal to input length */
		smw_crypto_set_cipher_output_len(cipher_args,
						 op_args.input_size);
		goto end;
	}

	/* Get 1st key type as reference */
	key_type_id = key_identifier->type_id;

	/* Get ELE algorithm */
	status = ele_set_cipher_algo(key_type_id, cipher_args->mode_id,
				     &op_args.cipher_algo);
	if (status != SMW_STATUS_OK)
		goto end;

	/* Get ELE operation */
	set_cipher_flags(cipher_args, cipher_args->op_type_id, &op_args.flags);

	if (key_identifier->s_id) {
		op_args.key_identifier =
			smw_crypto_get_cipher_key_id(cipher_args, 0);
	} else {
		/* Cipher using plaintext key buffer */
		op_args.flags |= HSM_CIPHER_FLAGS_PLAINTEXT_KEY;
		status = ele_get_key_type(key_type_id, &ele_key_type);
		if (status != SMW_STATUS_OK)
			goto end;

		op_args.key_type = ele_key_type;

		status = get_private_key_buffer(&op_args, key_desc);
		if (status != SMW_STATUS_OK)
			goto end;
	}

	op_args.output_size = smw_crypto_get_cipher_output_len(cipher_args);
	op_args.input = smw_crypto_get_cipher_input(cipher_args);
	op_args.iv = smw_crypto_get_cipher_iv(cipher_args);

	if (SET_OVERFLOW(smw_crypto_get_cipher_iv_len(cipher_args),
			 op_args.iv_size)) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	status = ele_open_key_store_service(hdl);
	if (status != SMW_STATUS_OK)
		goto end;

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

	/* Update the output length */
	smw_crypto_set_cipher_output_len(cipher_args, op_args.exp_output_size);

end:
	if (key_desc->format_id == SMW_KEYMGR_FORMAT_ID_BASE64 && op_args.key)
		SMW_UTILS_FREE(op_args.key);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);

	// coverity[missing_unlock]
	return status;
}

static int set_cipher_key(struct smw_crypto_cipher_args *cipher_args,
			  op_cipher_args_t *op_args)
{
	int status = SMW_STATUS_OK;

	struct smw_keymgr_descriptor *key_descriptor = NULL;
	struct smw_keymgr_identifier *key_identifier = NULL;
	hsm_key_type_t ele_key_type = (hsm_key_type_t)0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	key_descriptor = cipher_args->keys_desc[0];
	key_identifier = &key_descriptor->identifier;

	if (key_identifier->s_id) {
		op_args->key_identifier = key_identifier->s_id;
	} else {
		op_args->flags |= HSM_CIPHER_FLAGS_PLAINTEXT_KEY;

		status = ele_get_key_type(key_identifier->type_id,
					  &ele_key_type);
		if (status != SMW_STATUS_OK)
			goto end;

		op_args->key_type = ele_key_type;

		status = get_private_key_buffer(op_args, key_descriptor);
		if (status != SMW_STATUS_OK)
			goto end;
	}

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int set_output_length(struct smw_crypto_cipher_args *cipher_args,
			     struct cipher_context *context)
{
	int status = SMW_STATUS_OK;
	unsigned int expected_output_len = 0;
	struct crypto_output_params params = { 0 };

	params.input_len = smw_crypto_get_cipher_input_len(cipher_args);
	params.op_step = cipher_args->op_step;
	params.remaining_buffered_len = context->remaining_buffered_len;

	status = ele_calculate_expected_output_len(&params,
						   &expected_output_len);
	if (status != SMW_STATUS_OK)
		goto end;

	smw_crypto_set_cipher_output_len(cipher_args, expected_output_len);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned with output length = %u\n",
		       __func__, expected_output_len);
	return status;
}

static int
set_expected_output_length(struct smw_crypto_cipher_args *cipher_args,
			   struct cipher_context *cipher_ctx,
			   unsigned int subsystem_exp_output,
			   unsigned int implicit_update_exp_output)
{
	int status = SMW_STATUS_OK;
	unsigned int expected_output_len = 0;
	struct crypto_output_params params = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	params.op_step = cipher_args->op_step;
	params.remaining_buffered_len = cipher_ctx->remaining_buffered_len;

	if (cipher_args->op_step == SMW_OP_STEP_UPDATE) {
		/*
		 * For UPDATE: use subsystem expected output if available,
		 * otherwise use input length as estimate
		 */
		params.input_len =
			subsystem_exp_output ?
				subsystem_exp_output :
				smw_crypto_get_cipher_input_len(cipher_args);
	} else if (cipher_args->op_step == SMW_OP_STEP_FINAL) {
		params.input_len = implicit_update_exp_output;
	}

	/* Use common function to calculate expected output length */
	status = ele_calculate_expected_output_len(&params,
						   &expected_output_len);
	if (status != SMW_STATUS_OK)
		goto end;

	smw_crypto_set_cipher_output_len(cipher_args, expected_output_len);

end:
	SMW_DBG_PRINTF(VERBOSE,
		       "%s returned %d (expected output length = %u)\n",
		       __func__, status, expected_output_len);
	return status;
}

static void free_cipher_context(struct cipher_context *cipher_ctx)
{
	if (!cipher_ctx)
		return;

	if (cipher_ctx->cipher_hdl)
		(void)close_cipher_service(cipher_ctx->cipher_hdl);

	if (cipher_ctx->tmp_output)
		SMW_UTILS_FREE(cipher_ctx->tmp_output);

	if (cipher_ctx->ele_context)
		SMW_UTILS_FREE(cipher_ctx->ele_context);
}

static int do_cipher_multi_part(struct cipher_context *cipher_ctx,
				op_cipher_args_t *op_args)
{
	int status = SMW_STATUS_OK;
	hsm_err_t err = HSM_NO_ERROR;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (cipher_ctx->cipher_hdl == 0) {
		status = open_cipher_service(cipher_ctx->hdl,
					     &cipher_ctx->cipher_hdl);
		if (status != SMW_STATUS_OK)
			goto end;
	}

	if (!cipher_ctx->opaque_key) {
		op_args->flags |= HSM_CIPHER_FLAGS_PLAINTEXT_KEY;
		op_args->context = cipher_ctx->ele_context;
		op_args->context_size = cipher_ctx->ele_context_size;
	}

	op_args->cipher_algo = cipher_ctx->ele_cipher_algo;

	SMW_DBG_PRINTF(VERBOSE,
		       "[%s (%d)] Call hsm_cipher()\n"
		       "cipher_hdl: 0x%08X\n"
		       "op_cipher_args_t\n"
		       "    algo: 0x%08X\n"
		       "    flags: 0x%08X\n"
		       "    Key:\n"
		       "       - identifier: 0x%08X\n"
		       "       - buffer: %p\n"
		       "       - size: %d\n"
		       "    Input:\n"
		       "      - buffer: %p\n"
		       "      - size: %d\n"
		       "    IV:\n"
		       "      - buffer: %p\n"
		       "      - size: %d\n"
		       "    Output:\n"
		       "      - buffer: %p\n"
		       "      - size: %d\n"
		       "    Context:\n"
		       "      - buffer: %p\n"
		       "      - size: %d\n",
		       __func__, __LINE__, cipher_ctx->cipher_hdl,
		       op_args->cipher_algo, op_args->flags,
		       op_args->key_identifier, op_args->key, op_args->key_size,
		       op_args->input, op_args->input_size, op_args->iv,
		       op_args->iv_size, op_args->output, op_args->output_size,
		       op_args->context, op_args->context_size);

	err = hsm_cipher(cipher_ctx->cipher_hdl, op_args);
	SMW_DBG_PRINTF(DEBUG, "hsm_cipher returned %d\n", err);
	status = ele_convert_err(err);

	SMW_DBG_PRINTF(DEBUG, "exp_output_size = %d\n",
		       op_args->exp_output_size);

end:
	return status;
}

static int cipher_setup_context(struct subsystem_context *ele_ctx,
				struct smw_op_context *op_context,
				struct smw_crypto_cipher_args *cipher_args,
				op_cipher_args_t *op_args)
{
	int status = SMW_STATUS_ALLOC_FAILURE;
	struct cipher_context *cipher_ctx = NULL;
	struct smw_keymgr_descriptor *key_descriptor = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (cipher_args->nb_keys == 0 || !cipher_args->keys_desc ||
	    !cipher_args->keys_desc[0])
		return SMW_STATUS_INVALID_PARAM;

	key_descriptor = cipher_args->keys_desc[0];

	cipher_ctx = SMW_UTILS_CALLOC(1, sizeof(*cipher_ctx));
	if (!cipher_ctx)
		goto end;

	cipher_ctx->op_type_id = cipher_args->op_type_id;
	cipher_ctx->ele_cipher_algo = op_args->cipher_algo;
	cipher_ctx->opaque_key = key_descriptor->identifier.s_id != 0;

	status = ele_open_key_store_service(&ele_ctx->hdl);
	if (status != SMW_STATUS_OK)
		goto end;

	cipher_ctx->hdl = &ele_ctx->hdl;

	status = open_cipher_service(&ele_ctx->hdl, &cipher_ctx->cipher_hdl);
	if (status != SMW_STATUS_OK)
		goto end;

	smw_crypto_set_ctx_subsystem_id(op_context, SUBSYSTEM_ID_ELE);
	op_context->op_id = SMW_CRYPTO_OP_ID_CIPHER_MULTI_PART;
	op_context->op_state = CTX_OP_STATE_ALLOC;

	if (cipher_ctx->opaque_key) {
		SMW_DBG_PRINTF(DEBUG,
			       "Not setting up context with opaque key\n");
		goto end;
	}

	op_args->flags |= HSM_CIPHER_FLAGS_GET_CTX_SIZE;

	status = do_cipher_multi_part(cipher_ctx, op_args);
	if (status != SMW_STATUS_OK)
		goto end;

	op_args->flags &= ~HSM_CIPHER_FLAGS_GET_CTX_SIZE;

	if (op_args->exp_output_size) {
		cipher_ctx->ele_context_size = op_args->exp_output_size;

		cipher_ctx->ele_context =
			SMW_UTILS_CALLOC(1, cipher_ctx->ele_context_size);
		if (!cipher_ctx->ele_context) {
			status = SMW_STATUS_ALLOC_FAILURE;
			goto end;
		}
	}

end:
	if (status == SMW_STATUS_OK) {
		op_context->subsystem_context = cipher_ctx;
	} else {
		if (cipher_ctx) {
			free_cipher_context(cipher_ctx);
			SMW_UTILS_FREE(cipher_ctx);
		}
	}

	// coverity[missing_unlock]
	return status;
}

static int cipher_init(struct subsystem_context *ele_ctx,
		       struct smw_op_context *op_context,
		       struct smw_crypto_cipher_args *cipher_args)
{
	int status = SMW_STATUS_OK;
	op_cipher_args_t op_args = { 0 };
	struct cipher_context *cipher_ctx = NULL;
	struct smw_keymgr_descriptor *key_desc = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	key_desc = cipher_args->keys_desc[0];

	status = ele_get_device_info(ele_ctx);
	if (status != SMW_STATUS_OK)
		return status;

	if (!ele_ctx->info.cipher_multipart)
		return SMW_STATUS_OPERATION_NOT_SUPPORTED;

	status = set_cipher_key(cipher_args, &op_args);
	if (status != SMW_STATUS_OK)
		goto end;

	status =
		ele_set_cipher_algo(key_desc->identifier.type_id,
				    cipher_args->mode_id, &op_args.cipher_algo);
	if (status != SMW_STATUS_OK)
		goto end;

	op_args.iv = smw_crypto_get_cipher_iv(cipher_args);
	if (SET_OVERFLOW(smw_crypto_get_cipher_iv_len(cipher_args),
			 op_args.iv_size)) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	set_cipher_flags(cipher_args, cipher_args->op_type_id, &op_args.flags);

	status = cipher_setup_context(ele_ctx, op_context, cipher_args,
				      &op_args);
	if (status != SMW_STATUS_OK)
		goto end;

	cipher_ctx = op_context->subsystem_context;

	status = do_cipher_multi_part(cipher_ctx, &op_args);
	if (status == SMW_STATUS_OK)
		op_context->op_state = CTX_OP_STATE_INIT;

end:
	if (key_desc->format_id == SMW_KEYMGR_FORMAT_ID_BASE64 && op_args.key)
		SMW_UTILS_FREE(op_args.key);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int cipher_update_common(struct cipher_context *cipher_ctx,
				struct smw_crypto_cipher_args *cipher_args,
				unsigned int *bytes_written,
				unsigned int *expected_output_len,
				bool is_implicit_update)
{
	int status = SMW_STATUS_OK;
	op_cipher_args_t op_args = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (bytes_written)
		*bytes_written = 0;

	if (expected_output_len)
		*expected_output_len = 0;

	op_args.input = smw_crypto_get_cipher_input(cipher_args);
	op_args.input_size = smw_crypto_get_cipher_input_len(cipher_args);
	op_args.output = smw_crypto_get_cipher_output(cipher_args);
	op_args.output_size = smw_crypto_get_cipher_output_len(cipher_args);

	set_cipher_flags(cipher_args, cipher_ctx->op_type_id, &op_args.flags);

	status = do_cipher_multi_part(cipher_ctx, &op_args);
	if (status == SMW_STATUS_OUTPUT_TOO_SHORT) {
		if (expected_output_len) {
			/*
			 * For implicit UPDATE (before FINAL):
			 * Use input_size to calculate total expected output for FINAL.
			 * exp_output_size returns only immediate UPDATE output
			 * (e.g., 16 bytes for 24 bytes input), ignoring buffered data.
			 *
			 * For explicit UPDATE:
			 * Use exp_output_size as returned by ELE.
			 */
			if (is_implicit_update)
				*expected_output_len = op_args.input_size;
			else
				*expected_output_len = op_args.exp_output_size;
		}

		goto end;
	} else if (status != SMW_STATUS_OK) {
		goto end;
	}

	if (bytes_written) {
		if (SET_OVERFLOW(op_args.exp_output_size, *bytes_written)) {
			status = SMW_STATUS_OPERATION_FAILURE;
			goto end;
		}
	}

	if (!is_implicit_update) {
		smw_crypto_set_cipher_output_len(cipher_args,
						 op_args.exp_output_size);
	}

	status = ele_update_buffered_len(&cipher_ctx->remaining_buffered_len,
					 op_args.input_size,
					 op_args.exp_output_size);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int update_before_final(struct cipher_context *cipher_ctx,
			       struct smw_crypto_cipher_args *cipher_args,
			       unsigned int *bytes_written,
			       unsigned int *expected_output_len)
{
	int status = SMW_STATUS_OK;

	SMW_DBG_TRACE_FUNCTION_CALL;

	cipher_args->op_step = SMW_OP_STEP_UPDATE;

	status = cipher_update_common(cipher_ctx, cipher_args, bytes_written,
				      expected_output_len, true);

	cipher_args->op_step = SMW_OP_STEP_FINAL;

	return status;
}

static int cipher_update(struct smw_op_context *op_context,
			 struct smw_crypto_cipher_args *cipher_args)
{
	int status = SMW_STATUS_INVALID_PARAM;
	int tmp_status = SMW_STATUS_OK;
	struct cipher_context *cipher_ctx = NULL;
	unsigned int expected_output = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	cipher_ctx = op_context->subsystem_context;
	if (!cipher_ctx)
		goto end;

	/* Get output length feature */
	if (!smw_crypto_get_cipher_output(cipher_args)) {
		status = set_output_length(cipher_args, cipher_ctx);
		goto end;
	}

	status = cipher_update_common(cipher_ctx, cipher_args, NULL,
				      &expected_output, false);

	if (status == SMW_STATUS_OUTPUT_TOO_SHORT) {
		tmp_status = set_expected_output_length(cipher_args, cipher_ctx,
							expected_output, 0);
		if (tmp_status != SMW_STATUS_OK)
			status = tmp_status;
	}

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int cipher_final(struct smw_op_context *op_context,
			struct smw_crypto_cipher_args *cipher_args)
{
	int status = SMW_STATUS_INVALID_PARAM;
	int tmp_status = SMW_STATUS_OK;
	struct cipher_context *cipher_ctx = NULL;
	op_cipher_args_t op_args = { 0 };
	unsigned int update_output_offset = 0;
	unsigned int implicit_update_exp_output = 0;
	bool implicit_update_done = false;
	unsigned char *base_output = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	cipher_ctx = op_context->subsystem_context;
	if (!cipher_ctx)
		goto end;

	if (!smw_crypto_get_cipher_output(cipher_args)) {
		status = set_output_length(cipher_args, cipher_ctx);
		goto end;
	}

	if (smw_crypto_get_cipher_input_len(cipher_args)) {
		SMW_DBG_PRINTF(DEBUG,
			       "Final with input: performing update first\n");

		status = update_before_final(cipher_ctx, cipher_args,
					     &update_output_offset,
					     &implicit_update_exp_output);
		if (status != SMW_STATUS_OK)
			goto set_length_and_exit;

		implicit_update_done = true;

		SMW_DBG_PRINTF(DEBUG, "Final output will write at offset %u\n",
			       update_output_offset);
	}

	base_output = smw_crypto_get_cipher_output(cipher_args);
	op_args.output = base_output;
	op_args.output_size = smw_crypto_get_cipher_output_len(cipher_args);

	/* Set the output offset for final operation after implicit update */
	if (implicit_update_done && base_output) {
		op_args.output = base_output + update_output_offset;

		if (DEC_OVERFLOW(op_args.output_size, update_output_offset)) {
			status = SMW_STATUS_OUTPUT_TOO_SHORT;
			goto set_length_and_exit;
		}
	}

	/* For final after update, clear input (already processed) */
	if (implicit_update_done) {
		op_args.input = NULL;
		op_args.input_size = 0;
	} else {
		op_args.input = smw_crypto_get_cipher_input(cipher_args);
		op_args.input_size =
			smw_crypto_get_cipher_input_len(cipher_args);
	}

	set_cipher_flags(cipher_args, cipher_ctx->op_type_id, &op_args.flags);

	status = do_cipher_multi_part(cipher_ctx, &op_args);
	if (status != SMW_STATUS_OK)
		goto set_length_and_exit;

	if (INC_OVERFLOW(op_args.exp_output_size, update_output_offset)) {
		status = SMW_STATUS_OPERATION_FAILURE;
		goto end;
	}

	smw_crypto_set_cipher_output_len(cipher_args, op_args.exp_output_size);

set_length_and_exit:
	if (status == SMW_STATUS_OUTPUT_TOO_SHORT) {
		tmp_status =
			set_expected_output_length(cipher_args, cipher_ctx,
						   op_args.exp_output_size,
						   implicit_update_exp_output);
		if (tmp_status != SMW_STATUS_OK)
			status = tmp_status;
	}

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int cipher_multi_part(struct subsystem_context *ele_ctx, void *args)
{
	int status = SMW_STATUS_INVALID_PARAM;
	struct smw_crypto_cipher_args *cipher_args = args;
	struct smw_op_context *op_context = NULL;

	switch (cipher_args->op_step) {
	case SMW_OP_STEP_INIT:
		op_context = smw_crypto_get_cipher_init_op_context(cipher_args);
		if (!op_context)
			goto end;

		status = cipher_init(ele_ctx, op_context, cipher_args);
		break;

	case SMW_OP_STEP_UPDATE:
		op_context = smw_crypto_get_cipher_data_op_context(cipher_args);
		if (!op_context)
			goto end;

		status = cipher_update(op_context, cipher_args);
		break;

	case SMW_OP_STEP_FINAL:
		op_context = smw_crypto_get_cipher_data_op_context(cipher_args);
		if (!op_context)
			goto end;

		status = cipher_final(op_context, cipher_args);
		break;

	default:
		break;
	}

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

void ele_free_cipher_context(struct smw_op_context *ctx)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!ctx)
		return;

	free_cipher_context(ctx->subsystem_context);
}

int ele_copy_cipher_context(struct smw_op_context *src_ctx,
			    struct smw_op_context *dst_ctx)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	struct cipher_context *src_cipher_ctx = NULL;
	struct cipher_context *dst_cipher_ctx = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!src_ctx || !src_ctx->subsystem_context || !dst_ctx)
		goto end;

	src_cipher_ctx = src_ctx->subsystem_context;
	if (!src_cipher_ctx)
		goto end;

	if (src_cipher_ctx->opaque_key) {
		SMW_DBG_PRINTF(ERROR,
			       "Cannot copy cipher context with opaque key");
		goto end;
	}

	dst_cipher_ctx = SMW_UTILS_CALLOC(1, sizeof(*dst_cipher_ctx));
	if (!dst_cipher_ctx) {
		status = SMW_STATUS_ALLOC_FAILURE;
		goto end;
	}

	dst_cipher_ctx->cipher_hdl = 0;
	dst_cipher_ctx->hdl = src_cipher_ctx->hdl;
	dst_cipher_ctx->ele_cipher_algo = src_cipher_ctx->ele_cipher_algo;
	dst_cipher_ctx->op_type_id = src_cipher_ctx->op_type_id;
	dst_cipher_ctx->opaque_key = src_cipher_ctx->opaque_key;
	dst_cipher_ctx->remaining_buffered_len =
		src_cipher_ctx->remaining_buffered_len;
	dst_cipher_ctx->ele_context_size = src_cipher_ctx->ele_context_size;

	if (src_cipher_ctx->ele_context_size && src_cipher_ctx->ele_context) {
		dst_cipher_ctx->ele_context =
			SMW_UTILS_MALLOC(src_cipher_ctx->ele_context_size);
		if (!dst_cipher_ctx->ele_context) {
			status = SMW_STATUS_ALLOC_FAILURE;
			goto end;
		}

		SMW_UTILS_MEMCPY(dst_cipher_ctx->ele_context,
				 src_cipher_ctx->ele_context,
				 src_cipher_ctx->ele_context_size);
	}

	dst_ctx->subsystem_context = dst_cipher_ctx;

	status = SMW_STATUS_OK;

end:
	if (status != SMW_STATUS_OK) {
		if (dst_cipher_ctx) {
			if (dst_cipher_ctx->ele_context)
				SMW_UTILS_FREE(dst_cipher_ctx->ele_context);

			(void)close_cipher_service(dst_cipher_ctx->cipher_hdl);

			SMW_UTILS_FREE(dst_cipher_ctx);
		}
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int ele_cancel_cipher_operation(struct smw_op_context *ctx)
{
	int status = SMW_STATUS_INVALID_PARAM;

	SMW_DBG_TRACE_FUNCTION_CALL;

	op_cipher_args_t op_args = { 0 };
	struct cipher_context *cipher_ctx = ctx->subsystem_context;

	if (!cipher_ctx)
		goto end;

	op_args.flags = HSM_CIPHER_FLAGS_ABORT;

	status = do_cipher_multi_part(cipher_ctx, &op_args);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

bool ele_cipher_handle(struct subsystem_context *ele_ctx,
		       enum operation_id operation_id, void *args, int *status)
{
	switch (operation_id) {
	case OPERATION_ID_CIPHER:
		*status = cipher(&ele_ctx->hdl, args);
		break;

	case OPERATION_ID_CIPHER_MULTI_PART:
		*status = cipher_multi_part(ele_ctx, args);
		break;

	default:
		return false;
	}

	// coverity[missing_unlock]
	return true;
}
