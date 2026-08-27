// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include "smw_status.h"
#include "smw_crypto.h"

#include "compiler.h"
#include "utils.h"
#include "config.h"
#include "keymgr.h"
#include "aead.h"
#include "local.h"

#define ELA_IV_LEN  12
#define ELA_TAG_LEN 16

#define AEAD_ALGO(_key_type_id, _aead_mode_id)                                 \
	{                                                                      \
		.key_type_id = SMW_CONFIG_KEY_TYPE_ID_##_key_type_id,          \
		.aead_mode_id = SMW_CONFIG_AEAD_MODE_ID_##_aead_mode_id,       \
		.aead_algo = CRYPTO_AEAD_AES_##_aead_mode_id                   \
	}

static const struct {
	enum smw_config_key_type_id key_type_id;
	enum smw_config_aead_mode_id aead_mode_id;
	enum crypto_aead_algorithm aead_algo;
} aead_algos[] = { AEAD_ALGO(AES, GCM) };

static int ela_set_aead_algo(enum smw_config_key_type_id key_type_id,
			     enum smw_config_aead_mode_id aead_mode_id,
			     enum crypto_aead_algorithm *aead_algo)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
	unsigned int i = 0;

	for (; i < ARRAY_SIZE(aead_algos); i++) {
		if (key_type_id == aead_algos[i].key_type_id &&
		    aead_mode_id == aead_algos[i].aead_mode_id) {
			*aead_algo = aead_algos[i].aead_algo;
			status = SMW_STATUS_OK;
			break;
		}
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * use_ela() - Check if ELA should handle this AEAD operation
 * @aead_args: AEAD arguments
 *
 * This function checks if:
 * 1. ELA is enabled in configuration for AEAD
 * 2. The key is a plaintext buffer (not opaque)
 *
 * Return:
 * true  - ELA should handle this operation
 * false - Use standard ELE operations
 */
static bool use_ela(struct smw_crypto_aead_args *aead_args)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	/*
	 * Check if "USE_ELA" tag is set in the config file.
	 * If not defined, ELA crypto isn't enabled.
	 * Use standard ELE operations.
	 */
	if (!aead_is_ela_enabled(SUBSYSTEM_ID_ELE))
		return false;

	/*
	 * ELA is used for plaintext key buffer.
	 * For opaque key, use standard ELE operations.
	 */
	if (!smw_utils_key_buffer_set(&aead_args->key_desc)) {
		SMW_DBG_PRINTF(DEBUG,
			       "AEAD op not handled by ELA (opaque key)\n");
		return false;
	}

	return true;
}

static void set_all_outputs_length(struct smw_crypto_aead_args *args,
				   unsigned int output_len)
{
	if (args->op_type_id == SMW_CONFIG_AEAD_OP_TYPE_ID_ENCRYPT) {
		smw_crypto_set_aead_output_iv_len(args, ELA_IV_LEN);
		smw_crypto_set_aead_tag_len(args, ELA_TAG_LEN);
	}

	smw_crypto_set_aead_output_len(args, output_len);
}

static int set_output_length(struct smw_crypto_aead_args *aead_args)
{
	int status = SMW_STATUS_INVALID_PARAM;

	unsigned int output_len = smw_crypto_get_aead_input_len(aead_args);

	if (aead_args->op_type_id == SMW_CONFIG_AEAD_OP_TYPE_ID_ENCRYPT) {
		if (!smw_crypto_is_aead_tag_field_set(aead_args)) {
			if (INC_OVERFLOW(output_len, ELA_TAG_LEN))
				goto end;
		}

	} else {
		if (!smw_crypto_is_aead_tag_field_set(aead_args)) {
			if (DEC_OVERFLOW(output_len, ELA_TAG_LEN))
				goto end;
		}
	}

	status = SMW_STATUS_OK;

	set_all_outputs_length(aead_args, output_len);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned with output length = %u\n",
		       __func__, output_len);
	return status;
}

/**
 * calculate_aead_memory_size() - Calculate required memory size for AEAD op
 * @aead_args: AEAD arguments
 * @required_size: Required memory size for AEAD operation in bytes
 *
 * Return:
 * SMW_STATUS_OK            - Success
 * SMW_STATUS_INVALID_PARAM - Invalid argument parameter
 */
static int calculate_aead_memory_size(struct smw_crypto_aead_args *aead_args,
				      uint32_t *required_size)
{
	int status = SMW_STATUS_OK;

	unsigned int input_len = 0;
	unsigned int output_len = 0;
	unsigned int aad_len = smw_crypto_get_aead_aad_len(aead_args);
	unsigned int tag_len = ELA_TAG_LEN;
	uint32_t status_buf_len = sizeof(status_buf_t);
	uint32_t size = 0;
	uint32_t aligned_size = 0;

	status = smw_utils_get_aead_input_data_len(aead_args, &input_len);
	if (status != SMW_STATUS_OK)
		goto end;

	/* Input buffer (aligned to 64 bytes) */
	status = smw_utils_align_value(input_len, ELA_BUFFER_ALIGN_SIZE, &size);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_utils_get_aead_output_data_len(aead_args, &output_len);
	if (status != SMW_STATUS_OK)
		goto end;

	/* Output buffer (aligned to 64 bytes) */
	status = smw_utils_align_value(output_len, ELA_BUFFER_ALIGN_SIZE,
				       &aligned_size);
	if (status != SMW_STATUS_OK)
		goto end;

	if (ADD_OVERFLOW(size, aligned_size, &size)) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	/* AAD buffer (aligned to 64 bytes) if present */
	if (aad_len > 0) {
		status = smw_utils_align_value(aad_len, ELA_BUFFER_ALIGN_SIZE,
					       &aligned_size);
		if (status != SMW_STATUS_OK)
			goto end;

		if (ADD_OVERFLOW(size, aligned_size, &size)) {
			status = SMW_STATUS_INVALID_PARAM;
			goto end;
		}
	}

	/* Tag buffer (aligned to 64 bytes) */
	status = smw_utils_align_value(tag_len, ELA_BUFFER_ALIGN_SIZE,
				       &aligned_size);
	if (status != SMW_STATUS_OK)
		goto end;

	if (ADD_OVERFLOW(size, aligned_size, &size)) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	/* Status buffer (aligned to 64 bytes) */
	status = smw_utils_align_value(status_buf_len, ELA_BUFFER_ALIGN_SIZE,
				       &aligned_size);
	if (status != SMW_STATUS_OK)
		goto end;

	if (ADD_OVERFLOW(size, aligned_size, &size)) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	*required_size = size;

	SMW_DBG_PRINTF(DEBUG,
		       "AEAD memory calculation:\n"
		       "  input_len: %u\n"
		       "  output_len: %u\n"
		       "  aad_len: %u\n"
		       "  tag_len: %u\n"
		       "  status_buf_len: %u\n"
		       "  total_size: %u\n",
		       input_len, output_len, aad_len, tag_len, status_buf_len,
		       size);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * setup_aead_op_params() - Set aead operation parameters
 * @op: Crypto operation structure
 * @aead_args: SMW aead arguments
 * @keyslot: Key slot number
 * @algo: Prime aead algorithm
 * @ctx: ELA context
 *
 * Return:
 * SMW_STATUS_OK - Success
 * Error code otherwise
 */
static int setup_aead_op_params(crypto_op_args_t *op,
				struct smw_crypto_aead_args *aead_args,
				uint8_t keyslot,
				enum crypto_aead_algorithm algo,
				struct ela_context *ctx)
{
	int status = SMW_STATUS_INVALID_PARAM;

	uint8_t *input_data = smw_crypto_get_aead_input(aead_args);
	uint32_t aad_len = smw_crypto_get_aead_aad_len(aead_args);
	uint8_t *aad = smw_crypto_get_aead_aad(aead_args);
	uint8_t *tag = smw_crypto_get_aead_tag(aead_args);
	uint32_t offset = 0;
	unsigned int output_len = 0;
	unsigned int tag_len = smw_crypto_get_aead_tag_len(aead_args);
	uint32_t unaligned_offset = 0;
	uint64_t phys_addr_offset = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!tag || !tag_len) {
		SMW_DBG_PRINTF(ERROR, "Tag buffer or length not set\n");
		goto end;
	}

	if (!ctx->virtual_addr || !ctx->physical_addr) {
		SMW_DBG_PRINTF(ERROR, "Invalid ELA context addresses\n");
		goto end;
	}

	status = smw_utils_get_aead_input_data_len(aead_args, &op->src.len);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_utils_get_aead_output_data_len(aead_args, &output_len);
	if (status != SMW_STATUS_OK)
		goto end;

	/* Set source buffer */
	op->src.virt_addr = (uint8_t *)ctx->virtual_addr;
	op->src.phys_addr = ctx->physical_addr;

	/* Copy input data to ELA memory */
	SMW_UTILS_MEMCPY(op->src.virt_addr, input_data, op->src.len);
	/* Clean cache for input buffer */
	smw_utils_dcache_clean(op->src.virt_addr, op->src.len);

	status = smw_utils_align_value(op->src.len, ELA_BUFFER_ALIGN_SIZE,
				       &offset);
	if (status != SMW_STATUS_OK)
		goto end;

	/* Set dest buffer */
	op->dst.len = output_len;
	op->dst.virt_addr = op->src.virt_addr + offset;
	if (ADD_OVERFLOW(op->src.phys_addr, offset, &phys_addr_offset)) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	op->dst.phys_addr = phys_addr_offset;

	if (ADD_OVERFLOW(offset, output_len, &unaligned_offset)) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	status = smw_utils_align_value(unaligned_offset, ELA_BUFFER_ALIGN_SIZE,
				       &offset);
	if (status != SMW_STATUS_OK)
		goto end;

	/* Set AAD buffer */
	if (aad && aad_len) {
		op->op_aead_args.aad.virt_addr = op->src.virt_addr + offset;

		if (ADD_OVERFLOW(op->src.phys_addr, offset,
				 &phys_addr_offset)) {
			status = SMW_STATUS_INVALID_PARAM;
			goto end;
		}

		op->op_aead_args.aad.phys_addr = phys_addr_offset;
		op->op_aead_args.aad.len = aad_len;

		/* Copy AAD data to ELA memory */
		SMW_UTILS_MEMCPY(op->op_aead_args.aad.virt_addr, aad, aad_len);

		/* Clean cache for AAD buffer */
		smw_utils_dcache_clean(op->op_aead_args.aad.virt_addr, aad_len);

		if (ADD_OVERFLOW(offset, aad_len, &unaligned_offset)) {
			status = SMW_STATUS_INVALID_PARAM;
			goto end;
		}

		/* Update offset for next buffer - Only if AAD exists */
		status = smw_utils_align_value(unaligned_offset,
					       ELA_BUFFER_ALIGN_SIZE, &offset);
		if (status != SMW_STATUS_OK)
			goto end;
	} else {
		op->op_aead_args.aad.virt_addr = NULL;
		op->op_aead_args.aad.phys_addr = 0;
		op->op_aead_args.aad.len = 0;
	}

	/* allocate tag buffer from reserved memory */
	op->op_aead_args.tag.len = tag_len;
	op->op_aead_args.tag.virt_addr = op->src.virt_addr + offset;

	if (ADD_OVERFLOW(op->src.phys_addr, offset, &phys_addr_offset)) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	op->op_aead_args.tag.phys_addr = phys_addr_offset;

	if (aead_args->op_type_id == SMW_CONFIG_AEAD_OP_TYPE_ID_DECRYPT) {
		/* Copy TAG data to ELA memory for decryption */
		SMW_UTILS_MEMCPY(op->op_aead_args.tag.virt_addr,
				 smw_crypto_get_aead_tag(aead_args), tag_len);

		/* Clean cache for TAG buffer */
		smw_utils_dcache_clean(op->op_aead_args.tag.virt_addr, tag_len);
	}

	/* Set operation type */
	op->op_type = CRYPTO_OP_TYPE_AEAD;

	/* Set aead parameters */
	op->op_aead_args.algo = algo;
	op->op_aead_args.keyslot = keyslot;

	if (aead_args->op_type_id == SMW_CONFIG_AEAD_OP_TYPE_ID_ENCRYPT)
		op->op_aead_args.enc = 1;
	else
		op->op_aead_args.enc = 0;

	op->op_aead_args.iv = smw_crypto_get_aead_user_iv(aead_args);

	if (SET_OVERFLOW(smw_crypto_get_aead_user_iv_len(aead_args),
			 op->op_aead_args.ivlen)) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	if (ADD_OVERFLOW(offset, tag_len, &unaligned_offset)) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	/* Set status buffer (aligned after tag) */
	status = smw_utils_align_value(unaligned_offset, ELA_BUFFER_ALIGN_SIZE,
				       &offset);
	if (status != SMW_STATUS_OK)
		goto end;

	op->crypto_status.phys_addr =
		(status_buf_t *)(op->src.phys_addr + offset);
	op->crypto_status.virt_addr =
		(status_buf_t *)(op->src.virt_addr + offset);

	SMW_DBG_PRINTF(DEBUG,
		       "aead operation prepared:\n"
		       " algo: %d\n"
		       " keyslot: %u\n"
		       " input_len: %u\n"
		       " iv_len: %u\n"
		       " aad_len: %u\n",
		       algo, keyslot, op->src.len, op->op_aead_args.ivlen,
		       aad_len);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * retrieve_aead_output() - Complete aead operation
 * @op: AEAD operation structure
 * @aead_args: SMW aead arguments
 *
 * Return:
 * SMW_STATUS_OK - Success
 */
static int retrieve_aead_output(crypto_op_args_t *op,
				struct smw_crypto_aead_args *aead_args)
{
	int status = SMW_STATUS_INVALID_PARAM;

	unsigned char *output_data = smw_crypto_get_aead_output(aead_args);
	unsigned int output_len = 0;
	unsigned char *output_iv = smw_crypto_get_aead_output_iv(aead_args);
	unsigned char *iv = smw_crypto_get_aead_user_iv(aead_args);
	unsigned char *tag = smw_crypto_get_aead_tag(aead_args);

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!op->dst.virt_addr || !op->op_aead_args.tag.virt_addr ||
	    !op->crypto_status.virt_addr) {
		SMW_DBG_PRINTF(ERROR, "Invalid operation buffers\n");
		goto end;
	}

	if (!output_data)
		goto end;

	/* Clean and invalidate cache for crypto_status buffer */
	smw_utils_dcache_invalidate((uint8_t *)op->crypto_status.virt_addr,
				    sizeof(status_buf_t));

	status = convert_fce_status(op->crypto_status.virt_addr->status_code,
				    op->crypto_status.virt_addr->error_info);
	if (status != SMW_STATUS_OK)
		goto end;

	output_len = op->dst.len;

	/* Clean and invalidate cache for output buffer */
	smw_utils_dcache_invalidate(op->dst.virt_addr, op->dst.len);
	/* Copy output data from shared memory */
	SMW_UTILS_MEMCPY(output_data, op->dst.virt_addr, op->dst.len);

	if (aead_args->op_type_id == SMW_CONFIG_AEAD_OP_TYPE_ID_ENCRYPT) {
		if (!tag) {
			status = SMW_STATUS_INVALID_PARAM;
			goto end;
		}

		/* Clean and invalidate cache for tag buffer */
		smw_utils_dcache_invalidate(op->op_aead_args.tag.virt_addr,
					    op->op_aead_args.tag.len);

		/* Copy tag from ELA memory to tag buffer */
		SMW_UTILS_MEMCPY(smw_crypto_get_aead_tag(aead_args),
				 op->op_aead_args.tag.virt_addr,
				 op->op_aead_args.tag.len);

		if (!smw_crypto_is_aead_tag_field_set(aead_args)) {
			if (INC_OVERFLOW(output_len, ELA_TAG_LEN)) {
				status = SMW_STATUS_OPERATION_FAILURE;
				goto end;
			}
		}

		/* Copy user provided IV buffer to output_iv field. */
		if (output_iv && iv)
			SMW_UTILS_MEMCPY(output_iv, iv, ELA_IV_LEN);
	}

	set_all_outputs_length(aead_args, output_len);

	status = SMW_STATUS_OK;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * ela_aead_one_shot() - Execute AEAD one-shot operation
 * @aead_args: AEAD arguments
 *
 * Return:
 * SMW_STATUS_OK - Success
 * Error code otherwise
 */
static int ela_aead_one_shot(struct smw_crypto_aead_args *aead_args)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
	prime_err_t err = PRIME_ERR_NONE;

	struct smw_keymgr_descriptor *key_desc = &aead_args->key_desc;
	crypto_op_args_t op = { 0 };
	crypto_op_args_t *ops_ptr = &op;
	uint32_t nb_ops = 1;
	enum crypto_aead_algorithm algo = 0;

	uint8_t keyslot = 0;
	struct ela_context *ctx = NULL;
	uint32_t memory_size = 0;
	unsigned int input_len = 0;
	unsigned int output_len = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	/* ELA requires the IV size of 12 Bytes */
	if (smw_crypto_get_aead_user_iv_len(aead_args) != ELA_IV_LEN) {
		SMW_DBG_PRINTF(DEBUG,
			       "ELA requires the IV size of 12 Bytes.\n");
		goto end;
	}

	/* Currently ELA requires non-NULL AAD with length multiple of 16 bytes */
	if (!smw_crypto_get_aead_aad(aead_args) ||
	    !smw_crypto_get_aead_aad_len(aead_args) ||
	    (smw_crypto_get_aead_aad_len(aead_args) % 16 != 0)) {
		SMW_DBG_PRINTF(DEBUG, "ELA: Unsupported AAD params.\n");
		goto end;
	}

	/*
	 * For ELA, tag length must be 16 Bytes.
	 * For encryption operation, if tag length < ELA_TAG_LEN, set the required
	 * output buffer lengths and return SMW_STATUS_OUTPUT_TOO_SHORT.
	 */
	if (smw_crypto_get_aead_tag_len(aead_args) < ELA_TAG_LEN) {
		status = set_output_length(aead_args);
		if (status == SMW_STATUS_OK)
			status = SMW_STATUS_OUTPUT_TOO_SHORT;

		goto end;
	}

	/* Get aead algorithm using lookup table */
	status = ela_set_aead_algo(key_desc->identifier.type_id,
				   aead_args->mode_id, &algo);
	if (status != SMW_STATUS_OK)
		goto end;

	/* Get output length feature */
	if (!smw_crypto_get_aead_output(aead_args)) {
		status = set_output_length(aead_args);
		goto end;
	}

	status = smw_utils_get_aead_output_data_len(aead_args, &output_len);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_utils_get_aead_input_data_len(aead_args, &input_len);
	if (status != SMW_STATUS_OK)
		goto end;

	/* Check if output buffer length is sufficient */
	if (output_len < input_len) {
		status = set_output_length(aead_args);
		if (status == SMW_STATUS_OK)
			status = SMW_STATUS_OUTPUT_TOO_SHORT;

		goto end;
	}

	/* Calculate total memory needed for this operation with proper alignment */
	status = calculate_aead_memory_size(aead_args, &memory_size);
	if (status != SMW_STATUS_OK)
		goto end;

	/* Load ELA service with calculated memory size */
	status = ela_open_service(memory_size);
	if (status != SMW_STATUS_OK) {
		SMW_DBG_PRINTF(ERROR, "Failed to load ELA: %d\n", status);
		goto cleanup;
	}

	/* Get ELA context */
	ctx = ela_get_context();
	if (!ctx || !ctx->service_hdl || !ctx->virtual_addr ||
	    !ctx->physical_addr) {
		SMW_DBG_PRINTF(ERROR, "Invalid ELA context\n");
		status = SMW_STATUS_SUBSYSTEM_FAILURE;
		goto cleanup;
	}

	/* Load AES key into ELA key slot */
	status = ela_load_aes_key(ctx->service_hdl, key_desc, &keyslot);
	if (status != SMW_STATUS_OK)
		goto cleanup;

	status = setup_aead_op_params(ops_ptr, aead_args, keyslot, algo, ctx);
	if (status != SMW_STATUS_OK)
		goto cleanup;

	/* Execute AEAD operation */
	err = prime_process_ops(ctx->service_hdl, &ops_ptr, nb_ops);
	if (err != PRIME_ERR_NONE) {
		SMW_DBG_PRINTF(ERROR, "prime_process_ops failed: %d\n", err);
		status = convert_ela_err(err);
		goto cleanup;
	}

	SMW_DBG_PRINTF(DEBUG, "prime_process_ops completed\n");

	/* Retrieve output and copy IV */
	status = retrieve_aead_output(&op, aead_args);

cleanup:
	/* Close ELA service after operation */
	ela_close_service();

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

bool ela_aead_handle(enum operation_id operation_id, void *args, int *status)
{
	bool op_handled = false;
	int tmp_status = SMW_STATUS_OK;

	struct smw_crypto_aead_args *aead_args = args;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (operation_id != OPERATION_ID_AEAD)
		goto end;

	/* Check if ELA should handle this operation */
	if (!use_ela(aead_args))
		goto end;

	tmp_status = ela_aead_one_shot(args);

	/*
	 * If the status is not SMW_STATUS_OPERATION_NOT_SUPPORTED, it means ELA
	 * attempted to handle the operation, so return true to indicate
	 * the operation was handled (successfully or not).
	 * If the status is SMW_STATUS_OPERATION_NOT_SUPPORTED, redirect the
	 * operation to ELE.
	 */
	if (tmp_status != SMW_STATUS_OPERATION_NOT_SUPPORTED) {
		op_handled = true;
		*status = tmp_status;
	}

end:
	SMW_DBG_PRINTF(VERBOSE, "%s: Operation %d %s by ELA\n", __func__,
		       operation_id, op_handled ? "handled" : "not handled");

	return op_handled;
}
