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
#include "cipher.h"

#include "local.h"

#define CIPHER_ALGO(_key_type_id, _cipher_mode_id)                             \
	{                                                                      \
		.key_type_id = SMW_CONFIG_KEY_TYPE_ID_##_key_type_id,          \
		.cipher_mode_id = SMW_CONFIG_CIPHER_MODE_ID_##_cipher_mode_id, \
		.cipher_algo = CRYPTO_CIPHER_AES_##_cipher_mode_id             \
	}

static const struct {
	enum smw_config_key_type_id key_type_id;
	enum smw_config_cipher_mode_id cipher_mode_id;
	enum crypto_cipher_algorithm cipher_algo;
} cipher_algos[] = {
	CIPHER_ALGO(AES, CBC),
	CIPHER_ALGO(AES, CTR),
	CIPHER_ALGO(AES, ECB),
};

static int ela_set_cipher_algo(enum smw_config_key_type_id key_type_id,
			       enum smw_config_cipher_mode_id cipher_mode_id,
			       enum crypto_cipher_algorithm *cipher_algo)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
	unsigned int i = 0;

	for (; i < ARRAY_SIZE(cipher_algos); i++) {
		if (key_type_id == cipher_algos[i].key_type_id &&
		    cipher_mode_id == cipher_algos[i].cipher_mode_id) {
			*cipher_algo = cipher_algos[i].cipher_algo;
			status = SMW_STATUS_OK;
			break;
		}
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * use_ela() - Check if ELA should handle this cipher operation
 * @cipher_args: Cipher arguments
 *
 * This function checks if:
 * 1. ELA is enabled in config file for cipher operation
 * 2. The key is a plaintext buffer
 *
 * Return:
 * true  - ELA should handle this operation
 * false - Use standard ELE operations
 */
static bool use_ela(struct smw_crypto_cipher_args *cipher_args)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	/*
	 * Check if "USE_ELA" tag is set in the config file.
	 * If not defined, ELA crypto isn't enabled.
	 * Use standard ELE operations.
	 */
	if (!cipher_is_ela_enabled(SUBSYSTEM_ID_ELE))
		return false;

	/*
	 * ELA is used for plaintext key buffer.
	 * For opaque key, use standard ELE operations.
	 */
	if (!smw_utils_key_buffer_set(cipher_args->keys_desc[0])) {
		SMW_DBG_PRINTF(DEBUG,
			       "Cipher not handled by ELA (opaque key)\n");
		return false;
	}

	return true;
}

/**
 * calculate_cipher_memory_size() - Calculate required memory size for cipher op
 * @cipher_args: Cipher arguments
 * @required_size: Required memory size for cipher operation in bytes
 *
 * Return:
 * SMW_STATUS_OK            - Success
 * SMW_STATUS_INVALID_PARAM - Invalid argument parameter
 */
static int
calculate_cipher_memory_size(struct smw_crypto_cipher_args *cipher_args,
			     uint32_t *required_size)
{
	int status = SMW_STATUS_OK;

	uint32_t size = 0;
	uint32_t aligned_size = 0;
	unsigned int input_len = smw_crypto_get_cipher_input_len(cipher_args);
	unsigned int output_len = input_len;
	uint32_t status_buf_len = sizeof(status_buf_t);

	/* Input buffer (aligned to 64 bytes) */
	status = smw_utils_align_value(input_len, ELA_BUFFER_ALIGN_SIZE, &size);
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
		       "Cipher memory calculation:\n"
		       "  input_len: %u\n"
		       "  output_len: %u\n"
		       "  status_buf_len: %u\n"
		       "  total_size: %u\n",
		       input_len, output_len, status_buf_len, size);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * set_cipher_op_params() - Prepare cipher operation
 * @op: Cipher operation structure
 * @cipher_args: SMW cipher arguments
 * @keyslot: Key slot number
 * @algo: Prime cipher algorithm
 * @ctx: ELA context
 *
 * Return:
 * SMW_STATUS_OK - Success
 * Error code otherwise
 */
static int set_cipher_op_params(crypto_op_args_t *op,
				struct smw_crypto_cipher_args *cipher_args,
				uint8_t keyslot,
				enum crypto_cipher_algorithm algo,
				struct ela_context *ctx)
{
	int status = SMW_STATUS_INVALID_PARAM;

	unsigned int input_len = smw_crypto_get_cipher_input_len(cipher_args);
	unsigned char *input_data = smw_crypto_get_cipher_input(cipher_args);
	uint32_t offset = 0;
	uint32_t status_offset = 0;
	uint64_t phys_addr_offset = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!ctx->virtual_addr || !ctx->physical_addr) {
		SMW_DBG_PRINTF(ERROR, "Invalid ELA context addresses\n");
		goto end;
	}

	if (!input_data || input_len == 0) {
		SMW_DBG_PRINTF(ERROR, "Invalid input data or length\n");
		goto end;
	}

	/* Set source buffer */
	op->src.len = input_len;
	op->src.virt_addr = (uint8_t *)ctx->virtual_addr;
	op->src.phys_addr = ctx->physical_addr;

	/* Copy input data to ELA memory */
	SMW_UTILS_MEMCPY(op->src.virt_addr, input_data, input_len);
	/* Clean cache for input buffer */
	smw_utils_dcache_clean(op->src.virt_addr, input_len);

	/* Set destination buffer */
	status = smw_utils_align_value(op->src.len, ELA_BUFFER_ALIGN_SIZE,
				       &offset);
	if (status != SMW_STATUS_OK)
		goto end;

	op->dst.len = input_len;
	op->dst.virt_addr = op->src.virt_addr + offset;

	if (ADD_OVERFLOW(op->src.phys_addr, offset, &phys_addr_offset)) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	op->dst.phys_addr = phys_addr_offset;

	op->op_type = CRYPTO_OP_TYPE_AES;
	op->op_aes_args.algo = algo;
	op->op_aes_args.keyslot = keyslot;

	if (cipher_args->op_type_id == SMW_CONFIG_CIPHER_OP_TYPE_ID_ENCRYPT)
		op->op_aes_args.enc = 1;
	else
		op->op_aes_args.enc = 0;

	op->op_aes_args.iv = smw_crypto_get_cipher_iv(cipher_args);

	if (SET_OVERFLOW(smw_crypto_get_cipher_iv_len(cipher_args),
			 op->op_aes_args.ivlen)) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	/* Set status buffer (aligned after output data) */
	if (ADD_OVERFLOW(offset, op->dst.len, &status_offset)) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	status = smw_utils_align_value(status_offset, ELA_BUFFER_ALIGN_SIZE,
				       &offset);
	if (status != SMW_STATUS_OK)
		goto end;

	op->crypto_status.phys_addr =
		(status_buf_t *)(op->src.phys_addr + offset);
	op->crypto_status.virt_addr =
		(status_buf_t *)(op->src.virt_addr + offset);

	SMW_DBG_PRINTF(DEBUG,
		       "Cipher operation prepared:\n"
		       "  algo: %d\n"
		       "  keyslot: %u\n"
		       "  input_len: %u\n"
		       "  iv_len: %u\n",
		       algo, keyslot, input_len, op->op_aes_args.ivlen);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * retrieve_cipher_output() - Complete cipher operation
 * @op: Cipher operation structure
 * @cipher_args: SMW cipher arguments
 *
 * Return:
 * SMW_STATUS_OK - Success
 * Error code otherwise
 */
static int retrieve_cipher_output(crypto_op_args_t *op,
				  struct smw_crypto_cipher_args *cipher_args)
{
	int status = SMW_STATUS_INVALID_PARAM;

	unsigned char *output_data = smw_crypto_get_cipher_output(cipher_args);

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!op->dst.virt_addr || !op->crypto_status.virt_addr) {
		SMW_DBG_PRINTF(ERROR, "Invalid operation buffers\n");
		goto end;
	}

	if (!output_data)
		goto end;

	/* Clean and invalidate cache for crypto_status buffer */
	smw_utils_dcache_invalidate((uint8_t *)op->crypto_status.virt_addr,
				    sizeof(status_buf_t));

	/* Convert FCE status to SMW status */
	status = convert_fce_status(op->crypto_status.virt_addr->status_code,
				    op->crypto_status.virt_addr->error_info);
	if (status != SMW_STATUS_OK)
		goto end;

	/* Clean and invalidate cache for output buffer */
	smw_utils_dcache_invalidate(op->dst.virt_addr, op->dst.len);

	/* Copy output data from shared buffer */
	SMW_UTILS_MEMCPY(output_data, op->dst.virt_addr, op->dst.len);

	/* Set output length */
	smw_crypto_set_cipher_output_len(cipher_args, op->dst.len);

	SMW_DBG_PRINTF(DEBUG,
		       "Cipher operation completed: expected output len=%u\n",
		       op->dst.len);

	status = SMW_STATUS_OK;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * ela_cipher_one_shot() - Execute cipher one-shot operation
 * @cipher_args: Cipher arguments
 *
 * Return:
 * SMW_STATUS_OK - Success
 * Error code otherwise
 */
static int ela_cipher_one_shot(struct smw_crypto_cipher_args *cipher_args)
{
	int status = SMW_STATUS_OK;
	prime_err_t err = PRIME_ERR_NONE;

	struct smw_keymgr_descriptor *key_desc = cipher_args->keys_desc[0];
	unsigned int input_len = smw_crypto_get_cipher_input_len(cipher_args);
	struct ela_context *ctx = NULL;

	crypto_op_args_t op = { 0 };
	crypto_op_args_t *ops_ptr = &op;
	uint32_t nb_ops = 1;
	uint8_t keyslot = 0;
	enum crypto_cipher_algorithm algo = 0;
	uint32_t memory_size = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	/* Get output length feature */
	if (!smw_crypto_get_cipher_output(cipher_args)) {
		/* Cipher output length is equal to input length */
		smw_crypto_set_cipher_output_len(cipher_args, input_len);
		goto end;
	}

	/* Check if output buffer length is sufficient */
	if (smw_crypto_get_cipher_output_len(cipher_args) < input_len) {
		smw_crypto_set_cipher_output_len(cipher_args, input_len);
		status = SMW_STATUS_OUTPUT_TOO_SHORT;
		goto end;
	}

	/* Get cipher algorithm using lookup table */
	status = ela_set_cipher_algo(key_desc->identifier.type_id,
				     cipher_args->mode_id, &algo);
	if (status != SMW_STATUS_OK)
		goto end;

	/* Calculate required memory size for this operation */
	status = calculate_cipher_memory_size(cipher_args, &memory_size);
	if (status != SMW_STATUS_OK)
		goto end;

	/* Open ELA service with calculated memory size */
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

	status = set_cipher_op_params(&op, cipher_args, keyslot, algo, ctx);
	if (status != SMW_STATUS_OK)
		goto cleanup;

	/* Execute cipher operation */
	err = prime_process_ops(ctx->service_hdl, &ops_ptr, nb_ops);
	if (err != PRIME_ERR_NONE) {
		SMW_DBG_PRINTF(ERROR, "prime_process_ops failed: %d\n", err);
		status = convert_ela_err(err);
		goto cleanup;
	}

	/* Complete operation and copy output */
	status = retrieve_cipher_output(&op, cipher_args);

cleanup:
	ela_close_service();

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

bool ela_cipher_handle(enum operation_id operation_id, void *args, int *status)
{
	bool op_handled = false;
	int tmp_status = SMW_STATUS_OK;

	struct smw_crypto_cipher_args *cipher_args = args;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (operation_id != OPERATION_ID_CIPHER)
		goto end;

	/* Check if ELA should handle this operation */
	if (!use_ela(cipher_args))
		goto end;

	tmp_status = ela_cipher_one_shot(cipher_args);

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
