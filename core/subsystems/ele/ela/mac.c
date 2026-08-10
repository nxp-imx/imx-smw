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
#include "mac.h"

#include "local.h"

#define HASH_ALGO(_hash_algo_id, _length)                                      \
	{                                                                      \
		.hash_algo_id = SMW_CONFIG_HASH_ALGO_ID_SHA##_hash_algo_id,    \
		.hash_algo = CRYPTO_AUTH_SHA_##_hash_algo_id,                  \
		.length = _length                                              \
	}

static const struct {
	enum smw_config_hash_algo_id hash_algo_id;
	enum crypto_sha_algorithm hash_algo;
	uint32_t length;
} hash_algos[] = {
	HASH_ALGO(256, 32),
	HASH_ALGO(384, 48),
	HASH_ALGO(512, 64),
};

static int ela_set_hash_algo(enum smw_config_hash_algo_id hash_algo_id,
			     enum crypto_sha_algorithm *hash_algo)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
	unsigned int i = 0;

	for (; i < ARRAY_SIZE(hash_algos); i++) {
		if (hash_algo_id == hash_algos[i].hash_algo_id) {
			*hash_algo = hash_algos[i].hash_algo;
			status = SMW_STATUS_OK;
			break;
		}
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int ela_get_mac_length(enum smw_config_hash_algo_id hash_algo_id,
			      uint32_t *length)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
	unsigned int i = 0;

	for (; i < ARRAY_SIZE(hash_algos); i++) {
		if (hash_algo_id == hash_algos[i].hash_algo_id) {
			*length = hash_algos[i].length;
			status = SMW_STATUS_OK;
			break;
		}
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * use_ela() - Check if ELA should handle this MAC operation
 * @mac_args: MAC arguments
 *
 * This function checks if:
 * 1. ELA is enabled in configuration for MAC
 * 2. The key is a plaintext buffer (not opaque)
 *
 * Return:
 * true  - ELA should handle this operation
 * false - Use standard ELE operations
 */
static bool use_ela(struct smw_crypto_mac_args *mac_args)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	/*
	 * Check if "USE_ELA" tag is set in the config file.
	 * If not defined, ELA crypto isn't enabled.
	 * Use standard ELE operations.
	 */
	if (!mac_is_ela_enabled(SUBSYSTEM_ID_ELE))
		return false;

	/*
	 * ELA is used for plaintext key buffer.
	 * For opaque key, use standard ELE operations.
	 */
	if (!smw_utils_key_buffer_set(&mac_args->key_descriptor)) {
		SMW_DBG_PRINTF(DEBUG, "MAC op not handled by ELA\n");
		return false;
	}

	return true;
}

/**
 * calculate_hmac_memory_size() - Calculate required memory size for HMAC op
 * @mac_args: SMW MAC arguments
 * @required_size: Required memory size for HMAC operation in bytes
 *
 * Return:
 * SMW_STATUS_OK            - Success
 * SMW_STATUS_INVALID_PARAM - Invalid argument parameter
 */
static int calculate_hmac_memory_size(struct smw_crypto_mac_args *mac_args,
				      uint32_t *required_size)
{
	int status = SMW_STATUS_OK;

	uint32_t size = 0;
	uint32_t aligned_size = 0;
	unsigned int message_len = smw_mac_get_input_length(mac_args);
	unsigned int mac_len = smw_mac_get_mac_length(mac_args);
	uint32_t status_buf_len = sizeof(status_buf_t);

	/*
	 * Message buffer (aligned to 64 bytes)
	 * message_len is guaranteed non-zero here: ela_hmac_one_shot()
	 * returns early when mac_data is NULL, before this function is called.
	 */
	status = smw_utils_align_value(message_len, ELA_BUFFER_ALIGN_SIZE,
				       &size);
	if (status != SMW_STATUS_OK)
		goto end;

	/*
	 * MAC buffer (aligned to 64 bytes)
	 * mac_len is guaranteed to be >= required MAC length and non-zero, as
	 * ela_hmac_one_shot() returns early when mac_data is NULL or if user
	 * supplied mac_len < required MAC length before this function is called.
	 */
	status = smw_utils_align_value(mac_len, ELA_BUFFER_ALIGN_SIZE,
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
		       "HMAC memory calculation:\n"
		       "  message_len: %u\n"
		       "  mac_len: %u\n"
		       "  status_buf_len: %u\n"
		       "  total_size: %u\n",
		       message_len, mac_len, status_buf_len, size);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * set_hmac_op_params() - Prepare HMAC operation
 * @op: ELA crypto operation structure
 * @mac_args: SMW mac arguments
 * @keyslot: Key slot number
 * @algo: ELA MAC algorithm
 * @ctx: ELA context
 *
 * Return:
 * SMW_STATUS_OK - Success
 * Error code otherwise
 */
static int set_hmac_op_params(crypto_op_args_t *op,
			      struct smw_crypto_mac_args *mac_args,
			      uint8_t keyslot, enum crypto_sha_algorithm algo,
			      struct ela_context *ctx)
{
	int status = SMW_STATUS_INVALID_PARAM;

	unsigned int message_len = smw_mac_get_input_length(mac_args);
	unsigned char *message = smw_mac_get_input_data(mac_args);
	unsigned int mac_len = smw_mac_get_mac_length(mac_args);
	unsigned char *mac = smw_mac_get_mac_data(mac_args);
	uint32_t offset = 0;
	uint32_t unaligned_offset = 0;
	uint64_t phys_addr_offset = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!ctx->virtual_addr || !ctx->physical_addr) {
		SMW_DBG_PRINTF(ERROR, "Invalid ELA context addresses\n");
		goto end;
	}

	if (!message || !message_len) {
		SMW_DBG_PRINTF(ERROR, "Invalid input message\n");
		goto end;
	}

	op->op_type = CRYPTO_OP_TYPE_HMAC;
	op->op_mac_args.sha_algo = algo;
	op->op_mac_args.keyslot = keyslot;

	/* Set source buffer */
	op->src.len = message_len;
	op->src.virt_addr = (uint8_t *)ctx->virtual_addr;
	op->src.phys_addr = ctx->physical_addr;

	/* Copy input data to ELA memory using memcpy */
	SMW_UTILS_MEMCPY(op->src.virt_addr, message, message_len);
	smw_utils_dcache_clean(op->src.virt_addr, message_len);

	status = smw_utils_align_value(op->src.len, ELA_BUFFER_ALIGN_SIZE,
				       &offset);
	if (status != SMW_STATUS_OK)
		goto end;

	/* Set destination buffer */
	op->op_mac_args.digest.len = mac_len;
	op->op_mac_args.digest.virt_addr = op->src.virt_addr + offset;

	if (ADD_OVERFLOW(op->src.phys_addr, offset, &phys_addr_offset)) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	op->op_mac_args.digest.phys_addr = phys_addr_offset;

	if (mac_args->op_id == SMW_CONFIG_MAC_OP_ID_COMPUTE) {
		op->op_mac_args.dir = CRYPTO_AUTH_OP_HMAC_GEN;
	} else {
		op->op_mac_args.dir = CRYPTO_AUTH_OP_HMAC_VERIFY;

		if (!mac_len || !mac) {
			status = SMW_STATUS_INVALID_PARAM;
			goto end;
		}

		/* Copy MAC to shared memory for verification */
		SMW_UTILS_MEMCPY(op->op_mac_args.digest.virt_addr, mac,
				 mac_len);

		/* Clean cache for MAC buffer */
		smw_utils_dcache_clean(op->op_mac_args.digest.virt_addr,
				       mac_len);
	}

	/* Set status buffer (aligned after output data) */
	if (ADD_OVERFLOW(offset, mac_len, &unaligned_offset)) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	status = smw_utils_align_value(unaligned_offset, ELA_BUFFER_ALIGN_SIZE,
				       &offset);
	if (status != SMW_STATUS_OK)
		goto end;

	op->crypto_status.phys_addr =
		(status_buf_t *)(op->src.phys_addr + offset);
	op->crypto_status.virt_addr =
		(status_buf_t *)(op->src.virt_addr + offset);

	SMW_DBG_PRINTF(DEBUG,
		       "HMAC operation prepared:\n"
		       "  algo: %d\n"
		       "  keyslot: %u\n"
		       "  message_len: %u\n"
		       "  mac_len: %u\n",
		       algo, keyslot, message_len, mac_len);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * retrieve_hmac_output() - Retrieve HMAC operation output
 * @op: ELA crypto operation structure
 * @mac_args: SMW MAC arguments
 *
 * Return:
 * SMW_STATUS_OK - Success
 * Error code otherwise
 */
static int retrieve_hmac_output(crypto_op_args_t *op,
				struct smw_crypto_mac_args *mac_args)
{
	int status = SMW_STATUS_INVALID_PARAM;

	unsigned char *mac = smw_mac_get_mac_data(mac_args);

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!op->op_mac_args.digest.virt_addr || !op->crypto_status.virt_addr) {
		SMW_DBG_PRINTF(ERROR, "Invalid operation buffers\n");
		goto end;
	}

	if (!mac)
		goto end;

	/* Clean and invalidate cache for crypto_status buffer */
	smw_utils_dcache_invalidate((uint8_t *)op->crypto_status.virt_addr,
				    sizeof(status_buf_t));

	/* Convert FCE status to SMW status */
	status = convert_fce_status(op->crypto_status.virt_addr->status_code,
				    op->crypto_status.virt_addr->error_info);
	if (status != SMW_STATUS_OK)
		goto end;

	if (mac_args->op_id == SMW_CONFIG_MAC_OP_ID_COMPUTE) {
		/* Clean and invalidate cache for output buffer */
		smw_utils_dcache_invalidate(op->op_mac_args.digest.virt_addr,
					    op->op_mac_args.digest.len);

		/* Copy computed MAC from shared buffer */
		SMW_UTILS_MEMCPY(mac, op->op_mac_args.digest.virt_addr,
				 op->op_mac_args.digest.len);

		/* Set MAC buffer length */
		smw_mac_set_mac_length(mac_args, op->op_mac_args.digest.len);
	}

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int ela_load_hmac_key(prime_hdl_t service_hdl,
			     enum crypto_sha_algorithm algo,
			     struct smw_keymgr_descriptor *key_desc,
			     uint8_t *keyslot)
{
	int status = SMW_STATUS_INVALID_PARAM;
	prime_err_t err = PRIME_ERR_NONE;

	hmac_key_t key_args = { 0 };
	unsigned char *key_buffer = NULL;
	unsigned int key_length = 0;
	unsigned int hex_private_len = 0;
	unsigned char *key_buffer_hex = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	key_buffer = smw_keymgr_get_private_data(key_desc);
	key_length = smw_keymgr_get_private_length(key_desc);

	if (!key_buffer || !key_length) {
		SMW_DBG_PRINTF(ERROR, "Invalid key buffer\n");
		goto end;
	}

	status = smw_utils_key_set_hex_buffer(key_desc->format_id, key_buffer,
					      key_length, &key_buffer_hex,
					      &hex_private_len);
	if (status != SMW_STATUS_OK)
		goto end;

	if (SET_OVERFLOW(hex_private_len, key_args.keylen)) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	key_args.key = key_buffer_hex;
	key_args.keyslot = 0;
	key_args.sha_algo = algo;

	/* Initialize HMAC operation with the specified key */
	err = prime_mac_init(service_hdl, &key_args);
	status = convert_ela_err(err);
	if (status != SMW_STATUS_OK) {
		SMW_DBG_PRINTF(ERROR, "prime_mac_init failed: %d\n", err);
		goto end;
	}

	*keyslot = key_args.keyslot;

	SMW_DBG_PRINTF(DEBUG, "HMAC key loaded into slot %u\n", *keyslot);

end:
	if (key_desc->format_id == SMW_KEYMGR_FORMAT_ID_BASE64 &&
	    key_buffer_hex)
		SMW_UTILS_FREE(key_buffer_hex);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * ela_hmac_one_shot() - Execute HMAC one-shot operation
 * @mac_args: SMW mac arguments
 *
 * Return:
 * SMW_STATUS_OK - Success
 * Error code otherwise
 */
static int ela_hmac_one_shot(struct smw_crypto_mac_args *mac_args)
{
	int status = SMW_STATUS_OK;
	prime_err_t err = PRIME_ERR_NONE;

	struct smw_keymgr_descriptor *key_desc = &mac_args->key_descriptor;
	struct ela_context *ctx = NULL;

	crypto_op_args_t op = { 0 };
	crypto_op_args_t *ops_ptr = &op;
	uint32_t nb_ops = 1;
	uint8_t keyslot = 0;
	enum crypto_sha_algorithm algo = 0;
	uint32_t memory_size = 0;
	unsigned int mac_length = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	/* Get hash algorithm using lookup table */
	status = ela_set_hash_algo(mac_args->hash_id, &algo);
	if (status != SMW_STATUS_OK)
		goto end;

	status = ela_get_mac_length(mac_args->hash_id, &mac_length);
	if (status != SMW_STATUS_OK)
		goto end;

	if (!smw_mac_get_mac_data(mac_args)) {
		/* Get output length feature */
		if (mac_args->op_id == SMW_CONFIG_MAC_OP_ID_COMPUTE) {
			smw_mac_set_mac_length(mac_args, mac_length);
			status = SMW_STATUS_OK;
			goto end;
		} else {
			status = SMW_STATUS_INVALID_PARAM;
			goto end;
		}
	}

	/* Check if MAC buffer length is sufficient */
	if (smw_mac_get_mac_length(mac_args) < mac_length) {
		smw_mac_set_mac_length(mac_args, mac_length);
		status = SMW_STATUS_OUTPUT_TOO_SHORT;
		goto end;
	}

	if (!smw_mac_get_input_data(mac_args) ||
	    !smw_mac_get_input_length(mac_args)) {
		SMW_DBG_PRINTF(ERROR,
			       "ELA does not support empty input data\n");
		status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
		goto end;
	}

	/* Calculate required memory size for this operation */
	status = calculate_hmac_memory_size(mac_args, &memory_size);
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

	/* Load HMAC key into ELA key slot */
	status = ela_load_hmac_key(ctx->service_hdl, algo, key_desc, &keyslot);
	if (status != SMW_STATUS_OK)
		goto cleanup;

	status = set_hmac_op_params(&op, mac_args, keyslot, algo, ctx);
	if (status != SMW_STATUS_OK)
		goto cleanup;

	/* Execute HMAC operation */
	err = prime_process_ops(ctx->service_hdl, &ops_ptr, nb_ops);
	if (err != PRIME_ERR_NONE) {
		SMW_DBG_PRINTF(ERROR, "prime_process_ops failed: %d\n", err);
		status = convert_ela_err(err);
		goto cleanup;
	}

	/* Complete operation and copy MAC for MAC compute operation */
	status = retrieve_hmac_output(&op, mac_args);

cleanup:
	ela_close_service();

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

bool ela_mac_handle(enum operation_id operation_id, void *args, int *status)
{
	bool op_handled = false;
	int tmp_status = SMW_STATUS_OK;
	struct smw_crypto_mac_args *mac_args = args;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (operation_id != OPERATION_ID_MAC)
		goto end;

	/* Check if ELA should handle this operation */
	if (!use_ela(mac_args))
		goto end;

	switch (mac_args->algo_id) {
	case SMW_CONFIG_MAC_ALGO_ID_HMAC:
		tmp_status = ela_hmac_one_shot(mac_args);
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

		break;

	default:
		SMW_DBG_PRINTF(DEBUG, "MAC algo not supported\n");
		break;
	}

end:
	SMW_DBG_PRINTF(VERBOSE, "%s: Operation %d %s by ELA\n", __func__,
		       operation_id, op_handled ? "handled" : "not handled");

	return op_handled;
}
