// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021, 2023-2025 NXP
 */

#include <tee_client_api.h>

#include "smw_status.h"
#include "debug.h"
#include "utils.h"
#include "base64.h"
#include "operations.h"
#include "subsystems.h"
#include "config.h"
#include "keymgr.h"
#include "sign_verify.h"
#include "tee.h"
#include "hash.h"

#define SIGNATURE_TYPE_ID(_type, _id)                                          \
	{                                                                      \
		.smw_id = SMW_CONFIG_SIGN_TYPE_ID_##_type,                     \
		.tee_id = TEE_SIGNATURE_TYPE_##_id                             \
	}

/**
 * struct - Signature type IDs
 * @smw_id: Signature type ID as defined in SMW.
 * @tee_id: Signature type ID as defined in TEE subsystem.
 */
static const struct {
	enum smw_config_sign_type_id smw_id;
	enum tee_signature_type tee_id;
} signature_type_ids[] = {
	SIGNATURE_TYPE_ID(DEFAULT, DEFAULT),
	SIGNATURE_TYPE_ID(PKCS1_1_5, RSASSA_PKCS1_V1_5),
	SIGNATURE_TYPE_ID(PSS, RSASSA_PSS),
	SIGNATURE_TYPE_ID(PURE_EDDSA, PURE_EDDSA),
	SIGNATURE_TYPE_ID(EDDSA_PH, EDDSA_PH),
	SIGNATURE_TYPE_ID(EDDSA_CTX, EDDSA_CTX),
};

static int tee_convert_signature_type_id(enum smw_config_sign_type_id smw_id,
					 enum tee_signature_type *tee_id)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	unsigned int i = 0;
	unsigned int array_size = ARRAY_SIZE(signature_type_ids);

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (i = 0; i < array_size; i++) {
		if (signature_type_ids[i].smw_id == smw_id) {
			*tee_id = signature_type_ids[i].tee_id;
			status = SMW_STATUS_OK;
			break;
		}
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int set_public_key_buffer(struct smw_keymgr_descriptor *key_desc,
				 TEEC_Parameter *param,
				 unsigned char **hex_public_key)
{
	int status = SMW_STATUS_INVALID_PARAM;

	unsigned int public_key_len = smw_keymgr_get_public_length(key_desc);
	unsigned char *public_key = smw_keymgr_get_public_data(key_desc);
	unsigned int hex_public_key_len = 0;

	if (!public_key_len || !public_key)
		goto end;

	status = smw_keymgr_set_hex_key_buffer(key_desc->format_id, public_key,
					       public_key_len, hex_public_key,
					       &hex_public_key_len);
	if (status != SMW_STATUS_OK)
		goto end;

	if (SET_OVERFLOW(hex_public_key_len, param->tmpref.size)) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	param->tmpref.buffer = *hex_public_key;

end:
	return status;
}

static int get_pub_key_hex_len(struct smw_keymgr_descriptor *key_desc,
			       unsigned int *hex_buffer_len)
{
	unsigned int pub_size = smw_keymgr_get_public_length(key_desc);
	unsigned char *pub_buffer = smw_keymgr_get_public_data(key_desc);

	return smw_keymgr_get_hex_key_buffer_len(key_desc->format_id,
						 pub_buffer, pub_size,
						 hex_buffer_len);
}

static void get_eddsa_context(unsigned char **ctx, unsigned int *ctx_length,
			      struct smw_crypto_sign_verify_args *args)
{
	struct smw_eddsa_params *param = NULL;
	struct smw_op_context *op_context = NULL;
	struct sign_context *sign_ctx = NULL;

	if (args->op_step == SMW_OP_STEP_FINAL) {
		op_context = smw_sign_verify_get_op_context(args);
		if (op_context && op_context->subsystem_context) {
			sign_ctx = op_context->subsystem_context;

			*ctx = sign_ctx->eddsa_params.context;
			*ctx_length = sign_ctx->eddsa_params.context_length;
		}
	} else {
		param = smw_sign_verify_get_eddsa_context(args);
		if (param) {
			*ctx = param->context;
			*ctx_length = param->context_length;
		}
	}
}

/**
 * sign_verify() - Generate or verify a signature.
 * @args: Sign or verify arguments.
 * @op_id: OPERATION_ID_SIGN or OPERATION_ID_VERIFY.
 *
 * Return:
 * SMW_STATUS_OK		- Success.
 * SMW_STATUS_INVALID_PARAM	- One of the parameters is invalid.
 * SMW_STATUS_SUBSYSTEM_FAILURE	- Operation failed.
 */
static int sign_verify(struct smw_crypto_sign_verify_args *args,
		       enum operation_id op_id)
{
	int status = SMW_STATUS_INVALID_PARAM;

	TEEC_Operation operation = { 0 };
	TEEC_SharedMemory shm = { 0 };

	struct smw_keymgr_descriptor *key_descriptor = NULL;
	struct smw_keymgr_identifier *key_identifier = NULL;
	struct smw_sign_verify_attributes *sign_attrs = NULL;
	struct sign_verify_shared_params *shared_params = NULL;
	unsigned int shared_params_size =
		sizeof(struct sign_verify_shared_params);
	unsigned char *ctx = NULL;
	unsigned int ctx_length = 0;
	unsigned int sign_length = 0;
	unsigned char *hex_pub_key = NULL;

	uint32_t param0_type = TEEC_NONE;
	uint32_t param3_type = TEEC_NONE;

	enum tee_key_type key_type_id = TEE_KEY_TYPE_ID_INVALID;
	enum smw_keymgr_privacy_id key_privacy = SMW_KEYMGR_PRIVACY_ID_INVALID;

	enum ta_commands cmd_id = CMD_VERIFY;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!args)
		goto exit;

	key_descriptor = &args->key_descriptor;
	key_identifier = &key_descriptor->identifier;
	sign_attrs = &args->attributes;

	status = tee_convert_key_type(key_identifier,
				      SMW_CONFIG_HASH_ALGO_ID_INVALID,
				      &key_type_id);
	if (status != SMW_STATUS_OK)
		goto exit;

	if (sign_attrs->algo_id == SMW_CONFIG_SIGN_ALGO_ID_RSA) {
		/*
		 * Signature type is mandatory.
		 * Salt length optional attribute is only for RSASSA-PSS
		 * signature type.
		 */
		if (sign_attrs->type_id == SMW_CONFIG_SIGN_TYPE_ID_DEFAULT) {
			SMW_DBG_PRINTF(ERROR, "No signature type set\n");
			status = SMW_STATUS_INVALID_PARAM;
			goto exit;
		} else if (sign_attrs->type_id ==
				   SMW_CONFIG_SIGN_TYPE_ID_PKCS1_1_5 &&
			   sign_attrs->salt_length) {
			SMW_DBG_PRINTF(ERROR,
				       "Salt length not supported for %s\n",
				       "RSA PKCS1_V1_5");
			status = SMW_STATUS_INVALID_PARAM;
			goto exit;
		}
	} else if (sign_attrs->algo_id == SMW_CONFIG_SIGN_ALGO_ID_EDDSA) {
		get_eddsa_context(&ctx, &ctx_length, args);

		if (ctx && ctx_length) {
			if (ADD_OVERFLOW(shared_params_size, ctx_length,
					 &shared_params_size)) {
				status = SMW_STATUS_INVALID_PARAM;
				goto exit;
			}
		}
	}

	shared_params = SMW_UTILS_CALLOC(1, shared_params_size);
	if (!shared_params) {
		status = SMW_STATUS_ALLOC_FAILURE;
		goto exit;
	}

	status = tee_convert_hash_algorithm_id(sign_attrs->hash_id,
					       &shared_params->hash_algorithm);
	if (status != SMW_STATUS_OK)
		goto exit;

	status = tee_convert_signature_type_id(sign_attrs->type_id,
					       &shared_params->signature_type);
	if (status != SMW_STATUS_OK)
		goto exit;

	/*
	 * params[0] = Key buffer or key shared memory or none
	 * params[1] = Pointer to sign verify shared params structure
	 * params[2] = Message buffer and message length
	 * params[3] = Signature buffer and signature length
	 */

	switch (op_id) {
	case OPERATION_ID_SIGN:
		if (key_descriptor->format_id != SMW_KEYMGR_FORMAT_ID_INVALID) {
			param0_type = TEEC_MEMREF_PARTIAL_INPUT;
			key_privacy = SMW_KEYMGR_PRIVACY_ID_PAIR;
		}

		param3_type = TEEC_MEMREF_TEMP_OUTPUT;
		cmd_id = CMD_SIGN;
		break;

	case OPERATION_ID_VERIFY:
		if (key_descriptor->format_id != SMW_KEYMGR_FORMAT_ID_INVALID) {
			if (sign_attrs->algo_id ==
			    SMW_CONFIG_SIGN_ALGO_ID_RSA) {
				param0_type = TEEC_MEMREF_PARTIAL_INPUT;
				key_privacy = SMW_KEYMGR_PRIVACY_ID_PUBLIC;
			} else {
				/*
				 * Verify operation with a non RSA key doesn't
				 * require shared memory
				 */
				param0_type = TEEC_MEMREF_TEMP_INPUT;
			}
		}

		param3_type = TEEC_MEMREF_TEMP_INPUT;
		cmd_id = CMD_VERIFY;
		break;

	default:
		goto exit;
	}

	if (param0_type == TEEC_MEMREF_PARTIAL_INPUT) {
		status = copy_keys_to_shm(&shm, key_descriptor, key_privacy);
		if (status != SMW_STATUS_OK)
			goto exit;

		status = get_pub_key_hex_len(key_descriptor,
					     &shared_params->pub_key_len);
		if (status != SMW_STATUS_OK)
			goto exit;

		operation.params[0].memref.parent = &shm;
		operation.params[0].memref.offset = 0;
		operation.params[0].memref.size = shm.size;
	} else if (param0_type == TEEC_MEMREF_TEMP_INPUT) {
		status = set_public_key_buffer(key_descriptor,
					       &operation.params[0],
					       &hex_pub_key);
		if (status != SMW_STATUS_OK)
			goto exit;

		if (SET_OVERFLOW(operation.params[0].tmpref.size,
				 shared_params->pub_key_len)) {
			status = SMW_STATUS_INVALID_PARAM;
			goto exit;
		}
	} else {
		shared_params->id = key_identifier->s_id;
	}

	shared_params->key_type = key_type_id;
	shared_params->security_size = key_identifier->security_size;
	shared_params->msg_hashed = sign_attrs->msg_hashed;

	switch (sign_attrs->algo_id) {
	case SMW_CONFIG_SIGN_ALGO_ID_RSA:
		shared_params->sign_algorithm = TEE_ALGORITHM_ID_RSA;
		shared_params->salt_length = sign_attrs->salt_length;
		break;

	case SMW_CONFIG_SIGN_ALGO_ID_EDDSA:
		shared_params->sign_algorithm = TEE_ALGORITHM_ID_EDDSA;
		if (ctx && ctx_length) {
			if (SET_OVERFLOW(ctx_length,
					 shared_params->ctx_length)) {
				status = SMW_STATUS_INVALID_PARAM;
				goto exit;
			}

			SMW_UTILS_MEMCPY(shared_params->ctx, ctx, ctx_length);
		}
		break;

	case SMW_CONFIG_SIGN_ALGO_ID_ECDSA:
		shared_params->sign_algorithm = TEE_ALGORITHM_ID_ECDSA;
		break;

	default:
		status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
		goto exit;
	}

	operation.paramTypes =
		TEEC_PARAM_TYPES(param0_type, TEEC_MEMREF_TEMP_INPUT,
				 TEEC_MEMREF_TEMP_INPUT, param3_type);

	operation.params[1].tmpref.buffer = shared_params;
	operation.params[1].tmpref.size = shared_params_size;
	operation.params[2].tmpref.buffer = smw_sign_verify_get_msg_buf(args);
	operation.params[2].tmpref.size = smw_sign_verify_get_msg_len(args);

	/*
	 * In case the signature buffer is NULL, the length must be 0 to
	 * get the signature length.
	 */
	if (smw_sign_verify_get_sign_buf(args)) {
		operation.params[3].tmpref.buffer =
			smw_sign_verify_get_sign_buf(args);
		operation.params[3].tmpref.size =
			smw_sign_verify_get_sign_len(args);
	}

	/* Invoke TA */
	status = execute_tee_cmd(cmd_id, &operation);
	SMW_DBG_PRINTF_COND(ERROR, status != SMW_STATUS_OK,
			    "%s: Operation failed\n", __func__);

	if (status != SMW_STATUS_OK && status != SMW_STATUS_OUTPUT_TOO_SHORT)
		goto exit;

	if (op_id == OPERATION_ID_SIGN) {
		if (!SET_OVERFLOW(operation.params[3].tmpref.size,
				  sign_length)) {
			smw_sign_verify_set_sign_len(args, sign_length);

			if (status != SMW_STATUS_OK)
				goto exit;

			SMW_DBG_PRINTF(DEBUG, "Output (%u):\n", sign_length);
			SMW_DBG_HEX_DUMP(DEBUG,
					 operation.params[3].tmpref.buffer,
					 sign_length, 4);
		} else {
			status = SMW_STATUS_OPERATION_FAILURE;
		}
	}

exit:
	if (shared_params)
		free(shared_params);

	if (param0_type == TEEC_MEMREF_PARTIAL_INPUT)
		TEEC_ReleaseSharedMemory(&shm);

	if (key_descriptor &&
	    key_descriptor->format_id == SMW_KEYMGR_FORMAT_ID_BASE64 &&
	    hex_pub_key)
		SMW_UTILS_FREE(hex_pub_key);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int alloc_copy_eddsa_params(struct smw_eddsa_params *dst,
				   struct smw_eddsa_params *src)
{
	int status = SMW_STATUS_OK;

	if (!src || !src->context || !src->context_length)
		goto end;

	dst->context_length = src->context_length;

	dst->context = SMW_UTILS_MALLOC(dst->context_length);
	if (!dst->context) {
		status = SMW_STATUS_ALLOC_FAILURE;
		goto end;
	}

	SMW_UTILS_MEMCPY(dst->context, src->context, dst->context_length);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * set_sign_context() - Allocate and initialize signature subsystem specific ctx
 * @op_context: Pointer to operation context arguments structure
 * @args: Pointer to sign/verify arguments structure
 *
 * This function initializes the members of operation context structure. It also
 * allocates memory to Hash subsystem specific context and initializes it's
 * members.
 *
 * Return:
 * SMW_STATUS_OK            - Success
 * SMW_STATUS_INVALID_PARAM - One of the parameters is invalid
 * SMW_STATUS_ALLOC_FAILURE - Memory allocation failure
 */
static int set_sign_context(struct smw_op_context *op_context,
			    struct smw_crypto_sign_verify_args *args)
{
	int status = SMW_STATUS_INVALID_PARAM;

	struct smw_eddsa_params *eddsa_params = NULL;
	struct sign_context *ctx = NULL;

	if (!op_context)
		goto end;

	op_context->op_id = SMW_CRYPTO_OP_ID_SIGN_MULTI_PART;

	ctx = SMW_UTILS_CALLOC(1, sizeof(*ctx));
	if (!ctx) {
		status = SMW_STATUS_ALLOC_FAILURE;
		SMW_DBG_PRINTF(DEBUG,
			       "Sign subsystem context allocation failure\n");
		goto end;
	}

	eddsa_params = smw_sign_verify_get_eddsa_context(args);
	status = alloc_copy_eddsa_params(&ctx->eddsa_params, eddsa_params);
	if (status != SMW_STATUS_OK)
		goto end;

	ctx->attributes = args->attributes;

	status = smw_keymgr_copy_key(&ctx->key_descriptor,
				     &args->key_descriptor);
	if (status != SMW_STATUS_OK)
		goto end;

	op_context->subsystem_context = ctx;
	op_context->op_state = CTX_OP_STATE_INIT;

	smw_crypto_set_ctx_subsystem_id(op_context, SUBSYSTEM_ID_TEE);

	status = SMW_STATUS_OK;

end:
	if (status != SMW_STATUS_OK && ctx) {
		if (ctx->eddsa_params.context_length)
			SMW_UTILS_FREE(ctx->eddsa_params.context);

		SMW_UTILS_FREE(ctx);
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int signature_init(struct smw_crypto_sign_verify_args *args)
{
	int status = SMW_STATUS_INVALID_PARAM;

	struct smw_crypto_hash_args hash_args = { 0 };
	struct smw_hash_init_args init_pub = { 0 };
	struct smw_sign_verify_attributes *sign_attrs = NULL;

	struct smw_op_context *op_context = NULL;
	struct sign_context *ctx = NULL;
	enum tee_key_type key_type_id = TEE_KEY_TYPE_ID_INVALID;

	SMW_DBG_TRACE_FUNCTION_CALL;

	op_context = smw_sign_verify_get_op_context(args);
	if (!op_context)
		goto end;

	sign_attrs = &args->attributes;

	if (sign_attrs->algo_id == SMW_CONFIG_SIGN_ALGO_ID_RSA) {
		/*
		 * Signature type is mandatory.
		 * Salt length optional attribute is only for RSASSA-PSS
		 * signature type.
		 */
		if (sign_attrs->type_id == SMW_CONFIG_SIGN_TYPE_ID_DEFAULT) {
			SMW_DBG_PRINTF(ERROR, "No signature type set\n");
			goto end;
		} else if (sign_attrs->type_id ==
				   SMW_CONFIG_SIGN_TYPE_ID_PKCS1_1_5 &&
			   sign_attrs->salt_length) {
			SMW_DBG_PRINTF(ERROR,
				       "Salt length not supported for %s\n",
				       "RSA PKCS1_V1_5");
			goto end;
		}
	} else if (sign_attrs->algo_id == SMW_CONFIG_SIGN_ALGO_ID_EDDSA) {
		status = tee_convert_key_type(&args->key_descriptor.identifier,
					      SMW_CONFIG_HASH_ALGO_ID_INVALID,
					      &key_type_id);
		if (status != SMW_STATUS_OK)
			goto end;

		if (key_type_id != TEE_KEY_TYPE_ID_ED25519) {
			status = SMW_STATUS_KEY_INVALID;
			goto end;
		}

		/* Force the hash algorithm to be SHA512 */
		sign_attrs->hash_id = SMW_CONFIG_HASH_ALGO_ID_SHA512;
	}

	status = set_sign_context(op_context, args);
	if (status != SMW_STATUS_OK)
		goto end;

	ctx = op_context->subsystem_context;
	if (!ctx) {
		status = SMW_STATUS_OPERATION_FAILURE;
		goto end;
	}

	hash_args.algo_id = sign_attrs->hash_id;
	hash_args.op_step = SMW_OP_STEP_INIT;
	hash_args.init_pub = &init_pub;

	init_pub.input = smw_sign_verify_get_msg_buf(args);
	init_pub.input_length = smw_sign_verify_get_msg_len(args);
	init_pub.context = &ctx->hash_ctx;

	if (!tee_hash_handle(OPERATION_ID_HASH_MULTI_PART, &hash_args, &status))
		status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int signature_update(struct smw_crypto_sign_verify_args *args)
{
	int status = SMW_STATUS_INVALID_PARAM;

	struct smw_crypto_hash_args hash_args = { 0 };
	struct smw_hash_update_args update_pub = { 0 };

	struct smw_op_context *op_context = NULL;
	struct sign_context *ctx = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	op_context = smw_sign_verify_get_op_context(args);
	if (!op_context || !op_context->subsystem_context)
		goto end;

	ctx = op_context->subsystem_context;

	hash_args.op_step = SMW_OP_STEP_UPDATE;
	hash_args.update_pub = &update_pub;

	update_pub.input = smw_sign_verify_get_msg_buf(args);
	update_pub.input_length = smw_sign_verify_get_msg_len(args);
	update_pub.context = &ctx->hash_ctx;

	if (!tee_hash_handle(OPERATION_ID_HASH_MULTI_PART, &hash_args, &status))
		status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int signature_final(struct smw_crypto_sign_verify_args *args,
			   enum operation_id op_id)
{
	int status = SMW_STATUS_INVALID_PARAM;

	struct smw_sign_verify_final_args pub_args = { 0 };
	struct smw_crypto_sign_verify_args tmp_args = { 0 };

	struct smw_crypto_hash_args hash_args = { 0 };
	struct smw_hash_final_args final_pub = { 0 };

	struct smw_op_context *op_context = NULL;
	struct sign_context *ctx = NULL;

	unsigned char *digest = NULL;
	unsigned int digest_length = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	op_context = smw_sign_verify_get_op_context(args);
	if (!op_context || !op_context->subsystem_context)
		goto end;

	ctx = op_context->subsystem_context;

	hash_args.op_step = SMW_OP_STEP_FINAL;
	hash_args.final_pub = &final_pub;

	final_pub.input = smw_sign_verify_get_msg_buf(args);
	final_pub.input_length = smw_sign_verify_get_msg_len(args);
	final_pub.context = &ctx->hash_ctx;

	/* First get the digest length */
	if (!tee_hash_handle(OPERATION_ID_HASH_MULTI_PART, &hash_args, &status))
		status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	if (status != SMW_STATUS_OK && status != SMW_STATUS_OUTPUT_TOO_SHORT)
		goto end;

	digest_length = smw_crypto_get_hash_output_length(&hash_args);
	digest = SMW_UTILS_MALLOC(digest_length);
	if (!digest) {
		status = SMW_STATUS_ALLOC_FAILURE;
		goto end;
	}

	if (smw_sign_verify_get_sign_buf(args)) {
		final_pub.output = digest;
		final_pub.output_length = digest_length;

		if (!tee_hash_handle(OPERATION_ID_HASH_MULTI_PART, &hash_args,
				     &status))
			status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

		if (status != SMW_STATUS_OK)
			goto end;
	}

	/* Do digest buffer signature using temporary operation arguments */
	tmp_args.key_descriptor = ctx->key_descriptor;
	tmp_args.attributes = ctx->attributes;
	tmp_args.attributes.msg_hashed = true;
	tmp_args.op_step = SMW_OP_STEP_FINAL;
	tmp_args.final_pub = &pub_args;

	pub_args.context = smw_sign_verify_get_op_context(args);
	pub_args.message = digest;
	pub_args.message_length = digest_length;
	pub_args.signature = smw_sign_verify_get_sign_buf(args);
	pub_args.signature_length = smw_sign_verify_get_sign_len(args);

	status = sign_verify(&tmp_args, op_id);

	if (op_id == OPERATION_ID_SIGN)
		smw_sign_verify_set_sign_len(args, pub_args.signature_length);

end:
	if (digest)
		SMW_UTILS_FREE(digest);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int sign_multipart(struct smw_crypto_sign_verify_args *args)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	switch (args->op_step) {
	case SMW_OP_STEP_INIT:
		status = signature_init(args);
		break;

	case SMW_OP_STEP_UPDATE:
		status = signature_update(args);
		break;

	case SMW_OP_STEP_FINAL:
		status = signature_final(args, OPERATION_ID_SIGN);
		break;

	default:
		break;
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int verify_multipart(struct smw_crypto_sign_verify_args *args)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	switch (args->op_step) {
	case SMW_OP_STEP_INIT:
		status = signature_init(args);
		break;

	case SMW_OP_STEP_UPDATE:
		status = signature_update(args);
		break;

	case SMW_OP_STEP_FINAL:
		status = signature_final(args, OPERATION_ID_VERIFY);
		break;

	default:
		break;
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

bool tee_sign_verify_handle(enum operation_id op_id, void *args, int *status)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	switch (op_id) {
	case OPERATION_ID_SIGN:
	case OPERATION_ID_VERIFY:
		*status = sign_verify(args, op_id);
		break;
	case OPERATION_ID_SIGN_MULTI_PART:
		*status = sign_multipart(args);
		break;
	case OPERATION_ID_VERIFY_MULTI_PART:
		*status = verify_multipart(args);
		break;
	default:
		return false;
	}

	return true;
}

void tee_free_sign_context(struct smw_op_context *ctx)
{
	struct sign_context *sign_ctx = NULL;
	struct hash_context *hash_ctx = NULL;

	if (ctx && ctx->subsystem_context) {
		sign_ctx = ctx->subsystem_context;

		if (sign_ctx->eddsa_params.context)
			SMW_UTILS_FREE(sign_ctx->eddsa_params.context);

		sign_ctx->eddsa_params.context = NULL;

		hash_ctx = sign_ctx->hash_ctx.subsystem_context;
		if (hash_ctx)
			SMW_UTILS_FREE(hash_ctx);

		sign_ctx->hash_ctx.subsystem_context = NULL;

		smw_keymgr_free_key(&sign_ctx->key_descriptor);
	}
}

int tee_copy_sign_context(struct smw_op_context *src_context,
			  struct smw_op_context *dst_context,
			  struct shared_context *tee_dst_ctx)
{
	int status = SMW_STATUS_INVALID_PARAM;

	struct sign_context *src_sign_ctx = NULL;
	struct sign_context *dst_sign_ctx = NULL;
	struct hash_context *dst_hash_ctx = NULL;

	if (!src_context || !dst_context || !src_context->subsystem_context)
		goto end;

	src_sign_ctx = src_context->subsystem_context;

	/* Allocate the subsystem context for the destination */
	dst_sign_ctx = SMW_UTILS_CALLOC(1, sizeof(*dst_sign_ctx));
	if (!dst_sign_ctx) {
		status = SMW_STATUS_ALLOC_FAILURE;
		goto end;
	}

	/* Copy and allocate the eddsa parameters */
	status = alloc_copy_eddsa_params(&dst_sign_ctx->eddsa_params,
					 &src_sign_ctx->eddsa_params);
	if (status != SMW_STATUS_OK)
		goto end;

	dst_hash_ctx = SMW_UTILS_MALLOC(sizeof(*dst_hash_ctx));
	if (!dst_hash_ctx) {
		status = SMW_STATUS_ALLOC_FAILURE;
		goto end;
	}

	dst_sign_ctx->attributes = src_sign_ctx->attributes;
	dst_sign_ctx->hash_ctx = src_sign_ctx->hash_ctx;

	dst_hash_ctx->tee_handle = tee_dst_ctx->handle;
	dst_sign_ctx->hash_ctx.subsystem_context = dst_hash_ctx;

	status = smw_keymgr_copy_key(&dst_sign_ctx->key_descriptor,
				     &src_sign_ctx->key_descriptor);

end:
	if (dst_context)
		dst_context->subsystem_context = dst_sign_ctx;

	if (status != SMW_STATUS_OK && dst_sign_ctx) {
		tee_free_sign_context(dst_context);
		SMW_UTILS_FREE(dst_sign_ctx);
		dst_context->subsystem_context = NULL;
	}

	return status;
}
