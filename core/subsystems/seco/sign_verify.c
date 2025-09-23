// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2025 NXP
 */

#include "smw_status.h"
#include "smw_crypto.h"

#include "compiler.h"
#include "global.h"
#include "debug.h"
#include "utils.h"
#include "operations.h"
#include "subsystems.h"
#include "config.h"
#include "keymgr.h"
#include "sign_verify.h"
#include "hash.h"

#include "common.h"
#include "sign_verify_tls12.h"

/**
 * struct sign_context - Signature context
 * @hash_ctx: Hash context
 * @attributes: Signature attributes
 * @key_descriptor: Signature key descriptor
 */
struct sign_context {
	struct smw_op_context hash_ctx;
	struct smw_sign_verify_attributes attributes;
	struct smw_keymgr_descriptor key_descriptor;
};

#define SIGNATURE_SCHEME_ID(_key_type_id, _security_size, _algo_id,            \
			    _signature_scheme_id)                              \
	{                                                                      \
		.key_type_id = SMW_CONFIG_KEY_TYPE_ID_##_key_type_id,          \
		.security_size = _security_size,                               \
		.algo_id = SMW_CONFIG_HASH_ALGO_ID_##_algo_id,                 \
		.signature_scheme_id =                                         \
			HSM_SIGNATURE_SCHEME_ECDSA_##_signature_scheme_id      \
	}

/* Key type IDs must be ordered from lowest to highest.
 * Security sizes must be ordered from lowest to highest
 * for 1 given Key type ID.
 * HASH algo must be ordered from lowest to highest
 * for 1 given Key type ID / Security size
 */
static const struct {
	enum smw_config_key_type_id key_type_id;
	unsigned int security_size;
	enum smw_config_hash_algo_id algo_id;
	hsm_signature_scheme_id_t signature_scheme_id;
} signature_scheme_ids[] = {
	SIGNATURE_SCHEME_ID(SECP_R1, 256, SHA256, NIST_P256_SHA_256),
	SIGNATURE_SCHEME_ID(SECP_R1, 384, SHA384, NIST_P384_SHA_384),
	SIGNATURE_SCHEME_ID(BRAINPOOL_R1, 256, SHA256,
			    BRAINPOOL_R1_256_SHA_256),
	SIGNATURE_SCHEME_ID(BRAINPOOL_R1, 384, SHA384, BRAINPOOL_R1_384_SHA_384)
};

static int set_signature_scheme(enum smw_config_key_type_id key_type_id,
				unsigned int security_size,
				enum smw_config_hash_algo_id algo_id,
				hsm_signature_scheme_id_t *signature_scheme_id)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	unsigned int i = 0;
	unsigned int size = ARRAY_SIZE(signature_scheme_ids);

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (; i < size; i++) {
		if (signature_scheme_ids[i].key_type_id < key_type_id)
			continue;
		if (signature_scheme_ids[i].key_type_id > key_type_id)
			goto end;
		if (signature_scheme_ids[i].security_size < security_size)
			continue;
		if (signature_scheme_ids[i].security_size > security_size)
			goto end;
		if (algo_id != SMW_CONFIG_HASH_ALGO_ID_INVALID) {
			if (signature_scheme_ids[i].algo_id < algo_id)
				continue;
			if (signature_scheme_ids[i].algo_id > algo_id)
				goto end;
		}
		*signature_scheme_id =
			signature_scheme_ids[i].signature_scheme_id;
		status = SMW_STATUS_OK;
		break;
	}

	SMW_DBG_PRINTF(DEBUG, "SECO Signature Scheme ID: %x\n",
		       *signature_scheme_id);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static uint16_t get_signature_size(unsigned int security_size)
{
	/* SECO requires 1 extra byte */
	return (BITS_TO_BYTES_SIZE(security_size) * 2 + 1) & UINT16_MAX;
}

__weak int seco_tls_mac_finish(struct hdl *hdl, void *args)
{
	(void)hdl;
	(void)args;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

static int sign(struct hdl *hdl, void *args)
{
	int status = SMW_STATUS_OK;

	hsm_err_t err = HSM_NO_ERROR;

	op_generate_sign_args_t op_args = { 0 };

	struct smw_crypto_sign_verify_args *sign_args = args;
	struct smw_keymgr_descriptor *key_descriptor =
		&sign_args->key_descriptor;
	struct smw_keymgr_identifier *key_identifier =
		&key_descriptor->identifier;

	uint8_t *signature = NULL;
	unsigned int signature_size = 0;
	unsigned int pub_signature_size = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (key_descriptor->format_id != SMW_KEYMGR_FORMAT_ID_INVALID) {
		//TODO: first import key, then sign
		//      for now import is not supported by SECO
		status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
		goto end;
	}

	/* TLS finish case */
	if (sign_args->attributes.algo_id == SMW_CONFIG_SIGN_ALGO_ID_TLS_1_2) {
		status = seco_tls_mac_finish(hdl, args);
		goto end;
	}

	op_args.key_identifier = key_identifier->s_id;
	op_args.message = smw_sign_verify_get_msg_buf(sign_args);
	op_args.signature = smw_sign_verify_get_sign_buf(sign_args);
	op_args.message_size = smw_sign_verify_get_msg_len(sign_args);
	op_args.signature_size =
		(uint16_t)get_signature_size(key_identifier->security_size);

	pub_signature_size = smw_sign_verify_get_sign_len(sign_args);
	signature_size = BITS_TO_BYTES_SIZE(key_identifier->security_size) * 2;

	if (pub_signature_size < signature_size || !op_args.signature) {
		smw_sign_verify_set_sign_len(sign_args, signature_size);

		status = SMW_STATUS_OUTPUT_TOO_SHORT;
		goto end;
	}

	if (pub_signature_size == signature_size) {
		/* SECO requires a bigger buffer */
		signature = SMW_UTILS_MALLOC(op_args.signature_size);
		if (!signature) {
			status = SMW_STATUS_ALLOC_FAILURE;
			goto end;
		}
		op_args.signature = signature;
	}

	if (sign_args->attributes.msg_hashed)
		op_args.flags = HSM_OP_GENERATE_SIGN_FLAGS_INPUT_DIGEST;
	else
		op_args.flags = HSM_OP_GENERATE_SIGN_FLAGS_INPUT_MESSAGE;

	status = set_signature_scheme(key_identifier->type_id,
				      key_identifier->security_size,
				      sign_args->attributes.hash_id,
				      &op_args.scheme_id);
	if (status != SMW_STATUS_OK)
		goto end;

	SMW_DBG_PRINTF(VERBOSE,
		       "[%s (%d)] Call hsm_do_sign()\n"
		       "op_generate_sign_args_t\n"
		       "    key_identifier: 0x%08X\n"
		       "    scheme_id: 0x%08X\n"
		       "    flags: 0x%X\n"
		       "    Message\n"
		       "      - buffer: %p\n"
		       "      - size: %d\n"
		       "    Signature\n"
		       "      - buffer: %p\n"
		       "      - size: %d\n",
		       __func__, __LINE__, op_args.key_identifier,
		       op_args.scheme_id, op_args.flags, op_args.message,
		       op_args.message_size, op_args.signature,
		       op_args.signature_size);

	err = hsm_do_sign(hdl->key_store, &op_args);
	SMW_DBG_PRINTF(DEBUG, "hsm_do_sign returned %d\n", err);

	status = seco_convert_err(err);
	if (status != SMW_STATUS_OK)
		goto end;

	if (signature_size > op_args.signature_size)
		signature_size = op_args.signature_size;

	if (signature)
		smw_sign_verify_copy_sign_buf(sign_args, signature,
					      signature_size);

	smw_sign_verify_set_sign_len(sign_args, signature_size);

end:
	if (signature)
		SMW_UTILS_FREE(signature);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int verify(struct hdl *hdl, void *args)
{
	int status = SMW_STATUS_OK;

	hsm_err_t err = HSM_NO_ERROR;

	op_verify_sign_args_t op_args = { 0 };
	hsm_verification_status_t verification_status = 0;

	struct smw_crypto_sign_verify_args *verify_args = args;
	struct smw_keymgr_descriptor *key_descriptor =
		&verify_args->key_descriptor;

	struct smw_keymgr_descriptor export_key_desc = { 0 };
	unsigned int security_size = 0;
	uint8_t *key_buf = NULL;
	unsigned int key_size = 0;
	uint8_t *hex_key_buf = NULL;
	unsigned int hex_key_size = 0;
	uint8_t *signature = NULL;
	uint16_t signature_size = 0;
	uint16_t seco_signature_size = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	security_size = key_descriptor->identifier.security_size;
	if (!security_size) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	if (key_descriptor->format_id == SMW_KEYMGR_FORMAT_ID_INVALID) {
		export_key_desc.identifier.s_id =
			key_descriptor->identifier.s_id;
		export_key_desc.identifier.type_id =
			key_descriptor->identifier.type_id;
		export_key_desc.identifier.security_size = security_size;

		status = seco_export_public_key(hdl, &export_key_desc);
		if (status != SMW_STATUS_OK)
			goto end;

		hex_key_size = smw_keymgr_get_public_length(&export_key_desc);
		hex_key_buf = smw_keymgr_get_public_data(&export_key_desc);
	} else {
		key_size = smw_keymgr_get_public_length(key_descriptor);
		key_buf = smw_keymgr_get_public_data(key_descriptor);

		status =
			smw_keymgr_set_hex_key_buffer(key_descriptor->format_id,
						      key_buf, key_size,
						      &hex_key_buf,
						      &hex_key_size);
		if (status != SMW_STATUS_OK)
			goto end;
	}

	if (key_size > UINT16_MAX) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	op_args.key = hex_key_buf;
	op_args.message = smw_sign_verify_get_msg_buf(verify_args);
	op_args.signature = smw_sign_verify_get_sign_buf(verify_args);
	op_args.message_size = smw_sign_verify_get_msg_len(verify_args);

	if (!op_args.signature) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	if (SET_OVERFLOW(hex_key_size, op_args.key_size)) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	if (SET_OVERFLOW(smw_sign_verify_get_sign_len(verify_args),
			 op_args.signature_size)) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	seco_signature_size = get_signature_size(security_size);

	signature_size = (BITS_TO_BYTES_SIZE(security_size) * 2) & UINT16_MAX;
	if (!signature_size || !seco_signature_size) {
		status = SMW_STATUS_OPERATION_FAILURE;
		goto end;
	}

	if (op_args.signature_size == signature_size) {
		/* SECO requires a bigger buffer */
		signature = SMW_UTILS_MALLOC(seco_signature_size);
		if (!signature) {
			status = SMW_STATUS_ALLOC_FAILURE;
			goto end;
		}

		SMW_UTILS_MEMCPY(signature, op_args.signature,
				 op_args.signature_size);
		op_args.signature = signature;
		op_args.signature_size = seco_signature_size;
	}

	status = set_signature_scheme(key_descriptor->identifier.type_id,
				      security_size,
				      verify_args->attributes.hash_id,
				      &op_args.scheme_id);
	if (status != SMW_STATUS_OK)
		goto end;

	if (verify_args->attributes.msg_hashed)
		op_args.flags = HSM_OP_GENERATE_SIGN_FLAGS_INPUT_DIGEST;
	else
		op_args.flags = HSM_OP_GENERATE_SIGN_FLAGS_INPUT_MESSAGE;

	SMW_DBG_PRINTF(VERBOSE,
		       "[%s (%d)] Call hsm_verify_sign()\n"
		       "op_verify_sign_args_t\n"
		       "    scheme_id: 0x%08X\n"
		       "    flags: 0x%X\n"
		       "    Public Key\n"
		       "      - buffer: %p\n"
		       "      - size: %d\n"
		       "    Message\n"
		       "      - buffer: %p\n"
		       "      - size: %d\n"
		       "    Signature\n"
		       "      - buffer: %p\n"
		       "      - size: %d\n",
		       __func__, __LINE__, op_args.scheme_id, op_args.flags,
		       op_args.key, op_args.key_size, op_args.message,
		       op_args.message_size, op_args.signature,
		       op_args.signature_size);

	err = hsm_verify_sign(hdl->session, &op_args, &verification_status);
	status = seco_convert_err(err);

	SMW_DBG_PRINTF(DEBUG, "hsm_verify_sign returned %d\n", err);

end:
	if (export_key_desc.pub)
		(void)smw_keymgr_free_keypair_buffer(&export_key_desc);

	if (signature)
		SMW_UTILS_FREE(signature);

	if (key_descriptor->format_id == SMW_KEYMGR_FORMAT_ID_BASE64 &&
	    hex_key_buf)
		SMW_UTILS_FREE(hex_key_buf);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * set_sign_context() - Allocate and initialize signature subsystem specific ctx
 * @op_context: Pointer to operation context arguments structure
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

	ctx->attributes = args->attributes;

	status = smw_keymgr_copy_key(&ctx->key_descriptor,
				     &args->key_descriptor);
	if (status != SMW_STATUS_OK)
		goto end;

	op_context->subsystem_context = ctx;
	op_context->op_state = CTX_OP_STATE_INIT;

	smw_crypto_set_ctx_subsystem_id(op_context, SUBSYSTEM_ID_SECO);

	status = SMW_STATUS_OK;

end:
	if (status != SMW_STATUS_OK && ctx)
		SMW_UTILS_FREE(ctx);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int signature_init(struct hdl *hdl,
			  struct smw_crypto_sign_verify_args *args)
{
	int status = SMW_STATUS_INVALID_PARAM;

	struct smw_crypto_hash_args hash_args = { 0 };
	struct smw_hash_init_args init_pub = { 0 };
	struct smw_sign_verify_attributes *sign_attrs = NULL;
	struct smw_keymgr_descriptor *key_desc = &args->key_descriptor;
	struct smw_keymgr_identifier *key_identifier = &key_desc->identifier;

	struct smw_op_context *op_context = NULL;
	struct sign_context *ctx = NULL;
	hsm_signature_scheme_id_t scheme_id = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	op_context = smw_sign_verify_get_op_context(args);
	if (!op_context)
		goto end;

	sign_attrs = &args->attributes;

	status = set_signature_scheme(key_identifier->type_id,
				      key_identifier->security_size,
				      sign_attrs->hash_id, &scheme_id);
	if (status != SMW_STATUS_OK)
		goto end;

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

	if (!seco_hash_handle(hdl, OPERATION_ID_HASH_MULTI_PART, &hash_args,
			      &status))
		status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int signature_update(struct hdl *hdl,
			    struct smw_crypto_sign_verify_args *args)
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

	if (!seco_hash_handle(hdl, OPERATION_ID_HASH_MULTI_PART, &hash_args,
			      &status))
		status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int signature_final(struct hdl *hdl,
			   struct smw_crypto_sign_verify_args *args,
			   bool is_verify)
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
	if (!seco_hash_handle(hdl, OPERATION_ID_HASH_MULTI_PART, &hash_args,
			      &status))
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

		if (!seco_hash_handle(hdl, OPERATION_ID_HASH_MULTI_PART,
				      &hash_args, &status))
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

	if (is_verify) {
		status = verify(hdl, &tmp_args);
	} else {
		status = sign(hdl, &tmp_args);
		smw_sign_verify_set_sign_len(args, pub_args.signature_length);
	}

end:
	if (digest)
		SMW_UTILS_FREE(digest);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int sign_multipart(struct hdl *hdl,
			  struct smw_crypto_sign_verify_args *args)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	switch (args->op_step) {
	case SMW_OP_STEP_INIT:
		status = signature_init(hdl, args);
		break;

	case SMW_OP_STEP_UPDATE:
		status = signature_update(hdl, args);
		break;

	case SMW_OP_STEP_FINAL:
		status = signature_final(hdl, args, false);
		break;

	default:
		break;
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int verify_multipart(struct hdl *hdl,
			    struct smw_crypto_sign_verify_args *args)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	switch (args->op_step) {
	case SMW_OP_STEP_INIT:
		status = signature_init(hdl, args);
		break;

	case SMW_OP_STEP_UPDATE:
		status = signature_update(hdl, args);
		break;

	case SMW_OP_STEP_FINAL:
		status = signature_final(hdl, args, true);
		break;

	default:
		break;
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

bool seco_sign_verify_handle(struct hdl *hdl, enum operation_id operation_id,
			     void *args, int *status)
{
	SMW_DBG_ASSERT(args);

	switch (operation_id) {
	case OPERATION_ID_SIGN:
		*status = sign(hdl, args);
		break;
	case OPERATION_ID_VERIFY:
		*status = verify(hdl, args);
		break;
	case OPERATION_ID_SIGN_MULTI_PART:
		*status = sign_multipart(hdl, args);
		break;
	case OPERATION_ID_VERIFY_MULTI_PART:
		*status = verify_multipart(hdl, args);
		break;
	default:
		return false;
	}

	return true;
}

void seco_free_sign_context(struct smw_op_context *ctx)
{
	struct sign_context *sign_ctx = NULL;

	if (ctx && ctx->subsystem_context) {
		sign_ctx = ctx->subsystem_context;

		SMW_UTILS_FREE(sign_ctx->hash_ctx.subsystem_context);
		sign_ctx->hash_ctx.subsystem_context = NULL;

		smw_keymgr_free_key(&sign_ctx->key_descriptor);
	}
}

int seco_copy_sign_context(struct smw_op_context *src_ctx,
			   struct smw_op_context *dst_ctx)
{
	int status = SMW_STATUS_INVALID_PARAM;

	struct sign_context *src_sign_ctx = NULL;
	struct sign_context *dst_sign_ctx = NULL;

	if (!src_ctx || !dst_ctx || !src_ctx->subsystem_context)
		goto end;

	src_sign_ctx = src_ctx->subsystem_context;

	/* Allocate the subsystem context for the destination */
	dst_sign_ctx = SMW_UTILS_CALLOC(1, sizeof(*dst_sign_ctx));
	if (!dst_sign_ctx) {
		status = SMW_STATUS_ALLOC_FAILURE;
		goto end;
	}

	status = seco_copy_hash_context(&src_sign_ctx->hash_ctx,
					&dst_sign_ctx->hash_ctx);
	if (status != SMW_STATUS_OK)
		goto end;

	dst_sign_ctx->attributes = src_sign_ctx->attributes;

	status = smw_keymgr_copy_key(&dst_sign_ctx->key_descriptor,
				     &src_sign_ctx->key_descriptor);
	if (status != SMW_STATUS_OK)
		goto end;

end:
	if (dst_ctx)
		dst_ctx->subsystem_context = dst_sign_ctx;

	if (status != SMW_STATUS_OK && dst_sign_ctx) {
		seco_free_sign_context(dst_ctx);
		SMW_UTILS_FREE(dst_sign_ctx);
		dst_ctx->subsystem_context = NULL;
	}

	return status;
}
