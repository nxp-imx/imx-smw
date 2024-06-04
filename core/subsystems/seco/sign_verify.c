// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2024 NXP
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

#include "common.h"
#include "sign_verify_tls12.h"

#define SIGNATURE_SCHEME_ID(_key_type_id, _security_size, _algo_id,            \
			    _signature_scheme_id)                              \
	{                                                                      \
		.key_type_id = SMW_CONFIG_KEY_TYPE_ID_##_key_type_id,          \
		.security_size = _security_size,                               \
		.algo_id = SMW_CONFIG_HASH_ALGO_ID_##_algo_id,                 \
		.signature_scheme_id =                                         \
			HSM_SIGNATURE_SCHEME_##_signature_scheme_id            \
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
	SIGNATURE_SCHEME_ID(ECDSA_NIST, 256, SHA256, ECDSA_NIST_P256_SHA_256),
	SIGNATURE_SCHEME_ID(ECDSA_NIST, 384, SHA384, ECDSA_NIST_P384_SHA_384),
	SIGNATURE_SCHEME_ID(ECDSA_BRAINPOOL_R1, 256, SHA256,
			    ECDSA_BRAINPOOL_R1_256_SHA_256),
	SIGNATURE_SCHEME_ID(ECDSA_BRAINPOOL_R1, 384, SHA384,
			    ECDSA_BRAINPOOL_R1_384_SHA_384)
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

__weak int tls_mac_finish(struct hdl *hdl, void *args)
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
		status = tls_mac_finish(hdl, args);
		goto end;
	}

	op_args.key_identifier = key_identifier->id;
	op_args.message = smw_sign_verify_get_msg_buf(sign_args);
	op_args.signature = smw_sign_verify_get_sign_buf(sign_args);
	op_args.message_size = smw_sign_verify_get_msg_len(sign_args);
	op_args.signature_size =
		(uint16_t)get_signature_size(key_identifier->security_size);

	pub_signature_size = smw_sign_verify_get_sign_len(sign_args);
	signature_size = BITS_TO_BYTES_SIZE(key_identifier->security_size) * 2;

	if (pub_signature_size < signature_size) {
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

	if (sign_args->attributes.hash_id != SMW_CONFIG_HASH_ALGO_ID_INVALID)
		op_args.flags = HSM_OP_GENERATE_SIGN_FLAGS_INPUT_MESSAGE;
	else
		op_args.flags = HSM_OP_GENERATE_SIGN_FLAGS_INPUT_DIGEST;

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
		export_key_desc.identifier.id = key_descriptor->identifier.id;
		export_key_desc.identifier.type_id =
			key_descriptor->identifier.type_id;
		export_key_desc.identifier.security_size = security_size;

		status = seco_export_public_key(hdl, &export_key_desc);
		if (status != SMW_STATUS_OK)
			goto end;

		key_size = smw_keymgr_get_public_length(&export_key_desc);
		key_buf = smw_keymgr_get_public_data(&export_key_desc);
	} else {
		key_size = smw_keymgr_get_public_length(key_descriptor);
		key_buf = smw_keymgr_get_public_data(key_descriptor);
	}

	if (key_size > UINT16_MAX) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	op_args.key = key_buf;
	op_args.message = smw_sign_verify_get_msg_buf(verify_args);
	op_args.signature = smw_sign_verify_get_sign_buf(verify_args);
	op_args.key_size = key_size;
	op_args.message_size = smw_sign_verify_get_msg_len(verify_args);

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

	if (verify_args->attributes.hash_id != SMW_CONFIG_HASH_ALGO_ID_INVALID)
		op_args.flags = HSM_OP_GENERATE_SIGN_FLAGS_INPUT_MESSAGE;
	else
		op_args.flags = HSM_OP_GENERATE_SIGN_FLAGS_INPUT_DIGEST;

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
	default:
		return false;
	}

	return true;
}
