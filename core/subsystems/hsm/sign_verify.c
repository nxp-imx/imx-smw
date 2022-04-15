// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2022 NXP
 */

#include "hsm_api.h"

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
			    _hsm_signature_scheme_id)                          \
	{                                                                      \
		.key_type_id = SMW_CONFIG_KEY_TYPE_ID_##_key_type_id,          \
		.security_size = _security_size,                               \
		.algo_id = SMW_CONFIG_HASH_ALGO_ID_##_algo_id,                 \
		.hsm_signature_scheme_id =                                     \
			HSM_SIGNATURE_SCHEME_##_hsm_signature_scheme_id        \
	}

/* Key type IDs must be ordered from lowest to highest.
 * Security sizes must be ordered from lowest to highest
 * for 1 given Key type ID.
 * HASH algo must be ordered from lowest to highest
 * for 1 given Key type ID / Security size
 */
static struct {
	enum smw_config_key_type_id key_type_id;
	unsigned int security_size;
	enum smw_config_hash_algo_id algo_id;
	hsm_signature_scheme_id_t hsm_signature_scheme_id;
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

	unsigned int i;
	unsigned int size = ARRAY_SIZE(signature_scheme_ids);

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (i = 0; i < size; i++) {
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
			signature_scheme_ids[i].hsm_signature_scheme_id;
		status = SMW_STATUS_OK;
		break;
	}

	SMW_DBG_PRINTF(DEBUG, "HSM Signature Scheme ID: %x\n",
		       *signature_scheme_id);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static uint16_t get_hsm_signature_size(int security_size)
{
	/* HSM requires 1 extra byte */
	return BITS_TO_BYTES_SIZE(security_size) * 2 + 1;
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

	op_generate_sign_args_t op_generate_sign_args = { 0 };

	struct smw_crypto_sign_verify_args *sign_args = args;
	struct smw_keymgr_descriptor *key_descriptor =
		&sign_args->key_descriptor;
	struct smw_keymgr_identifier *key_identifier =
		&key_descriptor->identifier;

	uint8_t *signature = NULL;
	uint16_t signature_size;
	uint16_t pub_signature_size;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_ASSERT(sign_args);

	if (key_descriptor->format_id != SMW_KEYMGR_FORMAT_ID_INVALID) {
		//TODO: first import key, then sign
		//      for now import is not supported by HSM
		status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
		goto end;
	}

	/* TLS finish case */
	if (sign_args->attributes.tls_label !=
	    SMW_CONFIG_TLS_FINISH_ID_INVALID) {
		status = tls_mac_finish(hdl, args);
		goto end;
	}

	op_generate_sign_args.key_identifier = key_identifier->id;
	op_generate_sign_args.message = smw_sign_verify_get_msg_buf(sign_args);
	op_generate_sign_args.signature =
		smw_sign_verify_get_sign_buf(sign_args);
	op_generate_sign_args.message_size =
		smw_sign_verify_get_msg_len(sign_args);
	op_generate_sign_args.signature_size =
		get_hsm_signature_size(key_identifier->security_size);

	pub_signature_size = smw_sign_verify_get_sign_len(sign_args);
	signature_size = BITS_TO_BYTES_SIZE(key_identifier->security_size) * 2;

	if (pub_signature_size < signature_size) {
		smw_sign_verify_set_sign_len(sign_args, signature_size);
		status = SMW_STATUS_OUTPUT_TOO_SHORT;
		goto end;
	}

	if (pub_signature_size == signature_size) {
		/* HSM requires a bigger buffer */
		signature =
			SMW_UTILS_MALLOC(op_generate_sign_args.signature_size);
		if (!signature) {
			status = SMW_STATUS_ALLOC_FAILURE;
			goto end;
		}
		op_generate_sign_args.signature = signature;
	}

	if (sign_args->algo_id != SMW_CONFIG_HASH_ALGO_ID_INVALID)
		op_generate_sign_args.flags =
			HSM_OP_GENERATE_SIGN_FLAGS_INPUT_MESSAGE;
	else
		op_generate_sign_args.flags =
			HSM_OP_GENERATE_SIGN_FLAGS_INPUT_DIGEST;

	status = set_signature_scheme(key_identifier->type_id,
				      key_identifier->security_size,
				      sign_args->algo_id,
				      &op_generate_sign_args.scheme_id);
	if (status != SMW_STATUS_OK)
		goto end;

	SMW_DBG_PRINTF(VERBOSE,
		       "[%s (%d)] Call hsm_generate_signature()\n"
		       "signature_gen_hdl: %d\n"
		       "op_generate_sign_args_t\n"
		       "    key_identifier: %d\n"
		       "    message: %p\n"
		       "    signature: %p\n"
		       "    message_size: %d\n"
		       "    signature_size: %d\n"
		       "    scheme_id: %x\n"
		       "    flags: %x\n",
		       __func__, __LINE__, hdl->signature_gen,
		       op_generate_sign_args.key_identifier,
		       op_generate_sign_args.message,
		       op_generate_sign_args.signature,
		       op_generate_sign_args.message_size,
		       op_generate_sign_args.signature_size,
		       op_generate_sign_args.scheme_id,
		       op_generate_sign_args.flags);

	err = hsm_generate_signature(hdl->signature_gen,
				     &op_generate_sign_args);
	if (err != HSM_NO_ERROR) {
		SMW_DBG_PRINTF(DEBUG, "hsm_generate_signature returned %d\n",
			       err);
		status = SMW_STATUS_SUBSYSTEM_FAILURE;
		goto end;
	}

	if (signature_size > op_generate_sign_args.signature_size)
		signature_size = op_generate_sign_args.signature_size;

	if (signature)
		smw_sign_verify_copy_sign_buf(sign_args, signature,
					      signature_size);

	smw_sign_verify_set_sign_len(sign_args, signature_size);

	SMW_DBG_PRINTF(DEBUG, "Output (%d):\n", signature_size);
	SMW_DBG_HEX_DUMP(DEBUG, op_generate_sign_args.signature, signature_size,
			 4);

end:
	if (signature)
		SMW_UTILS_FREE(signature);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int
set_export_key_args(struct smw_keymgr_descriptor *key_descriptor,
		    struct smw_keymgr_export_key_args *export_key_args)
{
	int status = SMW_STATUS_OK;

	struct smw_keymgr_descriptor *export_key_descriptor =
		&export_key_args->key_descriptor;
	struct smw_keymgr_identifier *key_identifier =
		&export_key_descriptor->identifier;

	unsigned int public_length = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	*export_key_descriptor = *key_descriptor;
	export_key_descriptor->pub = NULL;
	export_key_descriptor->format_id = SMW_KEYMGR_FORMAT_ID_HEX;

	status = smw_keymgr_get_buffers_lengths(key_identifier,
						SMW_KEYMGR_FORMAT_ID_HEX,
						&public_length, NULL, NULL);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_keymgr_alloc_keypair_buffer(export_key_descriptor,
						 public_length, 0);
	if (status != SMW_STATUS_OK)
		goto end;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int
clear_export_key_args(struct smw_keymgr_export_key_args *export_key_args)
{
	int status = SMW_STATUS_OK;

	struct smw_keymgr_descriptor *key_descriptor =
		&export_key_args->key_descriptor;

	SMW_DBG_TRACE_FUNCTION_CALL;

	status = smw_keymgr_free_keypair_buffer(key_descriptor);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int verify(struct hdl *hdl, void *args)
{
	int status = SMW_STATUS_OK;

	hsm_err_t err = HSM_NO_ERROR;

	op_verify_sign_args_t op_verify_sign_args = { 0 };
	hsm_verification_status_t hsm_verification_status;

	struct smw_crypto_sign_verify_args *verify_args = args;
	struct smw_keymgr_descriptor *key_descriptor =
		&verify_args->key_descriptor;

	struct smw_keymgr_export_key_args export_key_args = { 0 };
	struct smw_keymgr_descriptor *export_key_descriptor =
		&export_key_args.key_descriptor;

	enum smw_config_key_type_id key_type_id;
	unsigned int security_size;
	uint8_t *key;
	uint16_t key_size;
	uint8_t *signature = NULL;
	uint16_t signature_size;
	uint16_t hsm_signature_size;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_ASSERT(verify_args);

	if (key_descriptor->format_id == SMW_KEYMGR_FORMAT_ID_INVALID) {
		status = set_export_key_args(key_descriptor, &export_key_args);
		if (status != SMW_STATUS_OK)
			goto end;

		hsm_key_handle(hdl, OPERATION_ID_EXPORT_KEY, &export_key_args,
			       &status);
		if (status != SMW_STATUS_OK)
			goto end;

		key_size = smw_keymgr_get_public_length(export_key_descriptor);
		key = smw_keymgr_get_public_data(export_key_descriptor);
	} else {
		key_size = smw_keymgr_get_public_length(key_descriptor);
		key = smw_keymgr_get_public_data(key_descriptor);
	}

	key_type_id = key_descriptor->identifier.type_id;
	security_size = key_descriptor->identifier.security_size;
	if (!security_size) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	op_verify_sign_args.key = key;
	op_verify_sign_args.message = smw_sign_verify_get_msg_buf(verify_args);
	op_verify_sign_args.signature =
		smw_sign_verify_get_sign_buf(verify_args);
	op_verify_sign_args.key_size = key_size;
	op_verify_sign_args.signature_size =
		smw_sign_verify_get_sign_len(verify_args);
	op_verify_sign_args.message_size =
		smw_sign_verify_get_msg_len(verify_args);

	hsm_signature_size = get_hsm_signature_size(security_size);
	signature_size = BITS_TO_BYTES_SIZE(security_size) * 2;
	if (op_verify_sign_args.signature_size == signature_size) {
		/* HSM requires a bigger buffer */
		signature = SMW_UTILS_MALLOC(hsm_signature_size);
		if (!signature) {
			status = SMW_STATUS_ALLOC_FAILURE;
			goto end;
		}
		SMW_UTILS_MEMCPY(signature, op_verify_sign_args.signature,
				 op_verify_sign_args.signature_size);
		op_verify_sign_args.signature = signature;
		op_verify_sign_args.signature_size = hsm_signature_size;
	}

	status = set_signature_scheme(key_type_id, security_size,
				      verify_args->algo_id,
				      &op_verify_sign_args.scheme_id);
	if (status != SMW_STATUS_OK)
		goto end;

	if (verify_args->algo_id != SMW_CONFIG_HASH_ALGO_ID_INVALID)
		op_verify_sign_args.flags =
			HSM_OP_GENERATE_SIGN_FLAGS_INPUT_MESSAGE;
	else
		op_verify_sign_args.flags =
			HSM_OP_GENERATE_SIGN_FLAGS_INPUT_DIGEST;

	SMW_DBG_PRINTF(VERBOSE,
		       "[%s (%d)] Call hsm_verify_signature()\n"
		       "  signature_ver_hdl: %d\n"
		       "  op_verify_sign_args_t\n"
		       "    key: %p\n"
		       "    message: %p\n"
		       "    signature: %p\n"
		       "    key_size: %d\n"
		       "    message_size: %d\n"
		       "    signature_size: %d\n"
		       "    scheme_id: %x\n"
		       "    flags: %x\n",
		       __func__, __LINE__, hdl->signature_ver,
		       op_verify_sign_args.key, op_verify_sign_args.message,
		       op_verify_sign_args.signature,
		       op_verify_sign_args.key_size,
		       op_verify_sign_args.message_size,
		       op_verify_sign_args.signature_size,
		       op_verify_sign_args.scheme_id,
		       op_verify_sign_args.flags);

	err = hsm_verify_signature(hdl->signature_ver, &op_verify_sign_args,
				   &hsm_verification_status);
	if (err != HSM_NO_ERROR) {
		SMW_DBG_PRINTF(DEBUG, "hsm_verify_signature returned %d\n",
			       err);
		status = SMW_STATUS_SUBSYSTEM_FAILURE;
		goto end;
	}

	if (hsm_verification_status != HSM_VERIFICATION_STATUS_SUCCESS)
		status = SMW_STATUS_SIGNATURE_INVALID;

end:
	(void)clear_export_key_args(&export_key_args);

	if (signature)
		SMW_UTILS_FREE(signature);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

bool hsm_sign_verify_handle(struct hdl *hdl, enum operation_id operation_id,
			    void *args, int *status)
{
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
