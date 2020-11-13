// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020 NXP
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
#include "keymgr.h"
#include "sign_verify.h"

#include "common.h"

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
struct {
	enum smw_config_key_type_id key_type_id;
	unsigned int security_size;
	enum smw_config_hash_algo_id algo_id;
	hsm_signature_scheme_id_t hsm_signature_scheme_id;
} signature_scheme_ids[] = {
	SIGNATURE_SCHEME_ID(ECDSA_NIST, 256, SHA256, ECDSA_NIST_P256_SHA_256),
	SIGNATURE_SCHEME_ID(ECDSA_NIST, 384, SHA384, ECDSA_NIST_P384_SHA_384),
	SIGNATURE_SCHEME_ID(ECDSA_NIST, 521, SHA512, ECDSA_NIST_P521_SHA_512),
	SIGNATURE_SCHEME_ID(ECDSA_BRAINPOOL_R1, 256, SHA256,
			    ECDSA_BRAINPOOL_R1_256_SHA_256),
	SIGNATURE_SCHEME_ID(ECDSA_BRAINPOOL_R1, 320, SHA384,
			    ECDSA_BRAINPOOL_R1_320_SHA_384),
	SIGNATURE_SCHEME_ID(ECDSA_BRAINPOOL_R1, 384, SHA384,
			    ECDSA_BRAINPOOL_R1_384_SHA_384),
	SIGNATURE_SCHEME_ID(ECDSA_BRAINPOOL_R1, 512, SHA512,
			    ECDSA_BRAINPOOL_R1_512_SHA_512),
	SIGNATURE_SCHEME_ID(ECDSA_BRAINPOOL_T1, 256, SHA256,
			    ECDSA_BRAINPOOL_T1_256_SHA_256),
	SIGNATURE_SCHEME_ID(ECDSA_BRAINPOOL_T1, 384, SHA384,
			    ECDSA_BRAINPOOL_T1_384_SHA_384),
	SIGNATURE_SCHEME_ID(ECDSA_BRAINPOOL_T1, 512, SHA512,
			    ECDSA_BRAINPOOL_T1_512_SHA_512),
	SIGNATURE_SCHEME_ID(DSA_SM2_FP, 256, SM3, DSA_SM2_FP_256_SM3)
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
		if (signature_scheme_ids[i].algo_id < algo_id)
			continue;
		if (signature_scheme_ids[i].algo_id > algo_id)
			goto end;
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

static int sign(struct hdl *hdl, void *args)
{
	int status = SMW_STATUS_OK;

	hsm_err_t err = HSM_NO_ERROR;

	op_generate_sign_args_t op_generate_sign_args;

	struct smw_crypto_sign_args *sign_args = args;
	struct smw_keymgr_descriptor *key_descriptor =
		&sign_args->key_descriptor;
	struct smw_keymgr_identifier *key_identifier =
		&key_descriptor->identifier;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_ASSERT(sign_args);

	if (key_descriptor->format_id == SMW_KEYMGR_FORMAT_ID_INVALID) {
		//TODO: first import key, then sign
		//      for now import is not supported by HSM
		status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
		goto end;
	}

	op_generate_sign_args.key_identifier = key_identifier->id;
	op_generate_sign_args.message = sign_args->message;
	op_generate_sign_args.signature = sign_args->signature;
	op_generate_sign_args.message_size = sign_args->message_length;
	op_generate_sign_args.signature_size = sign_args->signature_length;

	status = set_signature_scheme(key_identifier->type_id,
				      key_identifier->security_size,
				      sign_args->algo_id,
				      &op_generate_sign_args.scheme_id);
	if (status != SMW_STATUS_OK)
		goto end;

	op_generate_sign_args.flags =
		(sign_args->hashed) ? HSM_OP_GENERATE_SIGN_FLAGS_INPUT_DIGEST :
				      HSM_OP_GENERATE_SIGN_FLAGS_INPUT_MESSAGE;

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

	SMW_DBG_PRINTF(DEBUG, "Output (%d):\n", sign_args->signature_length);
	SMW_DBG_HEX_DUMP(DEBUG, sign_args->signature,
			 sign_args->signature_length, 4);

end:
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

	smw_keymgr_set_default_attributes(&export_key_args->key_attributes);
	*export_key_descriptor = *key_descriptor;
	export_key_descriptor->pub = NULL;
	export_key_descriptor->format_id = SMW_KEYMGR_FORMAT_ID_HEX;

	status = smw_keymgr_get_buffers_lengths(key_identifier->type_id,
						key_identifier->security_size,
						SMW_KEYMGR_FORMAT_ID_HEX,
						&public_length, NULL);
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

	struct smw_crypto_verify_args *verify_args = args;
	struct smw_keymgr_descriptor *key_descriptor =
		&verify_args->key_descriptor;

	struct smw_keymgr_export_key_args export_key_args = { 0 };
	struct smw_keymgr_descriptor *export_key_descriptor =
		&export_key_args.key_descriptor;

	enum smw_config_key_type_id key_type_id;
	unsigned int security_size;
	uint8_t *key;
	uint16_t key_size;
	hsm_op_verify_sign_flags_t flags =
		(verify_args->hashed) ? HSM_OP_VERIFY_SIGN_FLAGS_INPUT_DIGEST :
					HSM_OP_VERIFY_SIGN_FLAGS_INPUT_MESSAGE;

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

	op_verify_sign_args.key = key;
	op_verify_sign_args.message = verify_args->message;
	op_verify_sign_args.signature = verify_args->signature;
	op_verify_sign_args.key_size = key_size;
	op_verify_sign_args.signature_size = verify_args->signature_length;
	op_verify_sign_args.message_size = verify_args->message_length;

	status = set_signature_scheme(key_type_id, security_size,
				      verify_args->algo_id,
				      &op_verify_sign_args.scheme_id);
	if (status != SMW_STATUS_OK)
		goto end;

	op_verify_sign_args.flags = flags;

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
