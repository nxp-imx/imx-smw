// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
 */

#include "smw_status.h"
#include "smw_crypto.h"

#include "compiler.h"
#include "global.h"
#include "debug.h"
#include "utils.h"
#include "subsystems.h"
#include "config.h"
#include "keymgr.h"
#include "sign_verify.h"

#include "common.h"

/* Workaround */
#define HSM_SIGNATURE_SCHEME_ECDSA_ANY 0x06000600

#define SIGNATURE_SCHEME_ID(_key_type_id, _key_sizes, _hash, _scheme)          \
	{                                                                      \
		.key_type_id = SMW_CONFIG_KEY_TYPE_ID_##_key_type_id,          \
		.algo_id = SMW_CONFIG_HASH_ALGO_ID_##_hash,                    \
		.security_sizes = _key_sizes,                                  \
		.scheme_id = HSM_SIGNATURE_SCHEME_##_scheme                    \
	}

/*
 * Array of security key sizes supported for the signature per key type.
 * Last item must be 0.
 */
static const unsigned int ecdsa_nist_key_sizes[] = { 224, 256, 384, 521, 0 };
static const unsigned int ecdsa_r1_key_sizes[] = { 224, 256, 384, 0 };

static const struct signature_scheme {
	enum smw_config_key_type_id key_type_id;
	enum smw_config_hash_algo_id algo_id;
	const unsigned int *security_sizes;
	hsm_signature_scheme_id_t scheme_id;
} signature_schemes[] = {
	SIGNATURE_SCHEME_ID(ECDSA_NIST, ecdsa_nist_key_sizes, INVALID,
			    ECDSA_ANY),
	SIGNATURE_SCHEME_ID(ECDSA_NIST, ecdsa_nist_key_sizes, SHA224,
			    ECDSA_SHA224),
	SIGNATURE_SCHEME_ID(ECDSA_NIST, ecdsa_nist_key_sizes, SHA256,
			    ECDSA_SHA256),
	SIGNATURE_SCHEME_ID(ECDSA_NIST, ecdsa_nist_key_sizes, SHA384,
			    ECDSA_SHA384),
	SIGNATURE_SCHEME_ID(ECDSA_NIST, ecdsa_nist_key_sizes, SHA512,
			    ECDSA_SHA512),
	SIGNATURE_SCHEME_ID(ECDSA_BRAINPOOL_R1, ecdsa_r1_key_sizes, INVALID,
			    ECDSA_ANY),
	SIGNATURE_SCHEME_ID(ECDSA_BRAINPOOL_R1, ecdsa_r1_key_sizes, SHA224,
			    ECDSA_SHA224),
	SIGNATURE_SCHEME_ID(ECDSA_BRAINPOOL_R1, ecdsa_r1_key_sizes, SHA256,
			    ECDSA_SHA256),
	SIGNATURE_SCHEME_ID(ECDSA_BRAINPOOL_R1, ecdsa_r1_key_sizes, SHA384,
			    ECDSA_SHA384),
};

static bool check_security_size(unsigned int security_size,
				const struct signature_scheme *scheme)
{
	const unsigned int *check_size = scheme->security_sizes;

	while (*check_size) {
		if (security_size == *check_size)
			return true;

		check_size++;
	}

	return false;
}

static int set_signature_scheme(enum smw_config_key_type_id key_type_id,
				unsigned int security_size,
				enum smw_config_hash_algo_id algo_id,
				hsm_signature_scheme_id_t *scheme_id)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	unsigned int i = 0;
	const struct signature_scheme *scheme = signature_schemes;

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (; i < ARRAY_SIZE(signature_schemes); i++, scheme++) {
		if (scheme->key_type_id == key_type_id) {
			if (scheme->algo_id != algo_id)
				continue;

			if (!check_security_size(security_size, scheme))
				break;

			*scheme_id = scheme->scheme_id;
			SMW_DBG_PRINTF(DEBUG, "ELE Signature Scheme ID: 0x%X\n",
				       *scheme_id);
			status = SMW_STATUS_OK;
			break;
		}
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

__weak int tls_mac_finish(struct hdl *hdl, void *args)
{
	(void)hdl;
	(void)args;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

static int sign(struct hdl *hdl, void *args)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	hsm_err_t err = HSM_NO_ERROR;
	op_generate_sign_args_t op_args = { 0 };

	struct smw_crypto_sign_verify_args *sign_args = args;
	struct smw_keymgr_descriptor *key_desc = &sign_args->key_descriptor;
	struct smw_keymgr_identifier *key_identifier = &key_desc->identifier;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (key_desc->format_id != SMW_KEYMGR_FORMAT_ID_INVALID) {
		//TODO: first import key, then sign
		//      for now import is not supported by ELE
		goto end;
	}

	/* TLS finish case */
	if (sign_args->attributes.tls_label !=
	    SMW_CONFIG_TLS_FINISH_ID_INVALID) {
		status = tls_mac_finish(hdl, args);
		goto end;
	}

	op_args.key_identifier = key_identifier->id;
	op_args.message = smw_sign_verify_get_msg_buf(sign_args);
	op_args.signature = smw_sign_verify_get_sign_buf(sign_args);
	op_args.message_size = smw_sign_verify_get_msg_len(sign_args);

	if (SET_OVERFLOW(smw_sign_verify_get_sign_len(sign_args),
			 op_args.signature_size)) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	if (sign_args->algo_id != SMW_CONFIG_HASH_ALGO_ID_INVALID)
		op_args.flags = HSM_OP_GENERATE_SIGN_FLAGS_INPUT_MESSAGE;
	else
		op_args.flags = HSM_OP_GENERATE_SIGN_FLAGS_INPUT_DIGEST;

	status = set_signature_scheme(key_identifier->type_id,
				      key_identifier->security_size,
				      sign_args->algo_id, &op_args.scheme_id);
	if (status != SMW_STATUS_OK)
		goto end;

	SMW_DBG_PRINTF(VERBOSE,
		       "[%s (%d)] Call hsm_generate_signature()\n"
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
	SMW_DBG_PRINTF(DEBUG, "hsm_generate_signature returned %d\n", err);

	status = ele_convert_err(err);

	smw_sign_verify_set_sign_len(sign_args, op_args.exp_signature_size);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int verify(struct hdl *hdl, void *args)
{
	int status = SMW_STATUS_OK;

	hsm_err_t err = HSM_NO_ERROR;
	op_verify_sign_args_t op_args = { 0 };
	hsm_verification_status_t hsm_verification_status = 0;

	struct smw_crypto_sign_verify_args *verify_args = args;
	struct smw_keymgr_descriptor *key_desc = &verify_args->key_descriptor;

	struct smw_keymgr_descriptor export_key_desc = { 0 };

	enum smw_config_key_type_id key_type_id = 0;
	unsigned int security_size = 0;
	uint8_t *key_buf = NULL;
	unsigned int key_size = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (key_desc->format_id == SMW_KEYMGR_FORMAT_ID_INVALID) {
		export_key_desc.identifier.id = key_desc->identifier.id;
		status = ele_export_public_key(hdl, &export_key_desc);
		if (status != SMW_STATUS_OK)
			goto end;

		key_size = smw_keymgr_get_public_length(&export_key_desc);
		key_buf = smw_keymgr_get_public_data(&export_key_desc);
		security_size = export_key_desc.identifier.security_size;
		key_type_id = export_key_desc.identifier.type_id;
	} else {
		key_size = smw_keymgr_get_public_length(key_desc);
		key_buf = smw_keymgr_get_public_data(key_desc);
		security_size = key_desc->identifier.security_size;
		key_type_id = key_desc->identifier.type_id;
	}

	if (!security_size) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	status = ele_set_pubkey_type(key_type_id, &op_args.pkey_type);
	if (status != SMW_STATUS_OK)
		goto end;

	op_args.key_sz = security_size;
	op_args.key = key_buf;
	op_args.message = smw_sign_verify_get_msg_buf(verify_args);
	op_args.signature = smw_sign_verify_get_sign_buf(verify_args);
	op_args.message_size = smw_sign_verify_get_msg_len(verify_args);

	if (SET_OVERFLOW(key_size, op_args.key_size)) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	if (SET_OVERFLOW(smw_sign_verify_get_sign_len(verify_args),
			 op_args.signature_size)) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	status = set_signature_scheme(key_type_id, security_size,
				      verify_args->algo_id, &op_args.scheme_id);
	if (status != SMW_STATUS_OK)
		goto end;

	if (verify_args->algo_id != SMW_CONFIG_HASH_ALGO_ID_INVALID)
		op_args.flags = HSM_OP_GENERATE_SIGN_FLAGS_INPUT_MESSAGE;
	else
		op_args.flags = HSM_OP_GENERATE_SIGN_FLAGS_INPUT_DIGEST;

	SMW_DBG_PRINTF(VERBOSE,
		       "[%s (%d)] Call hsm_verify_signature()\n"
		       "  op_args_t\n"
		       "    scheme_id: 0x%08X\n"
		       "    flags: 0x%X\n"
		       "    Public Key\n"
		       "      - type: 0x%04X\n"
		       "      - security size: %d\n"
		       "      - buffer: %p\n"
		       "      - size: %d\n"
		       "    Message\n"
		       "      - buffer: %p\n"
		       "      - size: %d\n"
		       "    Signature\n"
		       "      - buffer: %p\n"
		       "      - size: %d\n",
		       __func__, __LINE__, op_args.scheme_id, op_args.flags,
		       op_args.pkey_type, op_args.key_sz, op_args.key,
		       op_args.key_size, op_args.message, op_args.message_size,
		       op_args.signature, op_args.signature_size);

	err = hsm_verify_sign(hdl->session, &op_args, &hsm_verification_status);

	status = ele_convert_err(err);
	SMW_DBG_PRINTF(DEBUG, "hsm_verify_signature returned %d\n", err);

	if (hsm_verification_status != HSM_VERIFICATION_STATUS_SUCCESS)
		status = SMW_STATUS_SIGNATURE_INVALID;

end:
	if (export_key_desc.pub)
		(void)smw_keymgr_free_keypair_buffer(&export_key_desc);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

bool ele_sign_verify_handle(struct hdl *hdl, enum operation_id operation_id,
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
