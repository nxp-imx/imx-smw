// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2025 NXP
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

/* Covers both Ed25519 (64) and Ed448 (114) */
#define MAX_ED_SIGN_SIZE 114

/* Covers both Ed25519 (32) and Ed448 (57) */
#define MAX_ED_PUB_KEY_SIZE 57

/* Workaround */
#define HSM_SIGNATURE_SCHEME_ECDSA_ANY 0x06000600

#define SIGNATURE_SCHEME_ID(_key_type_id, _key_sizes, _type, _hash, _scheme)   \
	{                                                                      \
		.key_type_id = SMW_CONFIG_KEY_TYPE_ID_##_key_type_id,          \
		.security_sizes = _key_sizes,                                  \
		.type_id = SMW_CONFIG_SIGN_TYPE_ID_##_type,                    \
		.hash_id = SMW_CONFIG_HASH_ALGO_ID_##_hash,                    \
		.scheme_id = HSM_SIGNATURE_SCHEME_##_scheme                    \
	}

/*
 * Array of security key sizes supported for the signature per key type.
 * Last item must be 0.
 */
static const unsigned int secp_r1_key_sizes[] = { 224, 256, 384, 521, 0 };
static const unsigned int brainpool_r1_key_sizes[] = { 224, 256, 384, 0 };
static const unsigned int rsa_key_sizes[] = { 2048, 3072, 4096, 0 };
static const unsigned int ed25519_key_sizes[] = { 255, 0 };

static const struct signature_scheme {
	enum smw_config_key_type_id key_type_id;
	const unsigned int *security_sizes;
	enum smw_config_sign_type_id type_id;
	enum smw_config_hash_algo_id hash_id;
	hsm_signature_scheme_id_t scheme_id;
} signature_schemes[] = {
	SIGNATURE_SCHEME_ID(SECP_R1, secp_r1_key_sizes, DEFAULT, INVALID,
			    ECDSA_ANY),
	SIGNATURE_SCHEME_ID(SECP_R1, secp_r1_key_sizes, DEFAULT, SHA224,
			    ECDSA_SHA224),
	SIGNATURE_SCHEME_ID(SECP_R1, secp_r1_key_sizes, DEFAULT, SHA256,
			    ECDSA_SHA256),
	SIGNATURE_SCHEME_ID(SECP_R1, secp_r1_key_sizes, DEFAULT, SHA384,
			    ECDSA_SHA384),
	SIGNATURE_SCHEME_ID(SECP_R1, secp_r1_key_sizes, DEFAULT, SHA512,
			    ECDSA_SHA512),
	SIGNATURE_SCHEME_ID(BRAINPOOL_R1, brainpool_r1_key_sizes, DEFAULT,
			    INVALID, ECDSA_ANY),
	SIGNATURE_SCHEME_ID(BRAINPOOL_R1, brainpool_r1_key_sizes, DEFAULT,
			    SHA224, ECDSA_SHA224),
	SIGNATURE_SCHEME_ID(BRAINPOOL_R1, brainpool_r1_key_sizes, DEFAULT,
			    SHA256, ECDSA_SHA256),
	SIGNATURE_SCHEME_ID(BRAINPOOL_R1, brainpool_r1_key_sizes, DEFAULT,
			    SHA384, ECDSA_SHA384),
	SIGNATURE_SCHEME_ID(RSA, rsa_key_sizes, PKCS1_1_5, SHA224,
			    RSA_PKCS1_V15_SHA224),
	SIGNATURE_SCHEME_ID(RSA, rsa_key_sizes, PKCS1_1_5, SHA256,
			    RSA_PKCS1_V15_SHA256),
	SIGNATURE_SCHEME_ID(RSA, rsa_key_sizes, PKCS1_1_5, SHA384,
			    RSA_PKCS1_V15_SHA384),
	SIGNATURE_SCHEME_ID(RSA, rsa_key_sizes, PKCS1_1_5, SHA512,
			    RSA_PKCS1_V15_SHA512),
	SIGNATURE_SCHEME_ID(RSA, rsa_key_sizes, PSS, SHA224,
			    RSA_PKCS1_PSS_MGF1_SHA224),
	SIGNATURE_SCHEME_ID(RSA, rsa_key_sizes, PSS, SHA256,
			    RSA_PKCS1_PSS_MGF1_SHA256),
	SIGNATURE_SCHEME_ID(RSA, rsa_key_sizes, PSS, SHA384,
			    RSA_PKCS1_PSS_MGF1_SHA384),
	SIGNATURE_SCHEME_ID(RSA, rsa_key_sizes, PSS, SHA512,
			    RSA_PKCS1_PSS_MGF1_SHA512),
	SIGNATURE_SCHEME_ID(ED25519, ed25519_key_sizes, PURE_EDDSA, INVALID,
			    PURE_EDDSA),
	SIGNATURE_SCHEME_ID(ED25519, ed25519_key_sizes, EDDSA_PH, INVALID,
			    ED25519PH),
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
				struct smw_sign_verify_attributes *attributes,
				hsm_signature_scheme_id_t *scheme_id)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	unsigned int i = 0;
	const struct signature_scheme *scheme = signature_schemes;

	enum smw_config_hash_algo_id hash_id = attributes->hash_id;
	enum smw_config_sign_type_id type_id = attributes->type_id;

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (; i < ARRAY_SIZE(signature_schemes); i++, scheme++) {
		if (scheme->key_type_id == key_type_id) {
			if (scheme->type_id !=
				    SMW_CONFIG_SIGN_TYPE_ID_DEFAULT &&
			    scheme->type_id != type_id)
				continue;

			if (scheme->hash_id != hash_id)
				continue;

			if (!check_security_size(security_size, scheme))
				break;

			*scheme_id = scheme->scheme_id;
			SMW_DBG_PRINTF(DEBUG,
				       "ELE Signature Scheme ID: 0x%08X\n",
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

static int check_rsa_pub_expo(struct smw_keymgr_descriptor *key_desc)
{
	int status = SMW_STATUS_OK;

	unsigned char *hex_pub_data = NULL;
	unsigned int hex_pub_len = 0;
	unsigned char *public_data = NULL;
	unsigned int public_len = 0;
	int i = 0;

	public_len = smw_keymgr_get_public_length(key_desc);
	public_data = smw_keymgr_get_public_data(key_desc);

	status = smw_keymgr_set_hex_key_buffer(key_desc->format_id, public_data,
					       public_len, &hex_pub_data,
					       &hex_pub_len);
	if (status != SMW_STATUS_OK)
		goto end;

	if (hex_pub_len != DEFAULT_RSA_PUB_EXP_LEN) {
		status = SMW_STATUS_PUBLIC_EXPONENT_NOT_SUPPORTED;
		SMW_DBG_PRINTF(DEBUG, "Unsupported RSA public exponent.\n");
		goto end;
	}

	for (; i < DEFAULT_RSA_PUB_EXP_LEN; i++) {
		if (hex_pub_data[i] !=
		    ((DEFAULT_RSA_PUB_EXP >> (i * 8)) & UCHAR_MAX)) {
			status = SMW_STATUS_PUBLIC_EXPONENT_NOT_SUPPORTED;
			SMW_DBG_PRINTF(DEBUG,
				       "Unsupported RSA public exponent.\n");
			break;
		}
	}

end:
	if (key_desc->format_id == SMW_KEYMGR_FORMAT_ID_BASE64 && hex_pub_data)
		SMW_UTILS_FREE(hex_pub_data);

	return status;
}

static int get_private_key_buffer(op_generate_sign_args_t *op_args,
				  struct smw_keymgr_descriptor *key_desc,
				  unsigned char **hex_private_buffer,
				  unsigned char **hex_modulus,
				  unsigned char **rsa_private_key_buf)
{
	int status = SMW_STATUS_INVALID_PARAM;

	unsigned int private_buf_len = smw_keymgr_get_private_length(key_desc);
	unsigned char *private_buffer = smw_keymgr_get_private_data(key_desc);
	unsigned int modulus_len = 0;
	unsigned char *modulus_buffer = NULL;
	unsigned int hex_modulus_len = 0;
	unsigned int hex_private_len = 0;

	struct smw_keymgr_identifier *key_identifier = &key_desc->identifier;

	if (!private_buf_len || !private_buffer)
		goto end;

	status = smw_keymgr_set_hex_key_buffer(key_desc->format_id,
					       private_buffer, private_buf_len,
					       hex_private_buffer,
					       &hex_private_len);
	if (status != SMW_STATUS_OK)
		goto end;

	if (key_identifier->type_id == SMW_CONFIG_KEY_TYPE_ID_RSA) {
		modulus_len = smw_keymgr_get_modulus_length(key_desc);
		modulus_buffer = smw_keymgr_get_modulus(key_desc);

		if (!modulus_len || !modulus_buffer || !rsa_private_key_buf) {
			status = SMW_STATUS_INVALID_PARAM;
			goto end;
		}

		status = smw_keymgr_set_hex_key_buffer(key_desc->format_id,
						       modulus_buffer,
						       modulus_len, hex_modulus,
						       &hex_modulus_len);
		if (status != SMW_STATUS_OK)
			goto end;

		if (ADD_OVERFLOW(hex_private_len, hex_modulus_len,
				 &op_args->priv_key_size)) {
			status = SMW_STATUS_INVALID_PARAM;
			goto end;
		}

		*rsa_private_key_buf = SMW_UTILS_MALLOC(op_args->priv_key_size);
		if (!*rsa_private_key_buf) {
			status = SMW_STATUS_ALLOC_FAILURE;
			goto end;
		}

		SMW_UTILS_MEMCPY(*rsa_private_key_buf, *hex_private_buffer,
				 hex_private_len);

		SMW_UTILS_MEMCPY(*rsa_private_key_buf + hex_private_len,
				 *hex_modulus, hex_modulus_len);

		op_args->priv_key = *rsa_private_key_buf;

	} else {
		if (SET_OVERFLOW(private_buf_len, op_args->priv_key_size)) {
			status = SMW_STATUS_INVALID_PARAM;
			goto end;
		}

		op_args->priv_key = *hex_private_buffer;
	}

end:
	return status;
}

static int sign(struct hdl *hdl, void *args)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	hsm_err_t err = HSM_NO_ERROR;
	op_generate_sign_args_t op_args = { 0 };

	struct smw_crypto_sign_verify_args *sign_args = args;
	struct smw_keymgr_descriptor *key_desc = &sign_args->key_descriptor;
	struct smw_keymgr_identifier *key_identifier = &key_desc->identifier;
	hsm_key_type_t ele_key_type = (hsm_key_type_t)0;

	unsigned char *hex_private_buffer = NULL;
	unsigned char *hex_modulus = NULL;
	unsigned char *rsa_private_key_buf = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	/* TLS finish case */
	if (sign_args->attributes.algo_id == SMW_CONFIG_SIGN_ALGO_ID_TLS_1_2) {
		if (key_desc->format_id != SMW_KEYMGR_FORMAT_ID_INVALID)
			//TODO: first import key, then sign
			//      for now import is not supported by ELE
			goto end;

		status = tls_mac_finish(hdl, args);
		goto end;
	}

	if (key_identifier->s_id) {
		op_args.key_identifier = key_identifier->s_id;
	} else {
		/* Sign using plaintext key buffer */
		op_args.flags = HSM_OP_GENERATE_SIGN_FLAGS_PLAINTEXT_KEY;
		status = ele_get_key_type(key_identifier->type_id,
					  &ele_key_type);
		if (status != SMW_STATUS_OK)
			goto end;

		op_args.key_type = ele_key_type;

		if (SET_OVERFLOW(key_identifier->security_size,
				 op_args.key_security_size)) {
			status = SMW_STATUS_INVALID_PARAM;
			goto end;
		}

		status = get_private_key_buffer(&op_args, key_desc,
						&hex_private_buffer,
						&hex_modulus,
						&rsa_private_key_buf);
		if (status != SMW_STATUS_OK)
			goto end;
	}

	if (SET_OVERFLOW(sign_args->attributes.salt_length, op_args.salt_len)) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	op_args.message = smw_sign_verify_get_msg_buf(sign_args);
	op_args.signature = smw_sign_verify_get_sign_buf(sign_args);
	op_args.message_size = smw_sign_verify_get_msg_len(sign_args);

	if (SET_OVERFLOW(smw_sign_verify_get_sign_len(sign_args),
			 op_args.signature_size)) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	status = set_signature_scheme(key_identifier->type_id,
				      key_identifier->security_size,
				      &sign_args->attributes,
				      &op_args.scheme_id);
	if (status != SMW_STATUS_OK)
		goto end;

	if (key_identifier->type_id == SMW_CONFIG_KEY_TYPE_ID_ED25519 &&
	    smw_sign_verify_get_ed25519ctx_buf(args)) {
		status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
		goto end;
	}

	if (sign_args->attributes.msg_hashed)
		op_args.flags |= HSM_OP_GENERATE_SIGN_FLAGS_INPUT_DIGEST;
	else
		op_args.flags |= HSM_OP_GENERATE_SIGN_FLAGS_INPUT_MESSAGE;

	SMW_DBG_PRINTF(VERBOSE,
		       "[%s (%d)] Call hsm_do_sign()\n"
		       "op_generate_sign_args_t\n"
		       "    key_identifier: 0x%08X\n"
		       "    Plaintext Private Key\n"
		       "      - key_type: 0x%08X\n"
		       "      - key_security_size (bits): %d\n"
		       "      - Private Key\n"
		       "        - buffer: %p\n"
		       "        - size: %d\n"
		       "    scheme_id: 0x%08X\n"
		       "    flags: 0x%X\n"
		       "    salt_len: %d\n"
		       "    Message\n"
		       "      - buffer: %p\n"
		       "      - size: %d\n"
		       "    Signature\n"
		       "      - buffer: %p\n"
		       "      - size: %d\n",
		       __func__, __LINE__, op_args.key_identifier,
		       op_args.key_type, op_args.key_security_size,
		       op_args.priv_key, op_args.priv_key_size,
		       op_args.scheme_id, op_args.flags, op_args.salt_len,
		       op_args.message, op_args.message_size, op_args.signature,
		       op_args.signature_size);

	err = hsm_do_sign(hdl->key_store, &op_args);
	SMW_DBG_PRINTF(DEBUG, "hsm_do_sign returned %d\n", err);

	status = ele_convert_err(err);

	smw_sign_verify_set_sign_len(sign_args, op_args.exp_signature_size);

	if (status != SMW_STATUS_OK)
		goto end;

	/*
	 * For platforms i.MX91 and i.MX93, signature generated using EDDSA
	 * algorithm is encoded in big-endian format. Hence, convert it to little
	 * endian.
	 */
	status = check_and_convert_sign_endian(op_args.signature, NULL,
					       op_args.exp_signature_size,
					       key_identifier->type_id);
	if (status != SMW_STATUS_OK)
		status = SMW_STATUS_OPERATION_FAILURE;

end:
	if (key_desc->format_id == SMW_KEYMGR_FORMAT_ID_BASE64) {
		if (hex_private_buffer)
			SMW_UTILS_FREE(hex_private_buffer);

		if (hex_modulus)
			SMW_UTILS_FREE(hex_modulus);
	}

	if (rsa_private_key_buf)
		SMW_UTILS_FREE(rsa_private_key_buf);

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
	struct smw_keymgr_descriptor *key_desc = &verify_args->key_descriptor;

	struct smw_keymgr_descriptor export_key_desc = { 0 };

	enum smw_config_key_type_id key_type_id = 0;
	enum smw_keymgr_format_id format_id = 0;
	unsigned int security_size = 0;
	uint8_t *key_buf = NULL;
	unsigned int key_size = 0;
	unsigned char *hex_key_buf = NULL;
	unsigned int hex_key_size = 0;
	unsigned char temp_sign[MAX_ED_SIGN_SIZE] = { 0 };
	unsigned char temp_pub_key[MAX_ED_PUB_KEY_SIZE] = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	format_id = key_desc->format_id;

	if (format_id == SMW_KEYMGR_FORMAT_ID_INVALID) {
		export_key_desc.identifier.s_id = key_desc->identifier.s_id;

		status = ele_export_public_key(hdl, &export_key_desc);
		if (status != SMW_STATUS_OK)
			goto end;

		security_size = export_key_desc.identifier.security_size;
		key_type_id = export_key_desc.identifier.type_id;

		if (key_type_id == SMW_CONFIG_KEY_TYPE_ID_RSA) {
			hex_key_size =
				smw_keymgr_get_modulus_length(&export_key_desc);
			hex_key_buf = smw_keymgr_get_modulus(&export_key_desc);

		} else {
			hex_key_size =
				smw_keymgr_get_public_length(&export_key_desc);
			hex_key_buf =
				smw_keymgr_get_public_data(&export_key_desc);
		}

	} else {
		/* Verify signature using plaintext key buffer */
		security_size = key_desc->identifier.security_size;
		key_type_id = key_desc->identifier.type_id;

		if (key_type_id == SMW_CONFIG_KEY_TYPE_ID_RSA) {
			status = check_rsa_pub_expo(key_desc);
			if (status != SMW_STATUS_OK)
				goto end;

			key_size = smw_keymgr_get_modulus_length(key_desc);
			key_buf = smw_keymgr_get_modulus(key_desc);

			status =
				smw_keymgr_set_hex_key_buffer(format_id,
							      key_buf, key_size,
							      &hex_key_buf,
							      &hex_key_size);
			if (status != SMW_STATUS_OK)
				goto end;

		} else {
			key_size = smw_keymgr_get_public_length(key_desc);
			key_buf = smw_keymgr_get_public_data(key_desc);

			status =
				smw_keymgr_set_hex_key_buffer(format_id,
							      key_buf, key_size,
							      &hex_key_buf,
							      &hex_key_size);
			if (status != SMW_STATUS_OK)
				goto end;
		}
	}

	if (!security_size) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	status = ele_set_pubkey_type(key_type_id, &op_args.pkey_type);
	if (status != SMW_STATUS_OK)
		goto end;

	op_args.key_sz = security_size;
	op_args.key = hex_key_buf;
	op_args.message = smw_sign_verify_get_msg_buf(verify_args);
	op_args.signature = smw_sign_verify_get_sign_buf(verify_args);
	op_args.message_size = smw_sign_verify_get_msg_len(verify_args);

	if (SET_OVERFLOW(hex_key_size, op_args.key_size)) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	if (SET_OVERFLOW(smw_sign_verify_get_sign_len(verify_args),
			 op_args.signature_size)) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	if (SET_OVERFLOW(verify_args->attributes.salt_length,
			 op_args.salt_len)) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	status = set_signature_scheme(key_type_id, security_size,
				      &verify_args->attributes,
				      &op_args.scheme_id);
	if (status != SMW_STATUS_OK)
		goto end;

	if (key_type_id == SMW_CONFIG_KEY_TYPE_ID_ED25519 &&
	    smw_sign_verify_get_ed25519ctx_buf(args)) {
		status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
		goto end;
	}

	/*
	 * On i.MX91 and i.MX93 platforms, EDDSA-based signature verification
	 * mandates the following input format requirements:
	 * - The signature must also be encoded in big-endian format to
	 *   ensure correct cryptographic validation.
	 * - The public key buffer must be encoded in big-endian format.
	 */
	status = check_and_convert_sign_endian(op_args.signature, temp_sign,
					       op_args.signature_size,
					       key_type_id);
	if (status != SMW_STATUS_OK)
		goto end;

	status = check_and_convert_endian(hex_key_buf, temp_pub_key,
					  hex_key_size, key_type_id);
	if (status != SMW_STATUS_OK)
		goto end;

	if (key_type_id == SMW_CONFIG_KEY_TYPE_ID_ED25519) {
		op_args.signature = temp_sign;
		op_args.key = temp_pub_key;
	}

	if (verify_args->attributes.msg_hashed)
		op_args.flags = HSM_OP_VERIFY_SIGN_FLAGS_INPUT_DIGEST;
	else
		op_args.flags = HSM_OP_VERIFY_SIGN_FLAGS_INPUT_MESSAGE;

	SMW_DBG_PRINTF(VERBOSE,
		       "[%s (%d)] Call hsm_verify_sign()\n"
		       "  op_verify_sign_args_t\n"
		       "    scheme_id: 0x%08X\n"
		       "    flags: 0x%X\n"
		       "    Public Key\n"
		       "      - type: 0x%04X\n"
		       "      - security size: %d\n"
		       "      - buffer: %p\n"
		       "      - size: %d\n"
		       "    salt_len: %d\n"
		       "    Message\n"
		       "      - buffer: %p\n"
		       "      - size: %d\n"
		       "    Signature\n"
		       "      - buffer: %p\n"
		       "      - size: %d\n",
		       __func__, __LINE__, op_args.scheme_id, op_args.flags,
		       op_args.pkey_type, op_args.key_sz, op_args.key,
		       op_args.key_size, op_args.salt_len, op_args.message,
		       op_args.message_size, op_args.signature,
		       op_args.signature_size);

	err = hsm_verify_sign(hdl->session, &op_args, &verification_status);

	status = ele_convert_err(err);
	SMW_DBG_PRINTF(DEBUG, "hsm_verify_sign returned %d\n", err);

	if (verification_status != HSM_VERIFICATION_STATUS_SUCCESS)
		status = SMW_STATUS_SIGNATURE_INVALID;

end:
	if (export_key_desc.pub)
		(void)smw_keymgr_free_keypair_buffer(&export_key_desc);

	if (format_id == SMW_KEYMGR_FORMAT_ID_BASE64 && hex_key_buf)
		SMW_UTILS_FREE(hex_key_buf);

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
