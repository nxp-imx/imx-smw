// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2025 NXP
 */

#include "smw_status.h"
#include "smw_crypto.h"

#include "global.h"
#include "debug.h"
#include "utils.h"
#include "subsystems.h"
#include "config.h"
#include "keymgr.h"
#include "sign_verify.h"
#include "hash.h"

#include "common.h"

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
static const unsigned int ed448_key_sizes[] = { 448, 0 };

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
	SIGNATURE_SCHEME_ID(ED25519, ed25519_key_sizes, PURE_EDDSA, SHA512,
			    PURE_EDDSA),
	SIGNATURE_SCHEME_ID(ED25519, ed25519_key_sizes, EDDSA_PH, INVALID,
			    ED25519PH),
	SIGNATURE_SCHEME_ID(ED25519, ed25519_key_sizes, EDDSA_PH, SHA512,
			    ED25519PH),
	SIGNATURE_SCHEME_ID(ED448, ed448_key_sizes, PURE_EDDSA, INVALID,
			    PURE_EDDSA),
	SIGNATURE_SCHEME_ID(ED448, ed448_key_sizes, PURE_EDDSA, SHAKE256,
			    PURE_EDDSA),
	SIGNATURE_SCHEME_ID(ED448, ed448_key_sizes, EDDSA_PH, INVALID, ED448PH),
	SIGNATURE_SCHEME_ID(ED448, ed448_key_sizes, EDDSA_PH, SHAKE256,
			    ED448PH),
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
			    scheme->type_id != type_id) {
				/*
				 * In case the signature type is not default, if user
				 * doesn't set the correct one, returns invalid parameter.
				 */
				status = SMW_STATUS_INVALID_PARAM;
				continue;
			}

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

	status = smw_utils_key_set_hex_buffer(key_desc->format_id,
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

		status = smw_utils_key_set_hex_buffer(key_desc->format_id,
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

static int sign(struct subsystem_context *ele_ctx, void *args)
{
	int status = SMW_STATUS_OK;

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

		status = tls_mac_finish(&ele_ctx->hdl, args);
		goto end;
	}

	if (sign_args->attributes.algo_id == SMW_CONFIG_SIGN_ALGO_ID_RSA) {
		/*
		 * Salt length optional attribute is only for RSASSA-PSS
		 * signature type.
		 */
		if (sign_args->attributes.type_id ==
			    SMW_CONFIG_SIGN_TYPE_ID_PKCS1_1_5 &&
		    sign_args->attributes.salt_length) {
			SMW_DBG_PRINTF(ERROR,
				       "Salt length not supported for %s\n",
				       "RSA PKCS1_V1_5");
			status = SMW_STATUS_INVALID_PARAM;
			goto end;
		}
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

	if (op_args.signature) {
		if (SET_OVERFLOW(smw_sign_verify_get_sign_len(sign_args),
				 op_args.signature_size)) {
			status = SMW_STATUS_INVALID_PARAM;
			goto end;
		}
	}

	status = set_signature_scheme(key_identifier->type_id,
				      key_identifier->security_size,
				      &sign_args->attributes,
				      &op_args.scheme_id);
	if (status != SMW_STATUS_OK)
		goto end;

	if (key_identifier->type_id == SMW_CONFIG_KEY_TYPE_ID_ED25519 &&
	    smw_sign_verify_get_eddsa_context(args)) {
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

	err = hsm_do_sign(ele_ctx->hdl.key_store, &op_args);
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
	status = check_and_convert_sign_endian(ele_ctx, op_args.signature, NULL,
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

static int verify_export_key(struct subsystem_context *ele_ctx,
			     struct smw_keymgr_descriptor *export_key_desc,
			     unsigned char **hex_key_buf,
			     unsigned int *hex_key_size)
{
	int status = SMW_STATUS_OK;

	status = ele_export_public_key(ele_ctx, export_key_desc);
	if (status != SMW_STATUS_OK)
		goto end;

	if (export_key_desc->identifier.type_id == SMW_CONFIG_KEY_TYPE_ID_RSA) {
		*hex_key_size = smw_keymgr_get_modulus_length(export_key_desc);
		*hex_key_buf = smw_keymgr_get_modulus(export_key_desc);

	} else {
		*hex_key_size = smw_keymgr_get_public_length(export_key_desc);
		*hex_key_buf = smw_keymgr_get_public_data(export_key_desc);
	}

end:
	return status;
}

static int verify(struct subsystem_context *ele_ctx, void *args)
{
	int status = SMW_STATUS_OK;

	hsm_err_t err = HSM_NO_ERROR;
	hsm_hdl_t op_handle = ele_ctx->hdl.session;
	op_verify_sign_args_t op_args = { 0 };
	hsm_verification_status_t verification_status = 0;

	struct ele_info *info = &ele_ctx->info;
	struct smw_crypto_sign_verify_args *verify_args = args;
	struct smw_keymgr_descriptor *key_desc = &verify_args->key_descriptor;
	struct smw_keymgr_descriptor export_key_desc = { 0 };
	struct smw_keymgr_descriptor *opaque_key_desc = NULL;

	struct smw_keymgr_get_key_attributes_args key_attrs = { 0 };

	enum smw_config_key_type_id key_type_id = 0;
	enum smw_keymgr_format_id format_id = 0;
	unsigned int security_size = 0;
	uint8_t *key_buf = NULL;
	unsigned int key_size = 0;
	unsigned char *hex_key_buf = NULL;
	unsigned int hex_key_size = 0;
	unsigned char *temp_sign = NULL;
	unsigned char *temp_pub_key = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	format_id = key_desc->format_id;

	op_args.flags = HSM_OP_VERIFY_SIGN_FLAGS_PLAINTEXT_KEY;

	if (verify_args->attributes.algo_id == SMW_CONFIG_SIGN_ALGO_ID_RSA) {
		/*
		 * Salt length optional attribute is only for RSASSA-PSS
		 * signature type.
		 */
		if (verify_args->attributes.type_id ==
			    SMW_CONFIG_SIGN_TYPE_ID_PKCS1_1_5 &&
		    verify_args->attributes.salt_length) {
			SMW_DBG_PRINTF(ERROR,
				       "Salt length not supported for %s\n",
				       "RSA PKCS1_V1_5");
			status = SMW_STATUS_INVALID_PARAM;
			goto end;
		}
	}

	if (key_desc->identifier.s_id) {
		status = ele_get_device_info(ele_ctx);
		if (status != SMW_STATUS_OK)
			goto end;

		if (info->sign_verif_opaque_key) {
			op_handle = ele_ctx->hdl.key_store;

			opaque_key_desc = &key_attrs.key_descriptor;
			opaque_key_desc->identifier.s_id =
				key_desc->identifier.s_id;

			op_args.key_identifier = key_desc->identifier.s_id;
			op_args.flags = HSM_OP_VERIFY_SIGN_FLAGS_OPAQUE_KEY;

			status = ele_get_key_attributes(&ele_ctx->hdl,
							&key_attrs);
		} else {
			opaque_key_desc = &export_key_desc;
			opaque_key_desc->identifier.s_id =
				key_desc->identifier.s_id;
			status = verify_export_key(ele_ctx, opaque_key_desc,
						   &hex_key_buf, &hex_key_size);
		}

		if (status != SMW_STATUS_OK)
			goto end;

		security_size = opaque_key_desc->identifier.security_size;
		key_type_id = opaque_key_desc->identifier.type_id;

	} else {
		/* Verify signature using plaintext key buffer */
		security_size = key_desc->identifier.security_size;
		key_type_id = key_desc->identifier.type_id;

		if (key_type_id == SMW_CONFIG_KEY_TYPE_ID_RSA) {
			status = is_rsa_pub_expo_default(key_desc);
			if (status != SMW_STATUS_OK)
				goto end;

			key_size = smw_keymgr_get_modulus_length(key_desc);
			key_buf = smw_keymgr_get_modulus(key_desc);

			status = smw_utils_key_set_hex_buffer(format_id,
							      key_buf, key_size,
							      &hex_key_buf,
							      &hex_key_size);
			if (status != SMW_STATUS_OK)
				goto end;

		} else {
			key_size = smw_keymgr_get_public_length(key_desc);
			key_buf = smw_keymgr_get_public_data(key_desc);

			status = smw_utils_key_set_hex_buffer(format_id,
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

	if (!(key_desc->identifier.s_id && info->sign_verif_opaque_key)) {
		status = ele_set_pubkey_type(key_type_id, &op_args.pkey_type);
		if (status != SMW_STATUS_OK)
			goto end;

		op_args.key_sz = security_size;
		op_args.key = hex_key_buf;

		if (SET_OVERFLOW(hex_key_size, op_args.key_size)) {
			status = SMW_STATUS_INVALID_PARAM;
			goto end;
		}

		/*
		 * On some device (e.g. i.MX93 and i.MX91), the
		 * public key buffer msut be big-endian.
		 */
		status = check_and_convert_endian(ele_ctx, hex_key_buf,
						  &temp_pub_key, hex_key_size,
						  key_type_id);
		if (status != SMW_STATUS_OK)
			goto end;

		if (temp_pub_key)
			op_args.key = temp_pub_key;
	}

	op_args.message = smw_sign_verify_get_msg_buf(verify_args);
	op_args.signature = smw_sign_verify_get_sign_buf(verify_args);
	op_args.message_size = smw_sign_verify_get_msg_len(verify_args);

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
	    smw_sign_verify_get_eddsa_context(args)) {
		status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
		goto end;
	}

	/*
	 * On some device (e.g. i.MX93 and i.MX91), the EDDSA-based signature
	 * to verify must be in big-endian format.
	 */
	status = check_and_convert_sign_endian(ele_ctx, op_args.signature,
					       &temp_sign,
					       op_args.signature_size,
					       key_type_id);
	if (status != SMW_STATUS_OK)
		goto end;

	if (temp_sign)
		op_args.signature = temp_sign;

	if (verify_args->attributes.msg_hashed)
		op_args.flags |= HSM_OP_VERIFY_SIGN_FLAGS_INPUT_DIGEST;
	else
		op_args.flags |= HSM_OP_VERIFY_SIGN_FLAGS_INPUT_MESSAGE;

	SMW_DBG_PRINTF(VERBOSE,
		       "[%s (%d)] Call hsm_verify_sign()\n"
		       "  op_verify_sign_args_t\n"
		       "    scheme_id: 0x%08X\n"
		       "    flags: 0x%X\n"
		       "    Public Key\n"
		       "      - id: 0x%08X\n"
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
		       op_args.key_identifier, op_args.pkey_type,
		       op_args.key_sz, op_args.key, op_args.key_size,
		       op_args.salt_len, op_args.message, op_args.message_size,
		       op_args.signature, op_args.signature_size);

	err = hsm_verify_sign(op_handle, &op_args, &verification_status);

	status = ele_convert_err(err);
	SMW_DBG_PRINTF(DEBUG, "hsm_verify_sign returned %d\n", err);

	if (verification_status != HSM_VERIFICATION_STATUS_SUCCESS)
		status = SMW_STATUS_SIGNATURE_INVALID;

end:
	if (temp_pub_key)
		free(temp_pub_key);

	if (temp_sign)
		free(temp_sign);

	if (export_key_desc.pub)
		(void)smw_keymgr_free_keypair_buffer(&export_key_desc);

	if (format_id == SMW_KEYMGR_FORMAT_ID_BASE64 && hex_key_buf)
		SMW_UTILS_FREE(hex_key_buf);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * set_sign_context() - Allocate and initialize signature subsystem specific ctx
 * @op_context: Pointer to operation context arguments structure
 *
 * This function initializes the members of operation context structure. It also
 * allocates memory to Hash subsystem specific context and initializes its
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

	status =
		smw_utils_key_copy(&ctx->key_descriptor, &args->key_descriptor);
	if (status != SMW_STATUS_OK)
		goto end;

	op_context->subsystem_context = ctx;
	op_context->op_state = CTX_OP_STATE_INIT;

	smw_crypto_set_ctx_subsystem_id(op_context, SUBSYSTEM_ID_ELE);

	status = SMW_STATUS_OK;

end:
	if (status != SMW_STATUS_OK && ctx)
		SMW_UTILS_FREE(ctx);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int signature_init(struct subsystem_context *ele_ctx,
			  struct smw_crypto_sign_verify_args *args)
{
	int status = SMW_STATUS_INVALID_PARAM;

	struct smw_crypto_hash_args hash_args = { 0 };
	struct smw_hash_init_args init_pub = { .version = 1 };
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
				      &args->attributes, &scheme_id);
	if (status != SMW_STATUS_OK)
		goto end;

	if (sign_attrs->algo_id == SMW_CONFIG_SIGN_ALGO_ID_RSA) {
		/*
		 * Salt length optional attribute is only for RSASSA-PSS
		 * signature type.
		 */
		if (sign_attrs->type_id == SMW_CONFIG_SIGN_TYPE_ID_PKCS1_1_5 &&
		    sign_attrs->salt_length) {
			SMW_DBG_PRINTF(ERROR,
				       "Salt length not supported for %s\n",
				       "RSA PKCS1_V1_5");
			status = SMW_STATUS_INVALID_PARAM;
			goto end;
		}
	} else if (sign_attrs->algo_id == SMW_CONFIG_SIGN_ALGO_ID_EDDSA) {
		if (sign_attrs->type_id == SMW_CONFIG_SIGN_TYPE_ID_PURE_EDDSA) {
			status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
			goto end;
		}

		if (key_identifier->type_id == SMW_CONFIG_KEY_TYPE_ID_ED25519) {
			if (smw_sign_verify_get_eddsa_context(args)) {
				status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
				goto end;
			}
			/* Force the hash algorithm to be SHA512 */
			sign_attrs->hash_id = SMW_CONFIG_HASH_ALGO_ID_SHA512;
		} else if (key_identifier->type_id ==
			   SMW_CONFIG_KEY_TYPE_ID_ED448) {
			/* Force the hash algorithm to be SHA512 */
			sign_attrs->hash_id = SMW_CONFIG_HASH_ALGO_ID_SHAKE256;
		}
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

	if (!ele_hash_handle(&ele_ctx->hdl, OPERATION_ID_HASH_MULTI_PART,
			     &hash_args, &status))
		status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int signature_update(struct subsystem_context *ele_ctx,
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

	if (!ele_hash_handle(&ele_ctx->hdl, OPERATION_ID_HASH_MULTI_PART,
			     &hash_args, &status))
		status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int signature_final(struct subsystem_context *ele_ctx,
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
	if (!ele_hash_handle(&ele_ctx->hdl, OPERATION_ID_HASH_MULTI_PART,
			     &hash_args, &status))
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

		if (!ele_hash_handle(&ele_ctx->hdl,
				     OPERATION_ID_HASH_MULTI_PART, &hash_args,
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

	if (is_verify) {
		status = verify(ele_ctx, &tmp_args);
	} else {
		status = sign(ele_ctx, &tmp_args);
		smw_sign_verify_set_sign_len(args, pub_args.signature_length);
	}

end:
	if (digest)
		SMW_UTILS_FREE(digest);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int sign_multipart(struct subsystem_context *ele_ctx,
			  struct smw_crypto_sign_verify_args *args)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	switch (args->op_step) {
	case SMW_OP_STEP_INIT:
		status = signature_init(ele_ctx, args);
		break;

	case SMW_OP_STEP_UPDATE:
		status = signature_update(ele_ctx, args);
		break;

	case SMW_OP_STEP_FINAL:
		status = signature_final(ele_ctx, args, false);
		break;

	default:
		break;
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int verify_multipart(struct subsystem_context *ele_ctx,
			    struct smw_crypto_sign_verify_args *args)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	switch (args->op_step) {
	case SMW_OP_STEP_INIT:
		status = signature_init(ele_ctx, args);
		break;

	case SMW_OP_STEP_UPDATE:
		status = signature_update(ele_ctx, args);
		break;

	case SMW_OP_STEP_FINAL:
		status = signature_final(ele_ctx, args, true);
		break;

	default:
		break;
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

bool ele_sign_verify_handle(struct subsystem_context *ele_ctx,
			    enum operation_id operation_id, void *args,
			    int *status)
{
	switch (operation_id) {
	case OPERATION_ID_SIGN:
		*status = sign(ele_ctx, args);
		break;
	case OPERATION_ID_VERIFY:
		*status = verify(ele_ctx, args);
		break;
	case OPERATION_ID_SIGN_MULTI_PART:
		*status = sign_multipart(ele_ctx, args);
		break;
	case OPERATION_ID_VERIFY_MULTI_PART:
		*status = verify_multipart(ele_ctx, args);
		break;
	default:
		return false;
	}

	return true;
}

void ele_free_sign_context(struct smw_op_context *ctx)
{
	struct sign_context *sign_ctx = NULL;

	if (ctx && ctx->subsystem_context) {
		sign_ctx = ctx->subsystem_context;

		ele_free_hash_context(&sign_ctx->hash_ctx);

		if (sign_ctx->hash_ctx.subsystem_context) {
			SMW_UTILS_FREE(sign_ctx->hash_ctx.subsystem_context);
			sign_ctx->hash_ctx.subsystem_context = NULL;
		}

		smw_utils_key_free(&sign_ctx->key_descriptor);
	}
}

int ele_copy_sign_context(struct smw_op_context *src_ctx,
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

	status = ele_copy_hash_context(&src_sign_ctx->hash_ctx,
				       &dst_sign_ctx->hash_ctx);
	if (status != SMW_STATUS_OK)
		goto end;

	dst_sign_ctx->attributes = src_sign_ctx->attributes;

	status = smw_utils_key_copy(&dst_sign_ctx->key_descriptor,
				    &src_sign_ctx->key_descriptor);
	if (status != SMW_STATUS_OK)
		goto end;

end:
	if (dst_ctx)
		dst_ctx->subsystem_context = dst_sign_ctx;

	if (status != SMW_STATUS_OK && dst_sign_ctx) {
		ele_free_sign_context(dst_ctx);
		SMW_UTILS_FREE(dst_sign_ctx);
		dst_ctx->subsystem_context = NULL;
	}

	return status;
}
