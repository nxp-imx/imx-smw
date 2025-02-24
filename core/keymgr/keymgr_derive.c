// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2025 NXP
 */

#include "smw_keymgr.h"
#include "smw_status.h"

#include "debug.h"
#include "operations.h"
#include "subsystems.h"
#include "keymgr_derive.h"
#include "keymgr_db.h"
#include "exec.h"
#include "utils.h"
#include "base64.h"

/*
 * Ordering must be the same for internal values and public values.
 * This way the offset between the internal values and the public values
 * can be used for conversion, and no conversion table is required.
 *
 * The offset between the internal values and the public values is
 * given by the first public value.
 */

#define SMW_TLS12_KEY_EXCHANGE_ID_OFFSET                                       \
	(SMW_TLS12_KEA_NAME_DH_DSS - SMW_TLS12_KEY_EXCHANGE_ID_DH_DSS)

#define SMW_TLS12_ENCRYPTION_ID_OFFSET                                         \
	(SMW_TLS12_ENC_NAME_3DES_EDE_CBC - SMW_TLS12_ENCRYPTION_ID_3DES_EDE_CBC)

#define MASTER_SECRET_STR     ((unsigned char *)"master secret")
#define MASTER_SECRET_LEN     (13)
#define KEY_EXPANSION_STR     ((unsigned char *)"key expansion")
#define KEY_EXPANSION_LEN     (13)
#define EXT_MASTER_SECRET_STR ((unsigned char *)"extended master secret")
#define EXT_MASTER_SECRET_LEN (22)

/**
 * tls12_get_key_exchange_id() - Get ID of TLS 1.2 key exchange name
 * @name: Key exchange name
 * @args: TLS 1.2 internal arguments
 *
 * Return:
 * SMW_STATUS_OK                      - Success
 * SMW_STATUS_INVALID_PARAM           - Invalid function parameter
 * SMW_STATUS_UNKNOWN_TLS12_KEA_NAME  - Unknown key exchange algorithm name
 */
static int tls12_get_key_exchange_id(smw_tls12_kea_t name,
				     struct smw_keymgr_tls12_args *args)
{
	int status = SMW_STATUS_UNKNOWN_TLS12_KEA_NAME;

	SMW_DBG_TRACE_FUNCTION_CALL;

	args->key_exchange_id = SMW_TLS12_KEY_EXCHANGE_ID_INVALID;

	if (name == SMW_TLS12_KEA_NAME_NONE) {
		status = SMW_STATUS_INVALID_PARAM;
	} else if (name < SMW_TLS12_KEA_NAME_NB) {
		if (!SUB_OVERFLOW(name, SMW_TLS12_KEY_EXCHANGE_ID_OFFSET,
				  (int *)&args->key_exchange_id))
			status = SMW_STATUS_OK;
	}

	if (status == SMW_STATUS_OK) {
		/* Set if it's ephemeral key exchange or not */
		switch (args->key_exchange_id) {
		case SMW_TLS12_KEY_EXCHANGE_ID_DHE_DSS:
		case SMW_TLS12_KEY_EXCHANGE_ID_DHE_RSA:
		case SMW_TLS12_KEY_EXCHANGE_ID_ECDHE_ECDSA:
		case SMW_TLS12_KEY_EXCHANGE_ID_ECDHE_RSA:
			args->ephemeral_key = true;
			break;

		default:
			args->ephemeral_key = false;
		}
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);

	return status;
}

static int check_key_definition(struct smw_keymgr_descriptor *key_desc,
				enum smw_keymgr_privacy_id type)
{
	int status = SMW_STATUS_INVALID_PARAM;

	if (smw_keymgr_get_api_key_id(key_desc)) {
		status = SMW_STATUS_OK;
		goto end;
	}

	if (type == SMW_KEYMGR_PRIVACY_ID_PAIR ||
	    type == SMW_KEYMGR_PRIVACY_ID_PRIVATE) {
		if (!smw_keymgr_get_private_data(key_desc) ||
		    !smw_keymgr_get_private_length(key_desc))
			goto end;
	}

	if (type == SMW_KEYMGR_PRIVACY_ID_PAIR ||
	    type == SMW_KEYMGR_PRIVACY_ID_PUBLIC) {
		if (!smw_keymgr_get_public_data(key_desc) ||
		    !smw_keymgr_get_public_length(key_desc))
			goto end;
	}

	if (key_desc->identifier.type_id == SMW_CONFIG_KEY_TYPE_ID_RSA) {
		/*
		 * Regardless to the key type to import (public key, private key
		 * or keypair) modulus must be set
		 */
		if (!smw_keymgr_get_modulus(key_desc) ||
		    !smw_keymgr_get_modulus_length(key_desc))
			goto end;
	}

	status = SMW_STATUS_OK;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);

	return status;
}

/**
 * tls12_validate_key_base() - Validate TLS 1.2 key base versus key exchange
 * @args: Internal key derivation arguments
 *
 * Return:
 * SMW_STATUS_OK              - Success
 * SMW_STATUS_INVALID_PARAM   - Invalid function parameter
 */
static int tls12_validate_key_base(struct smw_keymgr_derive_key_args *args)
{
	int status = SMW_STATUS_INVALID_PARAM;

	struct smw_keymgr_tls12_args *tls_args = args->kdf_args;

	if (!tls_args)
		goto end;

	/*
	 * Validate that key base type is correct with the key exchange
	 * value.
	 */
	switch (args->key_base.identifier.type_id) {
	case SMW_CONFIG_KEY_TYPE_ID_DERIVE:
	case SMW_CONFIG_KEY_TYPE_ID_TLS_MASTER:
		break;

	case SMW_CONFIG_KEY_TYPE_ID_RSA:
		if (tls_args->key_exchange_id !=
		    SMW_TLS12_KEY_EXCHANGE_ID_RSA) {
			SMW_DBG_PRINTF(DEBUG, "Invalid RSA key exchange (%d)\n",
				       tls_args->key_exchange_id);
			goto end;
		}
		break;

	case SMW_CONFIG_KEY_TYPE_ID_SECP_R1:
	case SMW_CONFIG_KEY_TYPE_ID_BRAINPOOL_R1:
	case SMW_CONFIG_KEY_TYPE_ID_BRAINPOOL_T1:
		switch (tls_args->key_exchange_id) {
		case SMW_TLS12_KEY_EXCHANGE_ID_ECDH_ECDSA:
		case SMW_TLS12_KEY_EXCHANGE_ID_ECDH_RSA:
		case SMW_TLS12_KEY_EXCHANGE_ID_ECDHE_ECDSA:
		case SMW_TLS12_KEY_EXCHANGE_ID_ECDHE_RSA:
			break;

		default:
			SMW_DBG_PRINTF(DEBUG,
				       "Invalid ECDH key exchange (%d)\n",
				       tls_args->key_exchange_id);
			goto end;
		}
		break;

	case SMW_CONFIG_KEY_TYPE_ID_DH:
		switch (tls_args->key_exchange_id) {
		case SMW_TLS12_KEY_EXCHANGE_ID_DH_DSS:
		case SMW_TLS12_KEY_EXCHANGE_ID_DH_RSA:
		case SMW_TLS12_KEY_EXCHANGE_ID_DHE_DSS:
		case SMW_TLS12_KEY_EXCHANGE_ID_DHE_RSA:
			break;

		default:
			SMW_DBG_PRINTF(DEBUG, "Invalid DH key exchange (%d)\n",
				       tls_args->key_exchange_id);
			goto end;
		}
		break;

	default:
		SMW_DBG_PRINTF(DEBUG,
			       "Invalid key base (%d) versus exchange (%d)\n",
			       args->key_base.identifier.type_id,
			       tls_args->key_exchange_id);
		goto end;
	}

	/*
	 * Key base must be a already subsystem key registered or
	 * public data buffer must contains the public key representing
	 * the pre_master_secret value (RSA, DH, ECDH).
	 */
	status = check_key_definition(&args->key_base,
				      SMW_KEYMGR_PRIVACY_ID_PUBLIC);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);

	return status;
}

/**
 * tsl12_get_encryption_id() - Get ID of TLS 1.2 cipher encryption name
 * @name: Cipher encryption name
 * @id: ID of the cipher encryption name
 *
 * Return:
 * SMW_STATUS_OK                     - Success
 * SMW_STATUS_INVALID_PARAM          - Invalid function parameter
 * SMW_STATUS_UNKNOWN_TLS12_ENC_NAME - Unknown TLS 1.2 encryption algorithm name
 */
static int tls12_get_encryption_id(smw_tls12_enc_t name,
				   enum smw_tls12_encryption_id *id)
{
	int status = SMW_STATUS_UNKNOWN_TLS12_ENC_NAME;

	SMW_DBG_TRACE_FUNCTION_CALL;

	*id = SMW_TLS12_ENCRYPTION_ID_INVALID;

	if (name == SMW_TLS12_ENC_NAME_NONE) {
		status = SMW_STATUS_INVALID_PARAM;
	} else if (name < SMW_TLS12_ENC_NAME_NB) {
		if (!SUB_OVERFLOW(name, SMW_TLS12_ENCRYPTION_ID_OFFSET,
				  (int *)id))
			status = SMW_STATUS_OK;
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);

	return status;
}

/**
 * tls12_is_encryption_ccm() - Return if the cipher encryption is CCM
 * @id: Cipher encryption mode
 *
 * Function returns if the TLS cipher encryption mode is an Authentication
 * Encryption with Additional Data (AEAD) CCM.
 *
 * Return:
 * True if AEAD CCM cipher mode,
 * False otherwise
 */
static bool tls12_is_encryption_ccm(enum smw_tls12_encryption_id id)
{
	if (id == SMW_TLS12_ENCRYPTION_ID_AES_128_CCM ||
	    id == SMW_TLS12_ENCRYPTION_ID_AES_256_CCM)
		return true;

	return false;
}

/**
 * tls12_is_encryption_gcm() - Return if the Cipher encryption is GCM
 * @id: Cipher encryption mode
 *
 * Function returns if the TLS cipher encryption mode is an Authentication
 * Encryption with Additional Data (AEAD) GCM.
 *
 * Return:
 * True if AEAD GCM cipher mode,
 * False otherwise
 */
static bool tls12_is_encryption_gcm(enum smw_tls12_encryption_id id)
{
	if (id == SMW_TLS12_ENCRYPTION_ID_AES_128_GCM ||
	    id == SMW_TLS12_ENCRYPTION_ID_AES_256_GCM)
		return true;

	return false;
}

/**
 * get_prf_id() - Get ID of Pseudo-Random Function
 * @name: Pseudo-Random Function name
 * @id: ID of the Pseudo-Random Function name
 *
 * Return:
 * SMW_STATUS_OK                - Success
 * SMW_STATUS_INVALID_PARAM     - Invalid function parameter
 * SMW_STATUS_UNKNOWN_ALGO_NAME - String name is not referenced
 */
static int get_prf_id(smw_hash_algo_t name, enum smw_config_hash_algo_id *id)
{
	int status = SMW_STATUS_INVALID_PARAM;

	SMW_DBG_TRACE_FUNCTION_CALL;

	*id = SMW_CONFIG_HASH_ALGO_ID_INVALID;

	if (name != SMW_HASH_ALGO_NAME_NONE)
		status = smw_utils_get_hash_algo_id(name, id);

	if (status == SMW_STATUS_UNKNOWN_NAME)
		status = SMW_STATUS_UNKNOWN_ALGO_NAME;

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);

	return status;
}

/**
 * set_derived_key_buffer_format() - Set the Format ID of the derived key
 * @args: Pointer to internal derived key descriptor structure.
 *
 * Return:
 * none.
 */
static void
set_derived_key_buffer_format(struct smw_keymgr_derived_key_desc *desc)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_ASSERT(desc);

	if (!desc->pub)
		return;

	desc->pub->format_name =
		smw_keymgr_get_key_format_name(desc->format_id);
}

/**
 * smw_keymgr_convert_derived_key_desc() - Convert to internal derived key
 *                                         descriptor structure.
 * @in: Pointer to public derived key descriptor structure.
 * @out: Pointer to an internal derived key descriptor structure.
 *
 * This function converts public derived key descriptor structure to internal
 * derived key descriptor structure.
 *
 * Return:
 * SMW_STATUS_OK                    - Success
 * SMW_STATUS_UNKNOWN_KEY_TYPE_NAME - Unknown key type name
 * SMW_STATUS_UNKNOWN_FORMAT_NAME   - Unknown key format name
 * SMW_STATUS_INVALID_PARAM         - One of the parameter is invalid
 */
static int
smw_keymgr_convert_derived_key_desc(struct smw_derived_key_descriptor *in,
				    struct smw_keymgr_derived_key_desc *out)
{
	int status = SMW_STATUS_INVALID_PARAM;

	enum smw_config_key_type_id type_id = SMW_CONFIG_KEY_TYPE_ID_INVALID;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_ASSERT(out);

	if (!in)
		goto end;

	status = smw_config_get_key_type_id(in->type_name, &type_id);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_keymgr_get_key_format_id(in->format_name, &out->format_id);
	if (status != SMW_STATUS_OK)
		goto end;

	out->identifier.id = in->id;
	out->identifier.type_id = type_id;
	out->identifier.security_size = in->security_size;
	out->pub = in;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * smw_keymgr_convert_prk_desc() - Convert PRK descriptor structure.
 * @in: Pointer to public key descriptor structure.
 * @out: Pointer to an internal key descriptor structure.
 *
 * This function converts public PRK descriptor structure to internal PRK
 * descriptor structure. Either the PRK ID is set or the buffer (public buffer)
 * is set. PRK key type is set to SMW_CONFIG_KEY_TYPE_ID_RAW.
 *
 * Return:
 * SMW_STATUS_OK                    - Success
 * SMW_STATUS_UNKNOWN_KEY_TYPE_NAME - Unknown key type name
 * SMW_STATUS_INVALID_PARAM         - One of the parameter is invalid
 */
static int smw_keymgr_convert_prk_desc(struct smw_key_descriptor *in,
				       struct smw_keymgr_descriptor *out)
{
	int status = SMW_STATUS_INVALID_PARAM;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_ASSERT(out);

	if (!in)
		goto end;

	out->identifier.type_id = SMW_CONFIG_KEY_TYPE_ID_RAW;

	if (!in->buffer) {
		out->format_id = SMW_KEYMGR_FORMAT_ID_INVALID;
	} else {
		status = smw_keymgr_get_key_format_id(in->buffer->format_name,
						      &out->format_id);
		if (status != SMW_STATUS_OK)
			goto end;
	}

	out->identifier.id = in->id;
	out->pub = in;

	status = setup_key_ops(out);
	/*
	 * In case of PRK, key can be either key id or a key buffer. If no buffer
	 * defined, assume it's a key id and it's correct.
	 */
	if (status == SMW_STATUS_NO_KEY_BUFFER)
		status = SMW_STATUS_OK;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * tls12_convert_args() - Convert additional operation argument for TLS 1.2
 * @args: Input API additional argument
 * @pub_args: Pointer to public derive key arguments structure
 * @conv_args: Pointer to internal derive key arguments structure
 * @subsystem_id: Subsystem ID
 *
 * Function allocates the TLS 1.2 internal arguments object and converts
 * additional operation argument.
 * If conversion failed, free the TLS 1.2 internal arguments object.
 *
 * TLS 1.2 additional argument contains input and output operation
 * argument.
 * The Input arguments define the TLS Cipher suite and master key generation.
 * The Output arguments are:
 *  - Set of Key IDs (varying according to cipher mode),
 *  - If encryption mode is AES GCM, the Client and Server write IVs.
 *
 * Return :
 * SMW_STATUS_OK                     - Success
 * SMW_STATUS_ALLOC_FAILURE          - Out of memory
 * SMW_STATUS_INVALID_PARAM          - Invalid function parameter
 * SMW_STATUS_UNKNOWN_ALGO_NAME      - Unknown hash algorithm name
 * SMW_STATUS_UNKNOWN_TLS12_KEA_NAME - Unknown TLS 1.2 Key exchange algo name
 * SMW_STATUS_UNKNOWN_TLS12_ENC_NAME - Unknown TLS 1.2 encryption algorithm name
 */
static int tls12_convert_args(struct smw_derive_key_args *pub_args,
			      struct smw_keymgr_derive_key_args *conv_args,
			      enum subsystem_id *subsystem_id)
{
	int status = SMW_STATUS_INVALID_PARAM;
	struct smw_keymgr_tls12_args *tls_args = NULL;
	struct smw_kdf_tls12_args *args = pub_args->kdf_arguments;

	if (!args || !args->kdf_input || !args->kdf_input_length)
		goto end;

	/* Get the input key base for the derivation */
	status = smw_keymgr_convert_descriptor(pub_args->key_descriptor_base,
					       &conv_args->key_base, false,
					       subsystem_id);
	if (status != SMW_STATUS_OK)
		return status;

	tls_args = SMW_UTILS_MALLOC(sizeof(*tls_args));
	if (!tls_args) {
		status = SMW_STATUS_ALLOC_FAILURE;
		goto end;
	}

	status = tls12_get_key_exchange_id(args->key_exchange_name, tls_args);
	if (status != SMW_STATUS_OK)
		goto end;

	status = tls12_get_encryption_id(args->encryption_name,
					 &tls_args->encryption_id);
	if (status != SMW_STATUS_OK)
		goto end;

	status = get_prf_id(args->prf_name, &tls_args->prf_id);
	if (status != SMW_STATUS_OK)
		goto end;

	if (smw_keymgr_tls12_is_encryption_aead(tls_args->encryption_id)) {
		if (!args->client_w_iv || !args->client_w_iv_length ||
		    !args->server_w_iv || !args->server_w_iv_length) {
			status = SMW_STATUS_INVALID_PARAM;
			goto end;
		}
	}

	tls_args->pub_args = args;
	conv_args->kdf_args = tls_args;
	SMW_DBG_PRINTF(DEBUG, "KDF Input %p\n", args);

end:
	if (status != SMW_STATUS_OK && tls_args)
		free(tls_args);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);

	return status;
}

/**
 * tls12_convert_output() - Convert TLS 1.2 output arguments
 * @args: Input API additional argument
 * @conv_args: Converted arguments
 *
 * Function allocates the TLS 1.2 internal arguments object and converts
 * additional operation argument.
 * If conversion failed, free the TLS 1.2 internal arguments object.
 *
 * The output of key derivation is a set of Key IDs returned in the
 * operation additional arguments function of the Cipher encrytion.
 * In addition, if the encryption algorithm is AES GCM, the
 * Client and Server write IVs are returned in the dedicated
 * IV buffers of the additional arguments.
 * If the key exchange is an ephemeral key, the generated
 * public key is exported in the derived key descriptor.
 *
 * Return:
 * SMW_STATUS_OK                     - Success
 * SMW_STATUS_ALLOC_FAILURE          - Out of memory
 * SMW_STATUS_INVALID_PARAM          - Invalid function parameter
 * SMW_STATUS_UNKNOWN_KEY_TYPE_NAME  - Unknown key type name
 * SMW_STATUS_UNKNOWN_FORMAT_NAME    - Unknown key format name
 */
static int tls12_convert_output(struct smw_derive_key_args *args,
				struct smw_keymgr_derive_key_args *conv_args)

{
	int status = SMW_STATUS_INVALID_PARAM;

	struct smw_key_descriptor *key_base = NULL;
	struct smw_derived_key_descriptor *key_out = NULL;
	struct smw_keymgr_tls12_args *tls_args = NULL;
	struct smw_keymgr_derived_key_desc *key_desc = NULL;

	key_base = args->key_descriptor_base;
	key_out = args->key_descriptor_derived;

	if (key_out->id || !conv_args->kdf_args)
		goto end;

	tls_args = conv_args->kdf_args;

	if (!tls_args->is_operation && tls_args->ephemeral_key) {
		if (!key_out->shared_secret) {
			status = SMW_STATUS_NO_KEY_BUFFER;
			goto end;
		}

		/*
		 * Prepare key derived output value before doing the
		 * key conversion to ensure that key converted into
		 * internal object is correct.
		 */
		key_out->id = INVALID_KEY_ID;

		/* Input base key defines the key type and size */
		key_out->type_name = key_base->type_name;
		key_out->security_size = key_base->security_size;
	}

	key_desc = &conv_args->key_derived;
	status = smw_keymgr_convert_derived_key_desc(key_out, key_desc);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);

	return status;
}

/**
 * hkdf_validate_key_base() - Validate base key
 * @args: Pointer to internal key derivation arguments structure
 *
 * Return:
 * SMW_STATUS_OK              - Success
 * SMW_STATUS_INVALID_PARAM   - Invalid function parameter
 */
static int hkdf_validate_key_base(struct smw_keymgr_derive_key_args *args)
{
	int status = SMW_STATUS_OK;

	struct smw_keymgr_identifier *identifier = &args->key_base.identifier;

	status = smw_keymgr_get_privacy_id(identifier->type_id,
					   &identifier->privacy_id);
	if (status != SMW_STATUS_OK)
		goto end;

	/*
	 * Base key must be either already registered or
	 * key public/private buffer must be set.
	 */
	status = check_key_definition(&args->key_base,
				      args->key_base.identifier.privacy_id);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);

	return status;
}

/**
 * hkdf_convert_output() - Convert HKDF output arguments
 * @args: Pointer to public SMW derive key arguments structure
 * @conv_args: Pointer to internal derive key arguments structure
 *
 * Return:
 * SMW_STATUS_OK                     - Success
 * SMW_STATUS_INVALID_PARAM          - Invalid function parameter
 * SMW_STATUS_UNKNOWN_KEY_TYPE_NAME  - Unknown key type name
 * SMW_STATUS_UNKNOWN_FORMAT_NAME    - Unknown key format name
 */
static int hkdf_convert_output(struct smw_derive_key_args *args,
			       struct smw_keymgr_derive_key_args *conv_args)

{
	int status = SMW_STATUS_INVALID_PARAM;

	struct smw_derived_key_descriptor *key_derived = NULL;
	struct smw_keymgr_derived_key_desc *desc = NULL;

	key_derived = args->key_descriptor_derived;

	if (key_derived->id || !conv_args->kdf_args)
		goto end;

	key_derived->id = INVALID_KEY_ID;

	desc = &conv_args->key_derived;
	status = smw_keymgr_convert_derived_key_desc(key_derived, desc);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);

	return status;
}

/**
 * ecdh_convert_output() - Convert ECDH output arguments
 * @args: Pointer to public SMW derive key arguments structure
 * @conv_args: Pointer to internal derive key arguments structure
 *
 * Return:
 * SMW_STATUS_OK                     - Success
 * SMW_STATUS_INVALID_PARAM          - Invalid function parameter
 * SMW_STATUS_UNKNOWN_KEY_TYPE_NAME  - Unknown key type name
 * SMW_STATUS_UNKNOWN_FORMAT_NAME    - Unknown key format name
 */
static int ecdh_convert_output(struct smw_derive_key_args *args,
			       struct smw_keymgr_derive_key_args *conv_args)

{
	int status = SMW_STATUS_INVALID_PARAM;

	struct smw_derived_key_descriptor *key_derived = NULL;
	struct smw_keymgr_derived_key_desc *desc = NULL;

	key_derived = args->key_descriptor_derived;

	if (key_derived->id != INVALID_KEY_ID || !conv_args->kdf_args)
		goto end;

	desc = &conv_args->key_derived;
	status = smw_keymgr_convert_derived_key_desc(key_derived, desc);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);

	return status;
}

static int convert_output_args(struct smw_derive_key_args *args,
			       struct smw_keymgr_derive_key_args *conv_args)
{
	int status = SMW_STATUS_OK;

	/*
	 * The output key derivation depends on the key derivation
	 * function if specified.
	 */
	switch (conv_args->kdf_id) {
	case SMW_CONFIG_KDF_ID_TLS12_KEY_EXCHANGE:
	case SMW_CONFIG_KDF_ID_TLS12_OP_KEY_EXCHANGE:
		status = tls12_convert_output(args, conv_args);
		break;

	case SMW_CONFIG_KDF_ID_HKDF:
	case SMW_CONFIG_KDF_ID_HKDF_EXTRACT:
	case SMW_CONFIG_KDF_ID_HKDF_EXPAND:
		status = hkdf_convert_output(args, conv_args);
		break;

	case SMW_CONFIG_KDF_ID_ECDH:
		status = ecdh_convert_output(args, conv_args);
		break;

	default:
		break;
	}

	return status;
}

/**
 * is_hkdf_extract_step() - Check if the step is HKDF_STEP_EXTRACT
 * @args: Pointer to additional HKDF arguments structure
 *
 * Return:
 * True if HKDF step is EXTRACT
 * False otherwise
 */
static bool is_hkdf_extract_step(struct smw_keymgr_hkdf_args *args)
{
	bool is_extract_step = false;
	enum hkdf_step step = smw_keymgr_get_hkdf_step(args);

	if (step == HKDF_STEP_EXTRACT)
		is_extract_step = true;

	return is_extract_step;
}

/**
 * create_key_in_db() - Create a key in the database
 * @id: New key identifier created in the database
 * @derive_key_args: Pointer to internal Key derivation arguments structure
 *
 * Function creates a new key in the OSAL object database if the KDF is HKDF
 * or ECDH.
 * The result of HKDF Extract step is PRK. This key is not stored in the SMW
 * key database.
 *
 * The given @identifier is stored in the object entry.
 *
 * Return:
 * SMW_STATUS_OK                - Success
 * SMW_STATUS_OPS_INVALID       - OSAL operation invalid
 * SMW_STATUS_KEY_DB_CREATE     - Key creation error
 */
static int create_key_in_db(unsigned int *new_id,
			    struct smw_keymgr_derive_key_args *derive_key_args)
{
	int status = SMW_STATUS_OK;

	struct smw_keymgr_identifier *identifier =
		&derive_key_args->key_derived.identifier;

	if (derive_key_args->kdf_id == SMW_CONFIG_KDF_ID_HKDF ||
	    derive_key_args->kdf_id == SMW_CONFIG_KDF_ID_HKDF_EXPAND) {
		if (!is_hkdf_extract_step(derive_key_args->kdf_args))
			status = smw_keymgr_db_create(new_id, identifier);
	} else if (derive_key_args->kdf_id == SMW_CONFIG_KDF_ID_ECDH ||
		   derive_key_args->kdf_id ==
			   SMW_CONFIG_KDF_ID_TLS12_OP_KEY_EXCHANGE) {
		status = smw_keymgr_db_create(new_id, identifier);
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * set_derived_key_identifier() - Set the derived key identifier in the DB
 * @id: Key identifier to update/delete in the database
 * @descriptor: Derived key descriptor structure
 *
 * Return:
 * SMW_STATUS_OK                - Success
 * SMW_STATUS_INVALID_PARAM     - One of the parameter is invalid
 * SMW_STATUS_OPS_INVALID       - OSAL operation invalid
 * SMW_STATUS_KEY_DB_UPDATE     - Key update error
 * SMW_STATUS_KEY_DB_DELETE     - Key delete error
 */
static int
set_derived_key_identifier(unsigned int id,
			   struct smw_keymgr_derived_key_desc *descriptor)
{
	int status = SMW_STATUS_INVALID_PARAM;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!descriptor || !descriptor->pub)
		return status;

	if (descriptor->identifier.id != INVALID_KEY_ID) {
		status = smw_keymgr_db_update(id, &descriptor->identifier);

		if (status == SMW_STATUS_OK)
			descriptor->pub->id = id;
	} else {
		status = smw_keymgr_db_delete(id, &descriptor->identifier);
	}

	return status;
}

/**
 * update_key_in_db() - Set the derived key identifier in the DB
 * @id: New key identifier created in the database
 * @derive_key_args: Pointer to internal Key derivation arguments structure
 *
 * If the KDF based key derivation operation returns a status other than
 * SMW_STATUS_OK and SMW_STATUS_KEY_POLICY_WARNING_IGNORED, delete the key from
 * the database. If the key derivation operation is successful, update the
 * derived key identifier in the database.
 * If the current HKDF step is HKDF Extract, as the key identifier of PRK is not
 * stored in the database, do not update the database.
 *
 * Return:
 * SMW_STATUS_OK                - Success
 * SMW_STATUS_OPS_INVALID       - OSAL operation invalid
 * SMW_STATUS_KEY_DB_UPDATE     - Key update error
 * SMW_STATUS_KEY_DB_DELETE     - Key delete error
 */
static int update_key_in_db(int status, unsigned int *id,
			    struct smw_keymgr_derive_key_args *derive_key_args)
{
	int ret_status = status;
	int temp_status = SMW_STATUS_OK;
	struct smw_keymgr_derived_key_desc *key_desc =
		&derive_key_args->key_derived;

	if (derive_key_args->kdf_id == SMW_CONFIG_KDF_ID_HKDF) {
		if (is_hkdf_extract_step(derive_key_args->kdf_args))
			goto end;
	}

	if (status != SMW_STATUS_OK &&
	    status != SMW_STATUS_KEY_POLICY_WARNING_IGNORED) {
		/* Delete the key from the database */
		(void)smw_keymgr_db_delete(*id, &key_desc->identifier);
		goto end;
	}

	temp_status = set_derived_key_identifier(*id, key_desc);
	if (temp_status == SMW_STATUS_OK)
		set_derived_key_buffer_format(key_desc);
	else
		ret_status = temp_status;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return ret_status;
}

bool smw_keymgr_tls12_is_encryption_aead(enum smw_tls12_encryption_id id)
{
	if (tls12_is_encryption_ccm(id) || tls12_is_encryption_gcm(id))
		return true;

	if (id == SMW_TLS12_ENCRYPTION_ID_CHACHA20_POLY1305)
		return true;

	return false;
}

bool smw_keymgr_is_store_key_set(struct smw_keymgr_derive_key_args *args)
{
	return args->store_key;
}

inline void
smw_keymgr_set_shared_secret_id(struct smw_keymgr_derived_key_desc *desc,
				uint32_t id)
{
	if (desc && desc->pub)
		desc->pub->id = id;
}

unsigned char *
smw_keymgr_get_shared_secret_buffer(struct smw_keymgr_derived_key_desc *desc)
{
	unsigned char *buffer = NULL;

	if (desc && desc->pub)
		buffer = desc->pub->shared_secret;

	return buffer;
}

unsigned int
smw_keymgr_get_shared_secret_len(struct smw_keymgr_derived_key_desc *desc)
{
	unsigned int len = 0;

	if (desc && desc->pub)
		len = desc->pub->shared_secret_len;

	return len;
}

void smw_keymgr_set_shared_secret_len(struct smw_keymgr_derived_key_desc *desc,
				      unsigned int len)
{
	if (desc && desc->pub)
		desc->pub->shared_secret_len = len;
}

int smw_keymgr_update_shared_secret(struct smw_keymgr_derived_key_desc *desc,
				    unsigned char *data, unsigned int length)
{
	int status = SMW_STATUS_OPERATION_FAILURE;
	unsigned char *shared_secret = NULL;
	unsigned int shared_secret_len = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	shared_secret = smw_keymgr_get_shared_secret_buffer(desc);

	if (!length) {
		smw_keymgr_set_shared_secret_len(desc, length);

		status = SMW_STATUS_OK;
	} else if (data && shared_secret) {
		shared_secret_len = smw_keymgr_get_shared_secret_len(desc);
		if (!shared_secret_len) {
			status = SMW_STATUS_INVALID_PARAM;
			goto end;
		}

		/* Update buffer data and length */
		if (desc->format_id == SMW_KEYMGR_FORMAT_ID_BASE64) {
			/* Encode hex_buffer in BASE64 buffer */
			status = smw_utils_base64_encode(data, length,
							 shared_secret,
							 &shared_secret_len);
		} else {
			shared_secret_len = length;
			status = SMW_STATUS_OK;
		}

		if (status == SMW_STATUS_OK ||
		    status == SMW_STATUS_OUTPUT_TOO_SHORT)
			smw_keymgr_set_shared_secret_len(desc,
							 shared_secret_len);

	} else if (!data) {
		/* Update only the buffer length */
		shared_secret_len = length;
		if (desc->format_id == SMW_KEYMGR_FORMAT_ID_BASE64)
			shared_secret_len = smw_utils_get_base64_len(length);

		smw_keymgr_set_shared_secret_len(desc, shared_secret_len);

		status = SMW_STATUS_OK;
	}

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

enum hkdf_step smw_keymgr_get_hkdf_step(struct smw_keymgr_hkdf_args *args)
{
	enum hkdf_step step = HKDF_STEP_INVALID;

	if (args && args->pub_args) {
		if (args->pub_args->expand && args->pub_args->extract)
			step = HKDF_STEP_FULL;
		else if (args->pub_args->expand && !args->pub_args->extract)
			step = HKDF_STEP_EXPAND;
		else if (!args->pub_args->expand && args->pub_args->extract)
			step = HKDF_STEP_EXTRACT;
	}

	return step;
}

/**
 * smw_keymgr_hkdf_get_salt() - Get salt buffer address
 * @args: Pointer to internal argument structure
 *
 * Return:
 * address of salt buffer
 * NULL
 */
static unsigned char *
smw_keymgr_hkdf_get_salt(struct smw_keymgr_derive_key_args *args)
{
	unsigned char *salt = NULL;
	struct smw_keymgr_hkdf_args *hkdf_args = NULL;
	enum hkdf_step step = HKDF_STEP_INVALID;

	SMW_DBG_ASSERT(args && args->kdf_args);

	hkdf_args = args->kdf_args;
	step = smw_keymgr_get_hkdf_step(hkdf_args);

	if (step == HKDF_STEP_EXTRACT)
		salt = hkdf_args->pub_args->hkdf_extract_args.salt;
	else if (step == HKDF_STEP_FULL)
		salt = hkdf_args->pub_args->hkdf_args.salt;

	return salt;
}

/**
 * smw_keymgr_hkdf_get_salt_len() - Get salt buffer length
 * @args: Pointer to internal arguments structure
 *
 * Return:
 * Salt buffer length
 * 0
 */
static unsigned int
smw_keymgr_hkdf_get_salt_len(struct smw_keymgr_derive_key_args *args)
{
	unsigned int salt_len = 0;
	struct smw_keymgr_hkdf_args *hkdf_args = NULL;
	enum hkdf_step step = HKDF_STEP_INVALID;

	SMW_DBG_ASSERT(args && args->kdf_args);

	hkdf_args = args->kdf_args;
	step = smw_keymgr_get_hkdf_step(hkdf_args);

	if (step == HKDF_STEP_EXTRACT)
		salt_len = hkdf_args->pub_args->hkdf_extract_args.salt_len;
	else if (step == HKDF_STEP_FULL)
		salt_len = hkdf_args->pub_args->hkdf_args.salt_len;

	return salt_len;
}

/**
 * smw_keymgr_hkdf_get_info() - Get info buffer address
 * @args: Pointer to internal argument structure
 *
 * Return:
 * address of info buffer
 * NULL
 */
static unsigned char *
smw_keymgr_hkdf_get_info(struct smw_keymgr_derive_key_args *args)
{
	unsigned char *info = NULL;
	struct smw_keymgr_hkdf_args *hkdf_args = NULL;
	enum hkdf_step step = HKDF_STEP_INVALID;

	SMW_DBG_ASSERT(args && args->kdf_args);

	hkdf_args = args->kdf_args;
	step = smw_keymgr_get_hkdf_step(hkdf_args);

	if (step == HKDF_STEP_EXPAND)
		info = hkdf_args->pub_args->hkdf_expand_args.info;
	else if (step == HKDF_STEP_FULL)
		info = hkdf_args->pub_args->hkdf_args.info;

	return info;
}

/**
 * smw_keymgr_hkdf_get_info_len() - Get info buffer length
 * @args: Pointer to internal arguments structure
 *
 * Return:
 * Info buffer length
 * 0
 */
static unsigned int
smw_keymgr_hkdf_get_info_len(struct smw_keymgr_derive_key_args *args)
{
	unsigned int info_len = 0;
	struct smw_keymgr_hkdf_args *hkdf_args = NULL;
	enum hkdf_step step = HKDF_STEP_INVALID;

	SMW_DBG_ASSERT(args && args->kdf_args);

	hkdf_args = args->kdf_args;
	step = smw_keymgr_get_hkdf_step(hkdf_args);

	if (step == HKDF_STEP_EXPAND)
		info_len = hkdf_args->pub_args->hkdf_expand_args.info_len;
	else if (step == HKDF_STEP_FULL)
		info_len = hkdf_args->pub_args->hkdf_args.info_len;

	return info_len;
}

/**
 * smw_keymgr_hkdf_get_peer_pub_buffer() - Get peer public key buffer address
 * @args: Pointer to internal arguments structure
 *
 * Return:
 * Address of peer public key buffer
 */
static unsigned char *
smw_keymgr_hkdf_get_peer_pub_buffer(struct smw_keymgr_derive_key_args *args)
{
	unsigned char *peer_pub_buffer = NULL;
	struct smw_keymgr_hkdf_args *hkdf_args = NULL;
	enum hkdf_step step = HKDF_STEP_INVALID;

	SMW_DBG_ASSERT(args && args->kdf_args);

	hkdf_args = args->kdf_args;
	step = smw_keymgr_get_hkdf_step(hkdf_args);

	if (step == HKDF_STEP_EXTRACT)
		peer_pub_buffer = hkdf_args->pub_args->hkdf_extract_args
					  .peer_public_buffer;
	else if (step == HKDF_STEP_FULL)
		peer_pub_buffer =
			hkdf_args->pub_args->hkdf_args.peer_public_buffer;

	return peer_pub_buffer;
}

/**
 * smw_keymgr_hkdf_get_peer_pub_buffer_len() - Get peer public key buffer length
 * @args: Pointer to internal arguments structure
 *
 * Return:
 * Length of peer public key buffer
 */
static unsigned int
smw_keymgr_hkdf_get_peer_pub_buffer_len(struct smw_keymgr_derive_key_args *args)
{
	unsigned int peer_pub_buffer_len = 0;
	struct smw_keymgr_hkdf_args *hkdf_args = NULL;
	enum hkdf_step step = HKDF_STEP_INVALID;

	SMW_DBG_ASSERT(args && args->kdf_args);

	hkdf_args = args->kdf_args;
	step = smw_keymgr_get_hkdf_step(hkdf_args);

	if (step == HKDF_STEP_EXTRACT)
		peer_pub_buffer_len = hkdf_args->pub_args->hkdf_extract_args
					      .peer_public_buffer_len;
	else if (step == HKDF_STEP_FULL)
		peer_pub_buffer_len =
			hkdf_args->pub_args->hkdf_args.peer_public_buffer_len;

	return peer_pub_buffer_len;
}

/**
 * smw_keymgr_ecdh_get_peer_pub_buffer_len() - Get peer public key buffer length
 * @args: Pointer to internal arguments structure
 *
 * Return:
 * Length of peer public key buffer
 */
static unsigned int
smw_keymgr_ecdh_get_peer_pub_buffer_len(struct smw_keymgr_derive_key_args *args)
{
	struct smw_keymgr_ecdh_args *ecdh_args = NULL;

	SMW_DBG_ASSERT(args && args->kdf_args);

	ecdh_args = args->kdf_args;

	SMW_DBG_ASSERT(ecdh_args->pub_args);

	return ecdh_args->pub_args->peer_public_buffer_length;
}

/**
 * smw_keymgr_ecdh_get_peer_pub_buffer() - Get peer public key buffer address
 * @args: Pointer to internal arguments structure
 *
 * Return:
 * Address of peer public key buffer
 */
static unsigned char *
smw_keymgr_ecdh_get_peer_pub_buffer(struct smw_keymgr_derive_key_args *args)
{
	struct smw_keymgr_ecdh_args *ecdh_args = NULL;

	SMW_DBG_ASSERT(args && args->kdf_args);

	ecdh_args = args->kdf_args;

	SMW_DBG_ASSERT(ecdh_args->pub_args);

	return ecdh_args->pub_args->peer_public_buffer;
}

/**
 * smw_keymgr_tls12_get_peer_pub_buffer() - Get peer public key buffer address
 * @args: Pointer to internal arguments structure
 *
 * Return:
 * Address of peer public key buffer
 */
static unsigned char *
smw_keymgr_tls12_get_peer_pub_buffer(struct smw_keymgr_derive_key_args *args)
{
	struct smw_keymgr_tls12_args *tls_args = NULL;

	SMW_DBG_ASSERT(args && args->kdf_args);

	tls_args = args->kdf_args;

	SMW_DBG_ASSERT(tls_args && tls_args->pub_op_args);

	return tls_args->pub_op_args->master_secret.peer_public_buffer;
}

/**
 * smw_keymgr_tls12_get_peer_pub_buffer_len() - Get peer public key buffer length
 * @args: Pointer to internal arguments structure
 *
 * Return:
 * Length of peer public key buffer
 */
static unsigned int
smw_keymgr_tls12_get_peer_pub_len(struct smw_keymgr_derive_key_args *args)
{
	struct smw_keymgr_tls12_args *tls_args = NULL;

	SMW_DBG_ASSERT(args && args->kdf_args);

	tls_args = args->kdf_args;

	SMW_DBG_ASSERT(tls_args && tls_args->pub_op_args);

	return tls_args->pub_op_args->master_secret.peer_public_buffer_length;
}

/**
 * smw_keymgr_tls12_get_label_len() - Get TLS1.2 label buffer length
 * @args: Pointer to internal arguments structure
 *
 * Return:
 * Length of TLS1.2 label buffer length
 */
unsigned int
smw_keymgr_tls12_get_label_len(struct smw_keymgr_derive_key_args *args)
{
	struct smw_keymgr_tls12_args *tls12_args = NULL;

	SMW_DBG_ASSERT(args && args->kdf_args);

	tls12_args = args->kdf_args;

	SMW_DBG_ASSERT(tls12_args->pub_op_args);

	switch (tls12_args->pub_op_args->op_name) {
	case SMW_TLS12_OP_NAME_MASTER_SECRET:
		if (tls12_args->pub_op_args->master_secret.ext_master_key)
			return EXT_MASTER_SECRET_LEN;
		else
			return MASTER_SECRET_LEN;

	case SMW_TLS12_OP_NAME_KEY_EXPANSION:
		return KEY_EXPANSION_LEN;

	default:
		return 0;
	}
}

/**
 * smw_keymgr_tls12_get_label() - Get TLS1.2 label buffer address
 * @args: Pointer to internal argument structure
 *
 * Return:
 * address of TLS1.2 label buffer
 * NULL
 */
unsigned char *
smw_keymgr_tls12_get_label(struct smw_keymgr_derive_key_args *args)
{
	struct smw_keymgr_tls12_args *tls12_args = NULL;

	SMW_DBG_ASSERT(args && args->kdf_args);

	tls12_args = args->kdf_args;

	SMW_DBG_ASSERT(tls12_args->pub_op_args);

	switch (tls12_args->pub_op_args->op_name) {
	case SMW_TLS12_OP_NAME_MASTER_SECRET:
		if (tls12_args->pub_op_args->master_secret.ext_master_key)
			return EXT_MASTER_SECRET_STR;
		else
			return MASTER_SECRET_STR;

	case SMW_TLS12_OP_NAME_KEY_EXPANSION:
		return KEY_EXPANSION_STR;

	default:
		return NULL;
	}
}

unsigned char *
smw_keymgr_tls12_get_client_w_iv(struct smw_keymgr_tls12_args *args)
{
	unsigned char *client_iv = NULL;

	if (args->is_operation) {
		SMW_DBG_ASSERT(args && args->pub_op_args);
		client_iv = args->pub_op_args->key_expansion.client_w_iv;
	} else {
		SMW_DBG_ASSERT(args && args->pub_args);
		client_iv = args->pub_args->client_w_iv;
	}

	return client_iv;
}

unsigned int
smw_keymgr_tls12_get_client_w_iv_length(struct smw_keymgr_tls12_args *args)
{
	unsigned int length = 0;

	if (args->is_operation) {
		SMW_DBG_ASSERT(args && args->pub_op_args);
		length = args->pub_op_args->key_expansion.client_w_iv_length;
	} else {
		SMW_DBG_ASSERT(args && args->pub_args);
		length = args->pub_args->client_w_iv_length;
	}

	return length;
}

void smw_keymgr_tls12_set_client_w_iv_length(struct smw_keymgr_tls12_args *args,
					     unsigned int length)
{
	if (args->is_operation) {
		SMW_DBG_ASSERT(args && args->pub_op_args);
		args->pub_op_args->key_expansion.client_w_iv_length = length;
	} else {
		SMW_DBG_ASSERT(args && args->pub_args);
		args->pub_args->client_w_iv_length = length;
	}
}

unsigned char *
smw_keymgr_tls12_get_server_w_iv(struct smw_keymgr_tls12_args *args)
{
	unsigned char *server_iv = NULL;

	if (args->is_operation) {
		SMW_DBG_ASSERT(args && args->pub_op_args);
		server_iv = args->pub_op_args->key_expansion.server_w_iv;
	} else {
		SMW_DBG_ASSERT(args && args->pub_args);
		server_iv = args->pub_args->server_w_iv;
	}

	return server_iv;
}

unsigned int
smw_keymgr_tls12_get_server_w_iv_length(struct smw_keymgr_tls12_args *args)
{
	unsigned int length = 0;

	if (args->is_operation) {
		SMW_DBG_ASSERT(args && args->pub_op_args);
		length = args->pub_op_args->key_expansion.server_w_iv_length;
	} else {
		SMW_DBG_ASSERT(args && args->pub_args);
		length = args->pub_args->server_w_iv_length;
	}

	return length;
}

void smw_keymgr_tls12_set_server_w_iv_length(struct smw_keymgr_tls12_args *args,
					     unsigned int length)
{
	if (args->is_operation) {
		SMW_DBG_ASSERT(args && args->pub_op_args);
		args->pub_op_args->key_expansion.server_w_iv_length = length;
	} else {
		SMW_DBG_ASSERT(args && args->pub_args);
		args->pub_args->server_w_iv_length = length;
	}
}

unsigned int
smw_keymgr_tls12_get_kdf_input_length(struct smw_keymgr_tls12_args *args)
{
	unsigned int length = 0;

	if (!args->is_operation) {
		SMW_DBG_ASSERT(args && args->pub_args);
		length = args->pub_args->kdf_input_length;
	}

	return length;
}

unsigned char *
smw_keymgr_tls12_get_kdf_input(struct smw_keymgr_tls12_args *args)
{
	unsigned char *kdf_input = NULL;

	if (!args->is_operation) {
		SMW_DBG_ASSERT(args && args->pub_args);
		kdf_input = args->pub_args->kdf_input;
	}

	return kdf_input;
}

bool smw_keymgr_tls12_get_ext_master_key(struct smw_keymgr_tls12_args *args)
{
	bool ext_master_key = false;

	if (args->is_operation) {
		SMW_DBG_ASSERT(args && args->pub_op_args);
		ext_master_key =
			args->pub_op_args->master_secret.ext_master_key;
	} else {
		SMW_DBG_ASSERT(args && args->pub_args);
		ext_master_key = args->pub_args->ext_master_key;
	}

	return ext_master_key;
}

void smw_keymgr_tls12_set_client_mac_key_id(struct smw_keymgr_tls12_args *args,
					    unsigned int id)
{
	if (args->is_operation) {
		SMW_DBG_ASSERT(args && args->pub_op_args);
		args->pub_op_args->key_expansion.client_w_mac_key_id = id;
	} else {
		SMW_DBG_ASSERT(args && args->pub_args);
		args->pub_args->client_w_mac_key_id = id;
	}
}

void smw_keymgr_tls12_set_server_mac_key_id(struct smw_keymgr_tls12_args *args,
					    unsigned int id)
{
	if (args->is_operation) {
		SMW_DBG_ASSERT(args && args->pub_op_args);
		args->pub_op_args->key_expansion.server_w_mac_key_id = id;
	} else {
		SMW_DBG_ASSERT(args && args->pub_args);
		args->pub_args->server_w_mac_key_id = id;
	}
}

void smw_keymgr_tls12_set_client_enc_key_id(struct smw_keymgr_tls12_args *args,
					    unsigned int id)
{
	if (args->is_operation) {
		SMW_DBG_ASSERT(args && args->pub_op_args);
		args->pub_op_args->key_expansion.client_w_enc_key_id = id;
	} else {
		SMW_DBG_ASSERT(args && args->pub_args);
		args->pub_args->client_w_enc_key_id = id;
	}
}

void smw_keymgr_tls12_set_server_enc_key_id(struct smw_keymgr_tls12_args *args,
					    unsigned int id)
{
	if (args->is_operation) {
		SMW_DBG_ASSERT(args && args->pub_op_args);
		args->pub_op_args->key_expansion.server_w_enc_key_id = id;
	} else {
		SMW_DBG_ASSERT(args && args->pub_args);
		args->pub_args->server_w_enc_key_id = id;
	}
}

unsigned int
smw_keymgr_tls12_get_master_sec_key_id(struct smw_keymgr_tls12_args *args)
{
	unsigned int key_id = 0;

	if (!args->is_operation) {
		SMW_DBG_ASSERT(args && args->pub_args);
		key_id = args->pub_args->master_sec_key_id;
	}

	return key_id;
}

void smw_keymgr_tls12_set_master_sec_key_id(struct smw_keymgr_tls12_args *args,
					    unsigned int id)
{
	if (!args->is_operation) {
		SMW_DBG_ASSERT(args && args->pub_args);
		args->pub_args->master_sec_key_id = id;
	}
}

unsigned char *
smw_keymgr_tls12_get_session_hash(struct smw_keymgr_tls12_args *args)
{
	SMW_DBG_ASSERT(args && args->is_operation && args->pub_op_args &&
		       args->pub_op_args->master_secret.session_hash);

	return args->pub_op_args->master_secret.session_hash->hash;
}

unsigned int
smw_keymgr_tls12_get_session_hash_length(struct smw_keymgr_tls12_args *args)
{
	SMW_DBG_ASSERT(args && args->is_operation && args->pub_op_args &&
		       args->pub_op_args->master_secret.session_hash);

	return args->pub_op_args->master_secret.session_hash->hash_length;
}

unsigned char *
smw_keymgr_tls12_get_client_random(struct smw_keymgr_tls12_args *args)
{
	struct smw_kdf_tls12_random_data *rd = NULL;

	SMW_DBG_ASSERT(args && args->is_operation && args->pub_op_args);

	if (args->pub_op_args->op_name == SMW_TLS12_OP_NAME_MASTER_SECRET)
		rd = args->pub_op_args->master_secret.random_data;
	else if (args->pub_op_args->op_name == SMW_TLS12_OP_NAME_KEY_EXPANSION)
		rd = args->pub_op_args->key_expansion.random_data;

	SMW_DBG_ASSERT(rd && rd->client_random);
	return rd->client_random;
}

unsigned int
smw_keymgr_tls12_get_client_random_length(struct smw_keymgr_tls12_args *args)
{
	struct smw_kdf_tls12_random_data *rd = NULL;

	SMW_DBG_ASSERT(args && args->is_operation && args->pub_op_args);

	if (args->pub_op_args->op_name == SMW_TLS12_OP_NAME_MASTER_SECRET)
		rd = args->pub_op_args->master_secret.random_data;
	else if (args->pub_op_args->op_name == SMW_TLS12_OP_NAME_KEY_EXPANSION)
		rd = args->pub_op_args->key_expansion.random_data;

	SMW_DBG_ASSERT(rd);
	return rd->client_random_length;
}

unsigned char *
smw_keymgr_tls12_get_server_random(struct smw_keymgr_tls12_args *args)
{
	struct smw_kdf_tls12_random_data *rd = NULL;

	SMW_DBG_ASSERT(args && args->is_operation && args->pub_op_args);

	if (args->pub_op_args->op_name == SMW_TLS12_OP_NAME_MASTER_SECRET)
		rd = args->pub_op_args->master_secret.random_data;
	else if (args->pub_op_args->op_name == SMW_TLS12_OP_NAME_KEY_EXPANSION)
		rd = args->pub_op_args->key_expansion.random_data;

	SMW_DBG_ASSERT(rd && rd->server_random);
	return rd->server_random;
}

unsigned int
smw_keymgr_tls12_get_server_random_length(struct smw_keymgr_tls12_args *args)
{
	struct smw_kdf_tls12_random_data *rd = NULL;

	SMW_DBG_ASSERT(args && args->is_operation && args->pub_op_args);

	if (args->pub_op_args->op_name == SMW_TLS12_OP_NAME_MASTER_SECRET)
		rd = args->pub_op_args->master_secret.random_data;
	else if (args->pub_op_args->op_name == SMW_TLS12_OP_NAME_KEY_EXPANSION)
		rd = args->pub_op_args->key_expansion.random_data;

	SMW_DBG_ASSERT(rd);
	return rd->server_random_length;
}

/**
 * hkdf_convert_input_args() - Convert additional operation arguments for HKDF
 * @pub_args: Pointer to public derive key arguments structure
 * @conv_args: Pointer to internal derive key arguments structure
 * @subsystem_id: Subsystem ID
 *
 * Function allocates the HKDF internal arguments object and converts
 * additional operation arguments.
 * If conversion failed, free the HKDF internal arguments object.
 *
 * Return :
 * SMW_STATUS_OK                     - Success
 * SMW_STATUS_ALLOC_FAILURE          - Out of memory
 * SMW_STATUS_INVALID_PARAM          - Invalid function parameter
 * SMW_STATUS_UNKNOWN_ALGO_NAME      - Unknown hash algorithm name
 */
static int hkdf_convert_input_args(struct smw_derive_key_args *pub_args,
				   struct smw_keymgr_derive_key_args *conv_args,
				   enum subsystem_id *subsystem_id)
{
	int status = SMW_STATUS_INVALID_PARAM;
	struct smw_keymgr_hkdf_args *hkdf_args = NULL;
	struct smw_key_descriptor *base_key_desc = NULL;
	struct smw_kdf_hkdf_args *hkdf_pub_args = pub_args->kdf_arguments;

	if (!hkdf_pub_args)
		goto end;

	if (!hkdf_pub_args->expand && !hkdf_pub_args->extract)
		goto end;

	if (conv_args->kdf_id == SMW_CONFIG_KDF_ID_HKDF_EXPAND) {
		if (!hkdf_pub_args->expand || hkdf_pub_args->extract) {
			SMW_DBG_PRINTF(ERROR,
				       "HKDF expand and arguments invalid\n");
			goto end;
		}
	} else if (conv_args->kdf_id == SMW_CONFIG_KDF_ID_HKDF_EXTRACT) {
		if (!hkdf_pub_args->extract || hkdf_pub_args->expand) {
			SMW_DBG_PRINTF(ERROR,
				       "HKDF extract and arguments invalid\n");
			goto end;
		}
	}

	base_key_desc = pub_args->key_descriptor_base;

	if (hkdf_pub_args->expand && !hkdf_pub_args->extract) {
		/* The HKDF Extract operation produces the PRK which serves as the base
		 * key to the HKDF Expand operation.
		 */
		/* Get the PRK key base for the derivation */
		status = smw_keymgr_convert_prk_desc(base_key_desc,
						     &conv_args->key_base);

		if (status != SMW_STATUS_OK)
			goto end;

		status = check_key_definition(&conv_args->key_base,
					      SMW_KEYMGR_PRIVACY_ID_PUBLIC);

	} else {
		/* Get the input key base for the derivation */
		status = smw_keymgr_convert_descriptor(base_key_desc,
						       &conv_args->key_base,
						       false, subsystem_id);
		if (status == SMW_STATUS_OK)
			status = hkdf_validate_key_base(conv_args);
	}

	if (status != SMW_STATUS_OK)
		return status;

	hkdf_args = SMW_UTILS_MALLOC(sizeof(*hkdf_args));
	if (!hkdf_args) {
		status = SMW_STATUS_ALLOC_FAILURE;
		goto end;
	}

	status = get_prf_id(hkdf_pub_args->hash_algo, &hkdf_args->prf_id);
	if (status != SMW_STATUS_OK)
		goto end;

	hkdf_args->pub_args = hkdf_pub_args;
	conv_args->kdf_args = hkdf_args;
	conv_args->ops.get_peer = smw_keymgr_hkdf_get_peer_pub_buffer;
	conv_args->ops.get_peer_len = smw_keymgr_hkdf_get_peer_pub_buffer_len;
	conv_args->ops.get_info = smw_keymgr_hkdf_get_info;
	conv_args->ops.get_info_len = smw_keymgr_hkdf_get_info_len;
	conv_args->ops.get_salt = smw_keymgr_hkdf_get_salt;
	conv_args->ops.get_salt_len = smw_keymgr_hkdf_get_salt_len;

end:
	if (status != SMW_STATUS_OK && hkdf_args)
		free(hkdf_args);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);

	return status;
}

/**
 * ecdh_convert_input_args() - Convert additional operation arguments for ECDH
 * @pub_args: Pointer to public derive key arguments structure
 * @conv_args: Pointer to internal derive key arguments structure
 * @subsystem_id: Subsystem ID
 *
 * Function allocates the KDF internal arguments object and converts
 * additional operation arguments.
 * If conversion failed, free the KDF internal arguments object.
 *
 * Return :
 * SMW_STATUS_OK                     - Success
 * SMW_STATUS_ALLOC_FAILURE          - Out of memory
 * SMW_STATUS_INVALID_PARAM          - Invalid function parameter
 * SMW_STATUS_UNKNOWN_ALGO_NAME      - Unknown hash algorithm name
 */
static int ecdh_convert_input_args(struct smw_derive_key_args *pub_args,
				   struct smw_keymgr_derive_key_args *conv_args,
				   enum subsystem_id *subsystem_id)
{
	int status = SMW_STATUS_OK;
	struct smw_keymgr_ecdh_args *ecdh_args = NULL;
	struct smw_key_descriptor *base_key_desc = NULL;
	struct smw_kdf_ecdh_args *ecdh_pub_args = pub_args->kdf_arguments;

	base_key_desc = pub_args->key_descriptor_base;

	/* Get the input key base for the derivation */
	status = smw_keymgr_convert_descriptor(base_key_desc,
					       &conv_args->key_base, false,
					       subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	ecdh_args = SMW_UTILS_MALLOC(sizeof(*ecdh_args));
	if (!ecdh_args) {
		status = SMW_STATUS_ALLOC_FAILURE;
		goto end;
	}

	ecdh_args->pub_args = ecdh_pub_args;
	conv_args->kdf_args = ecdh_args;
	conv_args->ops.get_peer = smw_keymgr_ecdh_get_peer_pub_buffer;
	conv_args->ops.get_peer_len = smw_keymgr_ecdh_get_peer_pub_buffer_len;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);

	return status;
}

static int
tls12_op_convert_input_args(struct smw_derive_key_args *pub_args,
			    struct smw_keymgr_derive_key_args *conv_args,
			    enum subsystem_id *subsystem_id)
{
	int status = SMW_STATUS_INVALID_PARAM;
	struct smw_keymgr_tls12_args *tls_args = NULL;
	struct smw_kdf_tls12_op_args *args = NULL;
	struct smw_kdf_tls12_master_secret_args *ms = NULL;
	struct smw_kdf_tls12_key_expansion_args *ke = NULL;
	enum smw_tls12_encryption_id enc_id = SMW_TLS12_ENCRYPTION_ID_INVALID;

	if (!pub_args)
		goto end;

	args = pub_args->kdf_arguments;

	if (!args)
		goto end;

	if (!args->context)
		goto end;

	if (args->version != 0) {
		status = SMW_STATUS_INVALID_VERSION;
		goto end;
	}

	if (args->op_name == SMW_TLS12_OP_NAME_MASTER_SECRET) {
		ms = &args->master_secret;

		if (ms->version != 0) {
			status = SMW_STATUS_INVALID_VERSION;
			goto end;
		}

		if (!ms->peer_public_buffer || !ms->peer_public_buffer_length)
			goto end;

		if (ms->ext_master_key) {
			if (!ms->session_hash || !ms->session_hash->hash ||
			    !ms->session_hash->hash_length)
				goto end;

			if (ms->session_hash->version != 0) {
				status = SMW_STATUS_INVALID_VERSION;
				goto end;
			}
		} else {
			if (!ms->random_data ||
			    !ms->random_data->client_random ||
			    !ms->random_data->client_random_length ||
			    !ms->random_data->server_random ||
			    !ms->random_data->server_random_length)
				goto end;

			if (ms->random_data->version != 0) {
				status = SMW_STATUS_INVALID_VERSION;
				goto end;
			}
		}
	} else if (args->op_name == SMW_TLS12_OP_NAME_KEY_EXPANSION) {
		ke = &args->key_expansion;

		if (ke->version != 0) {
			status = SMW_STATUS_INVALID_VERSION;
			goto end;
		}

		if (!ke->random_data || !ke->random_data->client_random ||
		    !ke->random_data->client_random_length ||
		    !ke->random_data->server_random ||
		    !ke->random_data->server_random_length)
			goto end;

		if (ke->random_data->version != 0) {
			status = SMW_STATUS_INVALID_VERSION;
			goto end;
		}
	} else {
		goto end;
	}

	/* Get the input key base for the derivation */
	status = smw_keymgr_convert_descriptor(pub_args->key_descriptor_base,
					       &conv_args->key_base, false,
					       subsystem_id);
	if (status != SMW_STATUS_OK)
		return status;

	tls_args = SMW_UTILS_MALLOC(sizeof(*tls_args));
	if (!tls_args) {
		status = SMW_STATUS_ALLOC_FAILURE;
		goto end;
	}

	tls_args->is_operation = true;

	status = get_prf_id(args->prf_name, &tls_args->prf_id);
	if (status != SMW_STATUS_OK)
		goto end;

	if (args->op_name == SMW_TLS12_OP_NAME_MASTER_SECRET) {
		status = tls12_get_key_exchange_id(ms->key_exchange_name,
						   tls_args);
		if (status != SMW_STATUS_OK)
			goto end;
	} else if (args->op_name == SMW_TLS12_OP_NAME_KEY_EXPANSION) {
		status = tls12_get_encryption_id(ke->encryption_name, &enc_id);
		if (status != SMW_STATUS_OK)
			goto end;

		tls_args->encryption_id = enc_id;

		if (smw_keymgr_tls12_is_encryption_aead(enc_id)) {
			if (!ke->client_w_iv || !ke->client_w_iv_length ||
			    !ke->server_w_iv || !ke->server_w_iv_length) {
				status = SMW_STATUS_INVALID_PARAM;
				goto end;
			}
		}
	}

	tls_args->pub_op_args = args;
	conv_args->kdf_args = tls_args;

	conv_args->ops.get_salt = smw_keymgr_tls12_get_label;
	conv_args->ops.get_salt_len = smw_keymgr_tls12_get_label_len;
	conv_args->ops.get_peer = smw_keymgr_tls12_get_peer_pub_buffer;
	conv_args->ops.get_peer_len = smw_keymgr_tls12_get_peer_pub_len;

	SMW_DBG_PRINTF(DEBUG, "KDF Input %p\n", args);

end:
	if (status != SMW_STATUS_OK && tls_args)
		free(tls_args);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);

	return status;
}

static int convert_input_args(struct smw_derive_key_args *args,
			      struct smw_keymgr_derive_key_args *conv_args,
			      enum subsystem_id *subsystem_id)
{
	/* Get the Key Derivation Function if any */
	int status = smw_config_get_kdf_id(args->kdf_name, &conv_args->kdf_id);

	if (status != SMW_STATUS_OK)
		return status;

	conv_args->store_key = args->store_derived_key;

	/*
	 * The key derivation arguments depends on the key derivation
	 * function if specified.
	 */
	switch (conv_args->kdf_id) {
	case SMW_CONFIG_KDF_ID_TLS12_KEY_EXCHANGE:
		status = tls12_convert_args(args, conv_args, subsystem_id);

		if (status == SMW_STATUS_OK)
			status = tls12_validate_key_base(conv_args);

		break;

	case SMW_CONFIG_KDF_ID_HKDF:
	case SMW_CONFIG_KDF_ID_HKDF_EXTRACT:
	case SMW_CONFIG_KDF_ID_HKDF_EXPAND:
		status = hkdf_convert_input_args(args, conv_args, subsystem_id);
		break;

	case SMW_CONFIG_KDF_ID_ECDH:
		status = ecdh_convert_input_args(args, conv_args, subsystem_id);
		break;

	case SMW_CONFIG_KDF_ID_TLS12_OP_KEY_EXCHANGE:
		status = tls12_op_convert_input_args(args, conv_args,
						     subsystem_id);

		if (status == SMW_STATUS_OK)
			status = tls12_validate_key_base(conv_args);

		break;

	default:
		status = SMW_STATUS_INVALID_PARAM;
		break;
	}

	return status;
}

static int derive_key_convert_args(struct smw_derive_key_args *args,
				   struct smw_keymgr_derive_key_args *conv_args,
				   enum subsystem_id *subsystem_id)
{
	int status = SMW_STATUS_VERSION_NOT_SUPPORTED;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (args->version != 0)
		goto end;

	status =
		smw_config_get_subsystem_id(args->subsystem_name, subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	conv_args->key_attributes = args->key_attributes;

	status = convert_input_args(args, conv_args, subsystem_id);

	if (status == SMW_STATUS_OK)
		status = convert_output_args(args, conv_args);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

unsigned char *smw_keymgr_get_salt(struct smw_keymgr_derive_key_args *args)
{
	if (args && args->ops.get_salt)
		return args->ops.get_salt(args);

	return NULL;
}

unsigned char *smw_keymgr_get_info(struct smw_keymgr_derive_key_args *args)
{
	if (args && args->ops.get_info)
		return args->ops.get_info(args);

	return NULL;
}

unsigned int smw_keymgr_get_salt_len(struct smw_keymgr_derive_key_args *args)
{
	if (args && args->ops.get_salt_len)
		return args->ops.get_salt_len(args);

	return 0;
}

unsigned int smw_keymgr_get_info_len(struct smw_keymgr_derive_key_args *args)
{
	if (args && args->ops.get_info_len)
		return args->ops.get_info_len(args);

	return 0;
}

unsigned char *
smw_keymgr_get_peer_pub_buffer(struct smw_keymgr_derive_key_args *args)
{
	if (args && args->ops.get_peer)
		return args->ops.get_peer(args);

	return NULL;
}

unsigned int
smw_keymgr_get_peer_pub_buffer_len(struct smw_keymgr_derive_key_args *args)
{
	if (args && args->ops.get_peer_len)
		return args->ops.get_peer_len(args);

	return 0;
}

enum smw_status_code smw_derive_key(struct smw_derive_key_args *args)
{
	int status = SMW_STATUS_OK;

	struct smw_keymgr_derive_key_args derive_key_args = { 0 };
	enum subsystem_id subsystem_id = SUBSYSTEM_ID_INVALID;
	unsigned int new_id = INVALID_KEY_ID;

	SMW_DBG_TRACE_API_CALL;

	if (!args || !args->key_descriptor_base ||
	    !args->key_descriptor_derived) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	status = derive_key_convert_args(args, &derive_key_args, &subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	if (args->store_derived_key) {
		status = create_key_in_db(&new_id, &derive_key_args);
		if (status != SMW_STATUS_OK)
			goto end;
	}

	status = smw_utils_execute_operation(OPERATION_ID_DERIVE_KEY,
					     &derive_key_args, subsystem_id);

	if (args->store_derived_key)
		status = update_key_in_db(status, &new_id, &derive_key_args);

end:
	if (derive_key_args.kdf_args)
		free(derive_key_args.kdf_args);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}
