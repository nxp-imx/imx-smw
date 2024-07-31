// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2024 NXP
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
 * tls12_convert_args() - Convert additional operation argument for TLS 1.2
 * @args: Input API additional argument
 * @conv_args: Converted arguments
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
static int tls12_convert_args(struct smw_kdf_tls12_args *args, void **conv_args)
{
	int status = SMW_STATUS_INVALID_PARAM;
	struct smw_keymgr_tls12_args *tls_args = NULL;

	if (!args || !args->kdf_input || !args->kdf_input_length)
		goto end;

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
	*conv_args = tls_args;
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

	if (tls_args->ephemeral_key) {
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

		key_desc = &conv_args->key_derived;

		status = smw_keymgr_convert_derived_key_desc(key_out, key_desc);
	} else {
		status = SMW_STATUS_OK;
	}

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
 * hkdf_convert_input_args() - Convert additional operation arguments for HKDF
 * @args: Pointer to additional HKDF operation arguments
 * @conv_args: Converted arguments
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
static int hkdf_convert_input_args(struct smw_kdf_hkdf_args *args,
				   void **conv_args)
{
	int status = SMW_STATUS_INVALID_PARAM;
	struct smw_keymgr_hkdf_args *hkdf_args = NULL;

	if (!args)
		goto end;

	if (!args->expand && !args->extract)
		goto end;

	hkdf_args = SMW_UTILS_MALLOC(sizeof(*hkdf_args));
	if (!hkdf_args) {
		status = SMW_STATUS_ALLOC_FAILURE;
		goto end;
	}

	status = get_prf_id(args->hash_algo, &hkdf_args->prf_id);
	if (status != SMW_STATUS_OK)
		goto end;

	hkdf_args->pub_args = args;
	*conv_args = hkdf_args;

end:
	if (status != SMW_STATUS_OK && hkdf_args)
		free(hkdf_args);

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

static int convert_input_args(struct smw_derive_key_args *args,
			      struct smw_keymgr_derive_key_args *conv_args,
			      enum subsystem_id *subsystem_id)
{
	/* Get the input key base for the derivation */
	int status = smw_keymgr_convert_descriptor(args->key_descriptor_base,
						   &conv_args->key_base, false,
						   subsystem_id);
	if (status != SMW_STATUS_OK)
		return status;

	/* Get the Key Derivation Function if any */
	status = smw_config_get_kdf_id(args->kdf_name, &conv_args->kdf_id);
	if (status != SMW_STATUS_OK)
		return status;

	/*
	 * The key derivation arguments depends on the key derivation
	 * function if specified.
	 */
	switch (conv_args->kdf_id) {
	case SMW_CONFIG_KDF_TLS12_KEY_EXCHANGE:
		status = tls12_convert_args(args->kdf_arguments,
					    &conv_args->kdf_args);

		if (status == SMW_STATUS_OK)
			status = tls12_validate_key_base(conv_args);

		break;

	case SMW_CONFIG_KDF_HKDF:
		status = hkdf_convert_input_args(args->kdf_arguments,
						 &conv_args->kdf_args);

		if (status == SMW_STATUS_OK)
			status = hkdf_validate_key_base(conv_args);

		break;

	default:
		/*
		 * Key base must be either a
		 *  - key identifier
		 *  - or a key private buffer
		 */
		status = check_key_definition(&conv_args->key_base,
					      SMW_KEYMGR_PRIVACY_ID_PRIVATE);
		break;
	}

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
	case SMW_CONFIG_KDF_TLS12_KEY_EXCHANGE:
		status = tls12_convert_output(args, conv_args);
		break;

	case SMW_CONFIG_KDF_HKDF:
		status = hkdf_convert_output(args, conv_args);
		break;

	default:
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

/**
 * create_key_in_db() - Create a key in the database
 * @id: New key identifier created in the database
 * @kdf_id: Key derivation function id
 * @identifier: Internal Key identifier object
 *
 * Function creates a new key in the OSAL object database if the key
 * derivation function is HKDF. The given @identifier is stored in the
 * object entry.
 *
 * Return:
 * SMW_STATUS_OK                - Success
 * SMW_STATUS_OPS_INVALID       - OSAL operation invalid
 * SMW_STATUS_KEY_DB_CREATE     - Key creation error
 */
static int create_key_in_db(unsigned int *new_id, enum smw_config_kdf_id kdf_id,
			    struct smw_keymgr_identifier *identifier)
{
	int status = SMW_STATUS_OK;

	if (kdf_id == SMW_CONFIG_KDF_HKDF)
		status = smw_keymgr_db_create(new_id, identifier);

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
 * @descriptor: Derived key descriptor structure
 *
 * If the HKDF based key derivation operation returns a status other than
 * SMW_STATUS_OK and SMW_STATUS_KEY_POLICY_WARNING_IGNORED, delete the key from
 * the database. If the key derivation operation is successful, update the
 * derived key identifier in the database.
 *
 * Return:
 * SMW_STATUS_OK                - Success
 * SMW_STATUS_OPS_INVALID       - OSAL operation invalid
 * SMW_STATUS_KEY_DB_UPDATE     - Key update error
 * SMW_STATUS_KEY_DB_DELETE     - Key delete error
 */
static int update_key_in_db(int status, unsigned int *id,
			    enum smw_config_kdf_id kdf_id,
			    struct smw_keymgr_derived_key_desc *key_desc)
{
	int ret_status = status;
	int temp_status = SMW_STATUS_OK;

	if (kdf_id == SMW_CONFIG_KDF_HKDF) {
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
	}

end:
	return ret_status;
}

bool smw_keymgr_tls12_is_encryption_aead(enum smw_tls12_encryption_id id)
{
	if (tls12_is_encryption_gcm(id))
		return true;

	return false;
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

unsigned char *smw_keymgr_get_salt(struct smw_keymgr_hkdf_args *args)
{
	unsigned char *salt = NULL;
	enum hkdf_step step = smw_keymgr_get_hkdf_step(args);

	if (step == HKDF_STEP_EXTRACT)
		salt = args->pub_args->hkdf_extract_args.salt;
	else if (step == HKDF_STEP_FULL)
		salt = args->pub_args->hkdf_args.salt;

	return salt;
}

unsigned int smw_keymgr_get_salt_len(struct smw_keymgr_hkdf_args *args)
{
	unsigned int salt_len = 0;
	enum hkdf_step step = smw_keymgr_get_hkdf_step(args);

	if (step == HKDF_STEP_EXTRACT)
		salt_len = args->pub_args->hkdf_extract_args.salt_len;
	else if (step == HKDF_STEP_FULL)
		salt_len = args->pub_args->hkdf_args.salt_len;

	return salt_len;
}

unsigned char *smw_keymgr_get_info(struct smw_keymgr_hkdf_args *args)
{
	unsigned char *info = NULL;
	enum hkdf_step step = smw_keymgr_get_hkdf_step(args);

	if (step == HKDF_STEP_EXPAND)
		info = args->pub_args->hkdf_expand_args.info;
	else if (step == HKDF_STEP_FULL)
		info = args->pub_args->hkdf_args.info;

	return info;
}

unsigned int smw_keymgr_get_info_len(struct smw_keymgr_hkdf_args *args)
{
	unsigned int info_len = 0;
	enum hkdf_step step = smw_keymgr_get_hkdf_step(args);

	if (step == HKDF_STEP_EXPAND)
		info_len = args->pub_args->hkdf_expand_args.info_len;
	else if (step == HKDF_STEP_FULL)
		info_len = args->pub_args->hkdf_args.info_len;

	return info_len;
}

unsigned int smw_keymgr_get_prk_id(struct smw_keymgr_hkdf_args *args)
{
	unsigned int id = 0;
	enum hkdf_step step = smw_keymgr_get_hkdf_step(args);

	if (step == HKDF_STEP_EXPAND)
		id = args->pub_args->hkdf_expand_args.prk_id;
	else if (step == HKDF_STEP_EXTRACT)
		id = args->pub_args->hkdf_extract_args.prk_id;

	return id;
}

inline void smw_keymgr_set_prk_id(struct smw_keymgr_hkdf_args *args,
				  unsigned int id)
{
	enum hkdf_step step = smw_keymgr_get_hkdf_step(args);

	if (step == HKDF_STEP_EXTRACT)
		args->pub_args->hkdf_extract_args.prk_id = id;
}

unsigned char *smw_keymgr_get_prk(struct smw_keymgr_hkdf_args *args)
{
	unsigned char *prk = NULL;
	enum hkdf_step step = smw_keymgr_get_hkdf_step(args);

	if (step == HKDF_STEP_EXPAND)
		prk = args->pub_args->hkdf_expand_args.prk;
	else if (step == HKDF_STEP_EXTRACT)
		prk = args->pub_args->hkdf_extract_args.prk;

	return prk;
}

unsigned int smw_keymgr_get_prk_len(struct smw_keymgr_hkdf_args *args)
{
	unsigned int prk_len = 0;
	enum hkdf_step step = smw_keymgr_get_hkdf_step(args);

	if (step == HKDF_STEP_EXTRACT)
		prk_len = args->pub_args->hkdf_extract_args.prk_len;
	else if (step == HKDF_STEP_EXPAND)
		prk_len = args->pub_args->hkdf_expand_args.prk_len;

	return prk_len;
}

inline void smw_keymgr_set_prk_len(struct smw_keymgr_hkdf_args *args,
				   unsigned int length)
{
	enum hkdf_step step = smw_keymgr_get_hkdf_step(args);

	if (step == HKDF_STEP_EXTRACT)
		args->pub_args->hkdf_extract_args.prk_len = length;
}

unsigned int smw_keymgr_get_okm_len(struct smw_keymgr_hkdf_args *args)
{
	unsigned int okm_len = 0;
	enum hkdf_step step = smw_keymgr_get_hkdf_step(args);

	if (step == HKDF_STEP_EXPAND)
		okm_len = args->pub_args->hkdf_expand_args.okm_len;
	else if (step == HKDF_STEP_FULL)
		okm_len = args->pub_args->hkdf_args.okm_len;

	return okm_len;
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

	status = create_key_in_db(&new_id, derive_key_args.kdf_id,
				  &derive_key_args.key_derived.identifier);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_utils_execute_operation(OPERATION_ID_DERIVE_KEY,
					     &derive_key_args, subsystem_id);

	status = update_key_in_db(status, &new_id, derive_key_args.kdf_id,
				  &derive_key_args.key_derived);

end:
	if (derive_key_args.kdf_args)
		free(derive_key_args.kdf_args);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}
