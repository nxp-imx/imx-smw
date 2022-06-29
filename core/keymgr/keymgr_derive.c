// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2022 NXP
 */

#include "smw_keymgr.h"
#include "smw_status.h"

#include "debug.h"
#include "operations.h"
#include "subsystems.h"
#include "keymgr_derive.h"
#include "exec.h"
#include "name.h"
#include "utils.h"

static const char *const tls12_key_exchange_name[] = {
	[SMW_TLS12_KEY_EXCHANGE_ID_RSA] = "RSA",
	[SMW_TLS12_KEY_EXCHANGE_ID_DH_DSS] = "DH_DSS",
	[SMW_TLS12_KEY_EXCHANGE_ID_DH_RSA] = "DH_RSA",
	[SMW_TLS12_KEY_EXCHANGE_ID_DHE_DSS] = "DHE_DSS",
	[SMW_TLS12_KEY_EXCHANGE_ID_DHE_RSA] = "DHE_RSA",
	[SMW_TLS12_KEY_EXCHANGE_ID_ECDH_ECDSA] = "ECDH_ECDSA",
	[SMW_TLS12_KEY_EXCHANGE_ID_ECDH_RSA] = "ECDH_RSA",
	[SMW_TLS12_KEY_EXCHANGE_ID_ECDHE_ECDSA] = "ECDHE_ECDSA",
	[SMW_TLS12_KEY_EXCHANGE_ID_ECDHE_RSA] = "ECDHE_RSA"
};

static const char *const tls12_encryption_name[] = {
	[SMW_TLS12_ENCRYPTION_ID_RC4_128] = "RC4_128",
	[SMW_TLS12_ENCRYPTION_ID_3DES_EDE_CBC] = "3DES_EDE_CBC",
	[SMW_TLS12_ENCRYPTION_ID_AES_128_CBC] = "AES_128_CBC",
	[SMW_TLS12_ENCRYPTION_ID_AES_256_CBC] = "AES_256_CBC",
	[SMW_TLS12_ENCRYPTION_ID_AES_128_GCM] = "AES_128_GCM",
	[SMW_TLS12_ENCRYPTION_ID_AES_256_GCM] = "AES_256_GCM"
};

/**
 * tls12_get_key_exchange_id() - Get ID of TLS 1.2 key exchange name
 * @name: Key exchange name
 * @args: TLS 1.2 internal arguments
 *
 * Return:
 * SMW_STATUS_OK              - Success
 * SMW_STATUS_INVALID_PARAM   - Invalid function parameter
 * SMW_STATUS_UNKNOWN_NAME    - String name is not referenced
 */
static int tls12_get_key_exchange_id(const char *name,
				     struct smw_keymgr_tls12_args *args)
{
	int status = SMW_STATUS_INVALID_PARAM;

	SMW_DBG_TRACE_FUNCTION_CALL;

	args->key_exchange_id = SMW_TLS12_KEY_EXCHANGE_ID_INVALID;

	if (name)
		status =
			smw_utils_get_string_index(name,
						   tls12_key_exchange_name,
						   SMW_TLS12_KEY_EXCHANGE_ID_NB,
						   &args->key_exchange_id);

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

		status = SMW_STATUS_OK;
		break;

	case SMW_CONFIG_KEY_TYPE_ID_ECDH_NIST:
	case SMW_CONFIG_KEY_TYPE_ID_ECDH_BRAINPOOL_R1:
	case SMW_CONFIG_KEY_TYPE_ID_ECDH_BRAINPOOL_T1:
		switch (tls_args->key_exchange_id) {
		case SMW_TLS12_KEY_EXCHANGE_ID_ECDH_ECDSA:
		case SMW_TLS12_KEY_EXCHANGE_ID_ECDH_RSA:
		case SMW_TLS12_KEY_EXCHANGE_ID_ECDHE_ECDSA:
		case SMW_TLS12_KEY_EXCHANGE_ID_ECDHE_RSA:
			status = SMW_STATUS_OK;
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
			status = SMW_STATUS_OK;
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
 * SMW_STATUS_OK              - Success
 * SMW_STATUS_INVALID_PARAM   - Invalid function parameter
 * SMW_STATUS_UNKNOWN_NAME    - String name is not referenced
 */
static int tls12_get_encryption_id(const char *name,
				   enum smw_tls12_encryption_id *id)
{
	int status = SMW_STATUS_INVALID_PARAM;

	SMW_DBG_TRACE_FUNCTION_CALL;

	*id = SMW_TLS12_ENCRYPTION_ID_INVALID;

	if (name)
		status = smw_utils_get_string_index(name, tls12_encryption_name,
						    SMW_TLS12_ENCRYPTION_ID_NB,
						    id);

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
 * tls12_get_prf_id() - Get ID of TLS 1.2 Pseudo-Random Function
 * @name: Pseudo-Random Function name
 * @id: ID of the Pseudo-Random Function name
 *
 * Return:
 * SMW_STATUS_OK              - Success
 * SMW_STATUS_INVALID_PARAM   - Invalid function parameter
 * SMW_STATUS_UNKNOWN_NAME    - String name is not referenced
 */
static int tls12_get_prf_id(const char *name, enum smw_config_hmac_algo_id *id)
{
	int status = SMW_STATUS_INVALID_PARAM;

	SMW_DBG_TRACE_FUNCTION_CALL;

	*id = SMW_CONFIG_HMAC_ALGO_ID_INVALID;

	if (name)
		status = smw_config_get_hmac_algo_id(name, id);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);

	return status;
}

/**
 * tls12_convert_args() - Convert additional operation argument for TLS 1.2
 * @args: Input API addtional argument
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
 * SMW_STATUS_OK            - Success
 * SMW_STATUS_ALLOC_FAILURE - Out of memory
 * SMW_STATUS_INVALID_PARAM - Invalid function parameter
 * SMW_STATUS_UNKNOWN_NAME  - String name is not referenced
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

	status = tls12_get_prf_id(args->prf_name, &tls_args->prf_id);
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
 * @args: Input API addtional argument
 * @conv_args: Converted arguments
 *
 * Function allocates the TLS 1.2 internal arguments object and converts
 * additional operation argument.
 * If conversion failed, free the TLS 1.2 internal arguments object.
 *
 * The output of key derivation is a set of Key IDs returned in the
 * operation additional arguments function of the Cipher encrytion.
 * In addition, if the encryption algorithm is AES GCM, the
 * Cient and Server write IVs are returned in the dedicated
 * IV buffers of the additional arguments.
 * If the key exchange is an ephemeral key, the generated
 * public key is exported in the derived key descriptor.
 *
 * Return:
 * SMW_STATUS_OK              - Success
 * SMW_STATUS_ALLOC_FAILURE   - Out of memory
 * SMW_STATUS_INVALID_PARAM   - Invalid function parameter
 * SMW_STATUS_UNKNOWN_NAME    - String name is not referenced
 */
static int tls12_convert_output(struct smw_derive_key_args *args,
				struct smw_keymgr_derive_key_args *conv_args)

{
	int status = SMW_STATUS_INVALID_PARAM;

	struct smw_key_descriptor *key_base;
	struct smw_key_descriptor *key_out;
	struct smw_keymgr_tls12_args *tls_args;
	struct smw_keymgr_descriptor *key_desc;
	unsigned int exp_pub_length = 0;

	key_base = args->key_descriptor_base;
	key_out = args->key_descriptor_derived;

	if (key_out->id || !conv_args->kdf_args)
		goto end;

	tls_args = conv_args->kdf_args;

	status = SMW_STATUS_OK;

	if (tls_args->ephemeral_key) {
		/*
		 * Prepare key derived output value before doing the
		 * key conversion to ensure that key converted into
		 * internal object is correct.
		 */
		key_out->id = INVALID_KEY_ID;
		key_out->type_name = key_base->type_name;
		key_out->security_size = key_base->security_size;

		key_desc = &conv_args->key_derived;
		/* Input base key defined the key type and size */
		status = smw_keymgr_convert_descriptor(key_out, key_desc);
		if (status != SMW_STATUS_OK)
			goto end;

		status = smw_keymgr_get_buffers_lengths(&key_desc->identifier,
							key_desc->format_id,
							&exp_pub_length, NULL,
							NULL);

		if (smw_keymgr_get_public_data(key_desc) &&
		    smw_keymgr_get_public_length(key_desc) < exp_pub_length)
			status = SMW_STATUS_INVALID_PARAM;
	}

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);

	return status;
}

static int convert_input_args(struct smw_derive_key_args *args,
			      struct smw_keymgr_derive_key_args *conv_args)
{
	int status;

	/* Get the input key base for the derivation */
	status = smw_keymgr_convert_descriptor(args->key_descriptor_base,
					       &conv_args->key_base);
	if (status != SMW_STATUS_OK && status != SMW_STATUS_NO_KEY_BUFFER)
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

	default:
		/*
		 * Key base must by either a
		 *  - key identifier
		 *  - or a key private buffer
		 */
		status = check_key_definition(&conv_args->key_base,
					      SMW_KEYMGR_PRIVACY_ID_PRIVATE);
	}

	return status;
}

static int convert_output_args(struct smw_derive_key_args *args,
			       struct smw_keymgr_derive_key_args *conv_args)
{
	int status = SMW_STATUS_INVALID_PARAM;

	/*
	 * The output key derivation depends on the key derivation
	 * function if specified.
	 */
	switch (conv_args->kdf_id) {
	case SMW_CONFIG_KDF_TLS12_KEY_EXCHANGE:
		status = tls12_convert_output(args, conv_args);
		break;

	default:
		status = SMW_STATUS_OK;
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

	/* Initialize key_attributes parameters to default values */
	smw_keymgr_set_default_attributes(&conv_args->key_attributes);

	status = smw_keymgr_read_attributes(&conv_args->key_attributes,
					    args->key_attributes_list,
					    &args->key_attributes_list_length);
	if (status != SMW_STATUS_OK)
		goto end;

	status = convert_input_args(args, conv_args);

	if (status == SMW_STATUS_OK)
		status = convert_output_args(args, conv_args);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

enum smw_status_code smw_derive_key(struct smw_derive_key_args *args)
{
	int status = SMW_STATUS_OK;

	struct smw_keymgr_derive_key_args derive_key_args = { 0 };
	enum subsystem_id subsystem_id = SUBSYSTEM_ID_INVALID;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!args || !args->key_descriptor_base ||
	    !args->key_descriptor_derived) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	status = derive_key_convert_args(args, &derive_key_args, &subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_utils_execute_operation(OPERATION_ID_DERIVE_KEY,
					     &derive_key_args, subsystem_id);

end:
	if (derive_key_args.kdf_args)
		free(derive_key_args.kdf_args);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

bool smw_keymgr_tls12_is_encryption_aead(enum smw_tls12_encryption_id id)
{
	if (tls12_is_encryption_gcm(id))
		return true;

	return false;
}
