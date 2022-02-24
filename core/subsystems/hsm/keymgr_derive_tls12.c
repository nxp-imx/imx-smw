// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2022 NXP
 */

#include "smw_status.h"

#include "debug.h"
#include "subsystems.h"
#include "utils.h"
#include "base64.h"
#include "keymgr_db.h"

#include "common.h"
#include "keymgr_derive_tls12.h"

/*
 * HSM TLS 1.2 hard coded value
 */
#define TLS12_CLIENT_W_IV_SIZE 4 /* Client write IVs */
#define TLS12_SERVER_W_IV_SIZE 4 /* Server write IVs */
#define TLS12_KDF_OUTPUT_SIZE  (TLS12_CLIENT_W_IV_SIZE + TLS12_SERVER_W_IV_SIZE)

#define TLS12_NB_KEYS_WITH_MAC 5 /* Number of keys when MAC keys present */
#define TLS12_NB_KEYS_NO_MAC   3 /* Number of keys when no MAC keys present */

#define TLS12_KDF_INPUT_SIZE		128
#define TLS12_KDF_EMS_SHA256_INPUT_SIZE 96
#define TLS12_KDF_EMS_SHA384_INPUT_SIZE 112

/*
 * List of TLS 1.2 Cipher suite supported in HSM
 * hsm_tls12_kdf[]: list of Key derivation function
 * hsm_tls12_key_ids[]: list of Keys (initiator and exchange)
 */
static const struct tls12_kdf_info {
	enum smw_tls12_key_exchange_id key_exchange_id;
	enum smw_tls12_encryption_id encryption_id;
	enum smw_config_hmac_algo_id prf_id;
	enum smw_config_key_type_id mac_key_id;
	unsigned int mac_security_size;
	enum smw_config_key_type_id enc_key_id;
	unsigned int enc_security_size;
	hsm_kdf_algo_id_t hsm_kdf;
	hsm_op_key_exchange_flags_t hsm_flags;
	unsigned char hsm_nb_shared_key_id;
} hsm_tls12_kdf[] = {
	{
		// TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
		.key_exchange_id = SMW_TLS12_KEY_EXCHANGE_ID_ECDHE_ECDSA,
		.encryption_id = SMW_TLS12_ENCRYPTION_ID_AES_128_CBC,
		.prf_id = SMW_CONFIG_HMAC_ALGO_ID_SHA256,
		.mac_key_id = SMW_CONFIG_KEY_TYPE_ID_HMAC_SHA256,
		.mac_security_size = 256,
		.enc_key_id = SMW_CONFIG_KEY_TYPE_ID_AES,
		.enc_security_size = 128,
		.hsm_kdf = HSM_KDF_HMAC_SHA_256_TLS_32_16_4,
		.hsm_flags = HSM_OP_KEY_EXCHANGE_FLAGS_GENERATE_EPHEMERAL |
			     HSM_KEY_INFO_TRANSIENT,
		.hsm_nb_shared_key_id = TLS12_NB_KEYS_WITH_MAC,
	},
	{
		// TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
		.key_exchange_id = SMW_TLS12_KEY_EXCHANGE_ID_ECDHE_ECDSA,
		.encryption_id = SMW_TLS12_ENCRYPTION_ID_AES_256_CBC,
		.prf_id = SMW_CONFIG_HMAC_ALGO_ID_SHA384,
		.mac_key_id = SMW_CONFIG_KEY_TYPE_ID_HMAC_SHA384,
		.mac_security_size = 384,
		.enc_key_id = SMW_CONFIG_KEY_TYPE_ID_AES,
		.enc_security_size = 256,
		.hsm_kdf = HSM_KDF_HMAC_SHA_384_TLS_48_32_4,
		.hsm_flags = HSM_OP_KEY_EXCHANGE_FLAGS_GENERATE_EPHEMERAL |
			     HSM_KEY_INFO_TRANSIENT,
		.hsm_nb_shared_key_id = TLS12_NB_KEYS_WITH_MAC,
	},
	{
		// TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
		.key_exchange_id = SMW_TLS12_KEY_EXCHANGE_ID_ECDHE_ECDSA,
		.encryption_id = SMW_TLS12_ENCRYPTION_ID_AES_128_GCM,
		.prf_id = SMW_CONFIG_HMAC_ALGO_ID_SHA256,
		.enc_key_id = SMW_CONFIG_KEY_TYPE_ID_AES,
		.enc_security_size = 128,
		.hsm_kdf = HSM_KDF_HMAC_SHA_256_TLS_0_16_4,
		.hsm_flags = HSM_OP_KEY_EXCHANGE_FLAGS_GENERATE_EPHEMERAL |
			     HSM_KEY_INFO_TRANSIENT,
		.hsm_nb_shared_key_id = TLS12_NB_KEYS_NO_MAC,
	},
	{
		// TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
		.key_exchange_id = SMW_TLS12_KEY_EXCHANGE_ID_ECDHE_ECDSA,
		.encryption_id = SMW_TLS12_ENCRYPTION_ID_AES_256_GCM,
		.prf_id = SMW_CONFIG_HMAC_ALGO_ID_SHA384,
		.enc_key_id = SMW_CONFIG_KEY_TYPE_ID_AES,
		.enc_security_size = 256,
		.hsm_kdf = HSM_KDF_HMAC_SHA_384_TLS_0_32_4,
		.hsm_flags = HSM_OP_KEY_EXCHANGE_FLAGS_GENERATE_EPHEMERAL |
			     HSM_KEY_INFO_TRANSIENT,
		.hsm_nb_shared_key_id = TLS12_NB_KEYS_NO_MAC,
	},
};

static const struct {
	enum smw_config_key_type_id key_type_id;
	unsigned int security_size;
	hsm_key_type_t hsm_key_initiator;
	hsm_key_exchange_scheme_id_t hsm_key_exchange;
} hsm_tls12_key_ids[] = {
	{
		.key_type_id = SMW_CONFIG_KEY_TYPE_ID_ECDH_NIST,
		.security_size = 256,
		.hsm_key_initiator = HSM_KEY_TYPE_ECDSA_NIST_P256,
		.hsm_key_exchange = HSM_KE_SCHEME_ECDH_NIST_P256,
	},
	{
		.key_type_id = SMW_CONFIG_KEY_TYPE_ID_ECDH_NIST,
		.security_size = 384,
		.hsm_key_initiator = HSM_KEY_TYPE_ECDSA_NIST_P384,
		.hsm_key_exchange = HSM_KE_SCHEME_ECDH_NIST_P384,
	},
	{
		.key_type_id = SMW_CONFIG_KEY_TYPE_ID_ECDH_BRAINPOOL_R1,
		.security_size = 256,
		.hsm_key_initiator = HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_256,
		.hsm_key_exchange = HSM_KE_SCHEME_ECDH_BRAINPOOL_R1_256,
	},
	{
		.key_type_id = SMW_CONFIG_KEY_TYPE_ID_ECDH_BRAINPOOL_R1,
		.security_size = 384,
		.hsm_key_initiator = HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_384,
		.hsm_key_exchange = HSM_KE_SCHEME_ECDH_BRAINPOOL_R1_384,
	},
};

static int get_hsm_tls_key_exchange_ids(struct smw_keymgr_identifier *key,
					op_key_exchange_args_t *op_args)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	enum smw_config_key_type_id type_id = key->type_id;
	unsigned short security_size = key->security_size;
	unsigned int i;

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (i = 0; i < ARRAY_SIZE(hsm_tls12_key_ids); i++) {
		if (hsm_tls12_key_ids[i].key_type_id == type_id &&
		    hsm_tls12_key_ids[i].security_size == security_size) {
			op_args->initiator_public_data_type =
				hsm_tls12_key_ids[i].hsm_key_initiator;
			op_args->key_exchange_scheme =
				hsm_tls12_key_ids[i].hsm_key_exchange;
			status = SMW_STATUS_OK;
			break;
		}
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static const struct tls12_kdf_info *
get_tls12_kdf_info(struct smw_keymgr_tls12_args *args)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(hsm_tls12_kdf); i++) {
		if (hsm_tls12_kdf[i].key_exchange_id == args->key_exchange_id &&
		    hsm_tls12_kdf[i].encryption_id == args->encryption_id &&
		    hsm_tls12_kdf[i].prf_id == args->prf_id)
			return &hsm_tls12_kdf[i];
	}

	return NULL;
}

static void delete_db_shared_keys(unsigned int *ids_array, int nb_shared_keys)
{
	int idx;
	struct smw_keymgr_identifier identifier = { 0 };

	identifier.id = INVALID_KEY_ID;
	identifier.subsystem_id = SUBSYSTEM_ID_HSM;
	/* Only transient key are generated */
	identifier.persistent = false;

	/* Delete all keys from the database */
	for (idx = 0; idx < nb_shared_keys && ids_array[idx] != INVALID_KEY_ID;
	     idx++) {
		(void)smw_keymgr_db_delete(ids_array[idx], &identifier);
	}
}

static int add_update_db_shared_keys(struct smw_keymgr_derive_key_args *args,
				     int nb_shared_keys,
				     unsigned int *ids_array,
				     unsigned int *ids_hsm_array)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
	int idx;
	unsigned int *id = ids_array;
	unsigned int *hsm_id = ids_hsm_array;
	struct smw_keymgr_identifier identifier = { 0 };
	struct smw_keymgr_tls12_args *tls_args;
	const struct tls12_kdf_info *kdf_info;

	tls_args = args->kdf_args;
	kdf_info = get_tls12_kdf_info(tls_args);
	if (!kdf_info)
		return status;

	/* Initialize the ids_array with invalid key ids */
	for (idx = 0; !hsm_id && idx < nb_shared_keys; idx++)
		ids_array[idx] = INVALID_KEY_ID;

	identifier.id = INVALID_KEY_ID;
	identifier.subsystem_id = SUBSYSTEM_ID_HSM;
	/* Only transient key are generated */
	identifier.persistent = false;

	if (nb_shared_keys == TLS12_NB_KEYS_WITH_MAC) {
		/*
		 * Create the Client and Server MAC write keys
		 */
		identifier.type_id = kdf_info->mac_key_id;
		identifier.security_size = kdf_info->mac_security_size;

		status = smw_keymgr_get_privacy_id(identifier.type_id,
						   &identifier.privacy_id);
		if (status != SMW_STATUS_OK)
			goto end;

		if (!hsm_id) {
			/* Create the Client MAC write Key */
			status = smw_keymgr_db_create(id, &identifier);
		} else {
			/* Update the Client MAC write Key */
			identifier.id = *hsm_id++;
			smw_keymgr_tls12_set_client_w_mac_key_id(tls_args, *id);
			status = smw_keymgr_db_update(*id, &identifier);
		}

		if (status != SMW_STATUS_OK) {
			SMW_DBG_PRINTF(ERROR,
				       "%s Key DB Client MAC key error\n",
				       (hsm_id) ? "Update" : "Create");
			goto end;
		}
		id++;

		if (!hsm_id) {
			/* Create the Server MAC write Key */
			status = smw_keymgr_db_create(id, &identifier);
		} else {
			/* Update the Server MAC write Key */
			identifier.id = *hsm_id++;
			smw_keymgr_tls12_set_server_w_mac_key_id(tls_args, *id);
			status = smw_keymgr_db_update(*id, &identifier);
		}
		id++;

		if (status != SMW_STATUS_OK) {
			SMW_DBG_PRINTF(ERROR,
				       "%s Key DB Server MAC key error\n",
				       (hsm_id) ? "Update" : "Create");
			goto end;
		}
	}

	/*
	 * Create Client and Server encryption write keys
	 */
	identifier.type_id = kdf_info->enc_key_id;
	identifier.security_size = kdf_info->enc_security_size;
	status = smw_keymgr_get_privacy_id(identifier.type_id,
					   &identifier.privacy_id);
	if (status != SMW_STATUS_OK)
		goto end;

	if (!hsm_id) {
		/* Create the Client Encryption write Key */
		status = smw_keymgr_db_create(id, &identifier);
	} else {
		/* Update the Client Encryption write Key */
		identifier.id = *hsm_id++;
		smw_keymgr_tls12_set_client_w_enc_key_id(tls_args, *id);
		status = smw_keymgr_db_update(*id, &identifier);
	}
	id++;

	if (status != SMW_STATUS_OK) {
		SMW_DBG_PRINTF(ERROR, "%s Key DB Client Encryption key error\n",
			       (hsm_id) ? "Update" : "Create");
		goto end;
	}

	if (!hsm_id) {
		/* Create the Server Encryption write Key */
		status = smw_keymgr_db_create(id, &identifier);
	} else {
		/* Update the Server Encryption write Key */
		identifier.id = *hsm_id++;
		smw_keymgr_tls12_set_server_w_enc_key_id(tls_args, *id);
		status = smw_keymgr_db_update(*id, &identifier);
	}
	id++;

	if (status != SMW_STATUS_OK) {
		SMW_DBG_PRINTF(ERROR, "%s Key DB Server Encryption key error\n",
			       (hsm_id) ? "Update" : "Create");
		goto end;
	}

	/*
	 * Create the Master Key
	 */
	identifier.type_id = SMW_CONFIG_KEY_TYPE_ID_TLS_MASTER_KEY;
	identifier.security_size = TLS12_MASTER_SECRET_SEC_SIZE;
	status = smw_keymgr_get_privacy_id(identifier.type_id,
					   &identifier.privacy_id);
	if (status != SMW_STATUS_OK)
		goto end;

	if (!hsm_id) {
		/* Create the Master Key */
		status = smw_keymgr_db_create(id, &identifier);
	} else {
		/* Update the Master Key */
		identifier.id = *hsm_id;
		smw_keymgr_tls12_set_master_sec_key_id(tls_args, *id);
		status = smw_keymgr_db_update(*id, &identifier);
	}

	if (status != SMW_STATUS_OK) {
		SMW_DBG_PRINTF(ERROR, "%s Key DB Master key error\n",
			       (hsm_id) ? "Update" : "Create");
	}

end:
	if (status != SMW_STATUS_OK && !hsm_id)
		delete_db_shared_keys(ids_array, nb_shared_keys);

	return status;
}

static int check_ivs_length(struct smw_keymgr_tls12_args *tls_args)
{
	/* Verify Client and Server Write IV lengths */
	if (smw_keymgr_tls12_get_client_w_iv_length(tls_args) <
	    TLS12_CLIENT_W_IV_SIZE) {
		SMW_DBG_PRINTF(DEBUG, "Client Write IV too short\n");
		smw_keymgr_tls12_set_client_w_iv_length(tls_args,
							TLS12_CLIENT_W_IV_SIZE);
		return SMW_STATUS_OUTPUT_TOO_SHORT;
	}

	if (smw_keymgr_tls12_get_server_w_iv_length(tls_args) <
	    TLS12_SERVER_W_IV_SIZE) {
		SMW_DBG_PRINTF(DEBUG, "Server Write IV too short\n");
		smw_keymgr_tls12_set_server_w_iv_length(tls_args,
							TLS12_SERVER_W_IV_SIZE);

		return SMW_STATUS_OUTPUT_TOO_SHORT;
	}

	return SMW_STATUS_OK;
}

static int check_kdf_input_length(op_key_exchange_args_t *args,
				  enum smw_config_hmac_algo_id prf_id)
{
	if ((args->flags & HSM_OP_KEY_EXCHANGE_FLAGS_USE_TLS_EMS) ==
	    HSM_OP_KEY_EXCHANGE_FLAGS_USE_TLS_EMS) {
		switch (prf_id) {
		case SMW_CONFIG_HMAC_ALGO_ID_SHA256:
			if (args->kdf_input_size !=
			    TLS12_KDF_EMS_SHA256_INPUT_SIZE)
				return SMW_STATUS_INVALID_PARAM;

			return SMW_STATUS_OK;

		case SMW_CONFIG_HMAC_ALGO_ID_SHA384:
			if (args->kdf_input_size !=
			    TLS12_KDF_EMS_SHA384_INPUT_SIZE)
				return SMW_STATUS_INVALID_PARAM;

			return SMW_STATUS_OK;

		default:
			return SMW_STATUS_INVALID_PARAM;
		}
	}

	if (args->kdf_input_size != TLS12_KDF_INPUT_SIZE)
		return SMW_STATUS_INVALID_PARAM;

	return SMW_STATUS_OK;
}

int derive_tls12(struct hdl *hdl, struct smw_keymgr_derive_key_args *args)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	struct smw_keymgr_identifier *key_derived_id;
	struct smw_keymgr_tls12_args *tls_args;
	const struct tls12_kdf_info *kdf_info;

	unsigned char kdf_output[TLS12_KDF_OUTPUT_SIZE] = { 0 };
	unsigned char *key_base;
	unsigned char *hex_key_base = NULL;
	unsigned char *key_derived = NULL;
	unsigned char *hex_key_derived = NULL;
	unsigned int *shared_key_ids = NULL;
	unsigned int *new_key_ids = NULL;
	unsigned int key_base_len;
	unsigned int key_derived_len;
	unsigned int hex_key_base_len;
	unsigned int hex_key_derived_len;
	int nb_shared_keys = 0;

	hsm_err_t hsm_err;
	op_key_exchange_args_t op_hsm_args = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	key_derived_id = &args->key_derived.identifier;
	tls_args = args->kdf_args;

	kdf_info = get_tls12_kdf_info(args->kdf_args);
	if (!kdf_info)
		goto end;

	status = get_hsm_tls_key_exchange_ids(key_derived_id, &op_hsm_args);
	if (status != SMW_STATUS_OK)
		goto end;

	if (smw_keymgr_tls12_is_encryption_aead(tls_args->encryption_id)) {
		status = check_ivs_length(tls_args);
		if (status != SMW_STATUS_OK)
			goto end;
	}

	/*
	 * Client and Server write IVs
	 * KDF output can't be NULL even if IV's are not expected
	 */
	op_hsm_args.kdf_output_size = sizeof(kdf_output);
	op_hsm_args.kdf_output = kdf_output;

	key_derived = smw_keymgr_get_public_data(&args->key_derived);
	key_derived_len = smw_keymgr_get_public_length(&args->key_derived);

	/* Key derived public output pointer must be defined */
	if (!key_derived) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	/* Get HEX derived key length */
	status = smw_keymgr_get_buffers_lengths(key_derived_id,
						SMW_KEYMGR_FORMAT_ID_HEX,
						&hex_key_derived_len, NULL,
						NULL);
	if (status != SMW_STATUS_OK)
		goto end;

	if (args->key_derived.format_id == SMW_KEYMGR_FORMAT_ID_BASE64) {
		hex_key_derived = SMW_UTILS_MALLOC(hex_key_derived_len);
		if (!hex_key_derived) {
			SMW_DBG_PRINTF(ERROR, "Allocation failure\n");
			status = SMW_STATUS_ALLOC_FAILURE;
			goto end;
		}

		op_hsm_args.ke_output = hex_key_derived;
		op_hsm_args.ke_output_size = hex_key_derived_len;
	} else {
		op_hsm_args.ke_output = key_derived;
		op_hsm_args.ke_output_size = hex_key_derived_len;
	}

	op_hsm_args.kdf_algorithm = kdf_info->hsm_kdf;
	op_hsm_args.shared_key_identifier_array_size =
		sizeof(unsigned int) * kdf_info->hsm_nb_shared_key_id;

	/*
	 * Shared key identifier array size depends if KDF is HMAC or not.
	 * Hence if cipher encryption is GCM, KDF is a SHA not HMAC.
	 *
	 * Allocate a double buffer to handle the OSAL Key IDs pre-added
	 * in the database and the TLS 1.2 shared keys
	 */
	nb_shared_keys = kdf_info->hsm_nb_shared_key_id;
	new_key_ids =
		SMW_UTILS_MALLOC(nb_shared_keys * sizeof(*new_key_ids) +
				 op_hsm_args.shared_key_identifier_array_size);
	if (!new_key_ids) {
		SMW_DBG_PRINTF(ERROR, "Allocation failure\n");
		status = SMW_STATUS_ALLOC_FAILURE;
		goto end;
	}

	shared_key_ids = new_key_ids + nb_shared_keys;

	status = add_update_db_shared_keys(args, nb_shared_keys, new_key_ids,
					   NULL);
	if (status != SMW_STATUS_OK)
		goto end;

	op_hsm_args.flags = kdf_info->hsm_flags;

	/* Add extended Master secret key flag if requested */
	if (smw_keymgr_tls12_get_ext_master_key(tls_args))
		op_hsm_args.flags |= HSM_OP_KEY_EXCHANGE_FLAGS_USE_TLS_EMS;

	op_hsm_args.kdf_input_size =
		smw_keymgr_tls12_get_kdf_input_length(tls_args);

	status = check_kdf_input_length(&op_hsm_args, kdf_info->prf_id);
	if (status != SMW_STATUS_OK)
		goto end;

	op_hsm_args.kdf_input = smw_keymgr_tls12_get_kdf_input(tls_args);

	op_hsm_args.shared_key_identifier_array = (uint8_t *)shared_key_ids;

	key_base = smw_keymgr_get_public_data(&args->key_base);
	key_base_len = smw_keymgr_get_public_length(&args->key_base);

	if (args->key_base.format_id == SMW_KEYMGR_FORMAT_ID_BASE64) {
		status = smw_utils_base64_decode(key_base, key_base_len,
						 &hex_key_base,
						 &hex_key_base_len);
		if (status != SMW_STATUS_OK)
			goto end;

		op_hsm_args.ke_input = hex_key_base;
		op_hsm_args.ke_input_size = hex_key_base_len;
	} else {
		op_hsm_args.ke_input = key_base;
		op_hsm_args.ke_input_size = key_base_len;
	}

	/* Only Transient keys generated */
	op_hsm_args.shared_key_info = HSM_KEY_INFO_TRANSIENT;
	op_hsm_args.shared_key_group = TRANSIENT_KEY_GROUP;

	SMW_DBG_PRINTF(VERBOSE,
		       "[%s (%d)] Call hsm_key_exchange()\n"
		       "  key_management_hdl: %d\n"
		       "  op_key_exchange_args_t\n"
		       "    key_identifier: %d\n"
		       "    shared_key_identifier_array: %p (size %d)\n"
		       "    ke_input: %p (size %d)\n"
		       "    ke_ouput: %p (size %d)\n"
		       "    kdf_input: %p (size %d)\n"
		       "    kdf_output: %p (size %d)\n"
		       "    shared_key: grp %d, info %d, type %d\n"
		       "    initiator_public_data_type: %d\n"
		       "    key_exchange_scheme: %d\n"
		       "    kdf_algorithm: %d\n"
		       "    flags: 0x%x\n"
		       "    signed_message: %p (size %d)\n",
		       __func__, __LINE__, hdl->key_management,
		       op_hsm_args.key_identifier,
		       op_hsm_args.shared_key_identifier_array,
		       op_hsm_args.shared_key_identifier_array_size,
		       op_hsm_args.ke_input, op_hsm_args.ke_input_size,
		       op_hsm_args.ke_output, op_hsm_args.ke_output_size,
		       op_hsm_args.kdf_input, op_hsm_args.kdf_input_size,
		       op_hsm_args.kdf_output, op_hsm_args.kdf_output_size,
		       op_hsm_args.shared_key_group,
		       op_hsm_args.shared_key_info, op_hsm_args.shared_key_type,
		       op_hsm_args.initiator_public_data_type,
		       op_hsm_args.key_exchange_scheme,
		       op_hsm_args.kdf_algorithm, op_hsm_args.flags,
		       op_hsm_args.signed_message, op_hsm_args.signed_msg_size);

	hsm_err = hsm_key_exchange(hdl->key_management, &op_hsm_args);

	SMW_DBG_PRINTF(DEBUG, "hsm_key_exchange returned %d\n", hsm_err);
	status = convert_hsm_err(hsm_err);
	if (status != SMW_STATUS_OK) {
		delete_db_shared_keys(new_key_ids, nb_shared_keys);
		goto end;
	}

	/* Convert output derived key in BASE64 format */
	if (hex_key_derived) {
		status = smw_utils_base64_encode(hex_key_derived,
						 hex_key_derived_len,
						 key_derived, &key_derived_len);
		if (status != SMW_STATUS_OK)
			goto end;

		smw_keymgr_set_public_length(&args->key_derived,
					     key_derived_len);
	} else {
		smw_keymgr_set_public_length(&args->key_derived,
					     hex_key_derived_len);
	}

	/* Extract Client and Server write IVs */
	if (smw_keymgr_tls12_is_encryption_aead(tls_args->encryption_id)) {
		memcpy(smw_keymgr_tls12_get_client_w_iv(tls_args), kdf_output,
		       TLS12_CLIENT_W_IV_SIZE);
		smw_keymgr_tls12_set_client_w_iv_length(tls_args,
							TLS12_CLIENT_W_IV_SIZE);

		memcpy(smw_keymgr_tls12_get_server_w_iv(tls_args),
		       &kdf_output[TLS12_CLIENT_W_IV_SIZE],
		       TLS12_SERVER_W_IV_SIZE);
		smw_keymgr_tls12_set_server_w_iv_length(tls_args,
							TLS12_SERVER_W_IV_SIZE);
	}

	/* Update the key database with the shared key ids */
	status = add_update_db_shared_keys(args, nb_shared_keys, new_key_ids,
					   shared_key_ids);
end:
	if (new_key_ids)
		SMW_UTILS_FREE(new_key_ids);

	if (hex_key_base)
		SMW_UTILS_FREE(hex_key_base);

	if (hex_key_derived)
		SMW_UTILS_FREE(hex_key_derived);

	SMW_DBG_PRINTF(DEBUG, "%s returned %d\n", __func__, status);
	return status;
}
