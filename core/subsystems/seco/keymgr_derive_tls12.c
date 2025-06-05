// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2025 NXP
 */
#include "smw_status.h"

#include "debug.h"
#include "subsystems.h"
#include "utils.h"
#include "base64.h"
#include "keymgr_db.h"
#include "operation_context.h"

#include "common.h"
#include "keymgr_derive_tls12.h"

/*
 * SECO TLS 1.2 hard coded value
 */
#define TLS12_CLIENT_W_IV_SIZE 4 /* Client write IVs */
#define TLS12_SERVER_W_IV_SIZE 4 /* Server write IVs */
#define TLS12_KDF_OUTPUT_SIZE  (TLS12_CLIENT_W_IV_SIZE + TLS12_SERVER_W_IV_SIZE)

#define TLS12_NB_KEYS_WITH_MAC 5 /* Number of keys when MAC keys present */
#define TLS12_NB_KEYS_NO_MAC   3 /* Number of keys when no MAC keys present */

#define TLS12_KDF_INPUT_SIZE		128
#define TLS12_KDF_EMS_SHA256_INPUT_SIZE 96
#define TLS12_KDF_EMS_SHA384_INPUT_SIZE 112

#define TLS12_KDF_DEF(_key_exchange_id, _encryption_id, _prf_id, _mac_key_id,  \
		      _mac_security_size, _enc_key_id, _enc_security_size,     \
		      _kdf, _nb_shared_key_id)                                 \
	{                                                                      \
		.key_exchange_id =                                             \
			SMW_TLS12_KEY_EXCHANGE_ID_##_key_exchange_id,          \
		.encryption_id = SMW_TLS12_ENCRYPTION_ID_##_encryption_id,     \
		.prf_id = SMW_CONFIG_HASH_ALGO_ID_##_prf_id,                   \
		.mac_key_id = SMW_CONFIG_KEY_TYPE_ID_##_mac_key_id,            \
		.mac_security_size = _mac_security_size,                       \
		.enc_key_id = SMW_CONFIG_KEY_TYPE_ID_##_enc_key_id,            \
		.enc_security_size = _enc_security_size,                       \
		.kdf = HSM_KDF_##_kdf,                                         \
		.flags = HSM_OP_KEY_EXCHANGE_FLAGS_GENERATE_EPHEMERAL |        \
			 HSM_KEY_INFO_TRANSIENT,                               \
		.nb_shared_key_id = TLS12_NB_KEYS_##_nb_shared_key_id,         \
	}

#define TLS12_KDF_DEF_WITH_MAC(_key_exchange_id, _encryption_id, _prf_id,      \
			       _mac_key_id, _mac_security_size, _enc_key_id,   \
			       _enc_security_size, _kdf)                       \
	TLS12_KDF_DEF(_key_exchange_id, _encryption_id, _prf_id, _mac_key_id,  \
		      _mac_security_size, _enc_key_id, _enc_security_size,     \
		      _kdf, WITH_MAC)

#define TLS12_KDF_DEF_NO_MAC(_key_exchange_id, _encryption_id, _prf_id,        \
			     _enc_key_id, _enc_security_size, _kdf)            \
	TLS12_KDF_DEF(_key_exchange_id, _encryption_id, _prf_id, INVALID, 0,   \
		      _enc_key_id, _enc_security_size, _kdf, NO_MAC)

/*
 * List of TLS 1.2 Cipher suite supported in SECO
 * tls12_kdf[]: list of Key derivation function
 * tls12_key_ids[]: list of Keys (initiator and exchange)
 */
static const struct tls12_kdf_info {
	enum smw_tls12_key_exchange_id key_exchange_id;
	enum smw_tls12_encryption_id encryption_id;
	enum smw_config_hash_algo_id prf_id;
	enum smw_config_key_type_id mac_key_id;
	unsigned int mac_security_size;
	enum smw_config_key_type_id enc_key_id;
	unsigned int enc_security_size;
	hsm_kdf_algo_id_t kdf;
	hsm_op_key_exchange_flags_t flags;
	unsigned char nb_shared_key_id;
} tls12_kdf[] = {
	/* TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 */
	TLS12_KDF_DEF_WITH_MAC(ECDHE_ECDSA, AES_128_CBC, SHA256, HMAC, 256, AES,
			       128, HMAC_SHA_256_TLS_32_16_4),
	/* TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 */
	TLS12_KDF_DEF_WITH_MAC(ECDHE_ECDSA, AES_256_CBC, SHA384, HMAC, 384, AES,
			       256, HMAC_SHA_384_TLS_48_32_4),
	/* TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 */
	TLS12_KDF_DEF_NO_MAC(ECDHE_ECDSA, AES_128_GCM, SHA256, AES, 128,
			     HMAC_SHA_256_TLS_0_16_4),
	/* TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 */
	TLS12_KDF_DEF_NO_MAC(ECDHE_ECDSA, AES_256_GCM, SHA384, AES, 256,
			     HMAC_SHA_384_TLS_0_32_4),
};

#define KEY_DEF(_key_type_id, _security_size, _key_initiator, _key_exchange)   \
	{                                                                      \
		.key_type_id = SMW_CONFIG_KEY_TYPE_ID_##_key_type_id,          \
		.security_size = _security_size,                               \
		.key_initiator = HSM_KEY_TYPE_##_key_initiator,                \
		.key_exchange = HSM_KE_SCHEME_##_key_exchange                  \
	}
static const struct key_def {
	enum smw_config_key_type_id key_type_id;
	unsigned int security_size;
	hsm_key_type_t key_initiator;
	hsm_key_exchange_scheme_id_t key_exchange;
} key_def_list[] = {
	KEY_DEF(SECP_R1, 256, ECDSA_NIST_P256, ECDH_NIST_P256),
	KEY_DEF(SECP_R1, 384, ECDSA_NIST_P384, ECDH_NIST_P384),
	KEY_DEF(BRAINPOOL_R1, 256, ECDSA_BRAINPOOL_R1_256,
		ECDH_BRAINPOOL_R1_256),
	KEY_DEF(BRAINPOOL_R1, 384, ECDSA_BRAINPOOL_R1_384,
		ECDH_BRAINPOOL_R1_384),
};

static const struct key_def *get_key_def(struct smw_keymgr_identifier *key)
{
	const struct key_def *key_def = key_def_list;
	const struct key_def *ret_key = NULL;
	unsigned int i = 0;

	for (; i < ARRAY_SIZE(key_def_list); i++, key_def++) {
		if (key_def->key_type_id == key->type_id &&
		    key_def->security_size == key->security_size) {
			ret_key = key_def;
			break;
		}
	}

	return ret_key;
}

static int get_tls_key_exchange_ids(struct smw_keymgr_identifier *key,
				    op_key_exchange_args_t *op_args)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
	const struct key_def *key_def = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	key_def = get_key_def(key);
	if (key_def) {
		op_args->initiator_public_data_type = key_def->key_initiator;
		op_args->key_exchange_scheme = key_def->key_exchange;
		status = SMW_STATUS_OK;
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static void
get_tls_key_exchange_ids_partial(struct seco_tls12_partial_data *partial,
				 op_key_exchange_args_t *op_args)
{
	op_args->initiator_public_data_type =
		partial->initiator_public_data_type;
	op_args->key_exchange_scheme = partial->key_exchange_scheme;
}

static unsigned short get_key_exchange_length(struct smw_keymgr_identifier *key)
{
	unsigned short length = 0;
	const struct key_def *key_def = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (BITS_TO_BYTES_SIZE(key->security_size) * 2 <= UINT16_MAX) {
		key_def = get_key_def(key);
		if (key_def)
			length = (BITS_TO_BYTES_SIZE(key->security_size) * 2) &
				 UINT16_MAX;
	}

	return length;
}

static int
check_reallocate_key_exchange_buffer(unsigned char **data,
				     unsigned short *length,
				     struct smw_keymgr_derived_key_desc *desc)
{
	int status = SMW_STATUS_INVALID_PARAM;

	unsigned char *shared_secret_data = NULL;
	unsigned int shared_secret_length = 0;
	unsigned char *tmp_key = NULL;
	unsigned short key_size = 0;
	unsigned int max_shared_secret_length = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	shared_secret_data = smw_keymgr_get_shared_secret_buffer(desc);

	/* SECO requires exact shared secret key size */
	key_size = get_key_exchange_length(&desc->identifier);
	if (!key_size) {
		if (shared_secret_data) {
			SMW_DBG_PRINTF(ERROR,
				       "Shared secret buffer is not set\n");
			status = SMW_STATUS_INVALID_PARAM;
		} else {
			status = SMW_STATUS_OK;
		}

		goto end;
	}

	shared_secret_length = smw_keymgr_get_shared_secret_len(desc);

	/* First check if the user set shared secret buffer size is big enough */
	max_shared_secret_length = key_size;
	if (desc->format_id == SMW_KEYMGR_FORMAT_ID_BASE64)
		max_shared_secret_length =
			smw_utils_get_base64_len(max_shared_secret_length);

	if (shared_secret_length < max_shared_secret_length) {
		smw_keymgr_set_shared_secret_len(desc,
						 max_shared_secret_length);
		status = SMW_STATUS_OUTPUT_TOO_SHORT;
	} else if (shared_secret_data) {
		if (desc->format_id == SMW_KEYMGR_FORMAT_ID_BASE64) {
			tmp_key = SMW_UTILS_MALLOC(max_shared_secret_length);
			if (!tmp_key) {
				SMW_DBG_PRINTF(ERROR, "Allocation failure\n");
				status = SMW_STATUS_ALLOC_FAILURE;
				goto end;
			}
		} else {
			tmp_key = shared_secret_data;
		}

		*length = key_size;
		*data = tmp_key;

		status = SMW_STATUS_OK;
	}

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static const struct tls12_kdf_info *
get_tls12_kdf_info(struct smw_keymgr_tls12_args *args)
{
	unsigned int i = 0;

	for (; i < ARRAY_SIZE(tls12_kdf); i++) {
		if (tls12_kdf[i].key_exchange_id == args->key_exchange_id &&
		    tls12_kdf[i].encryption_id == args->encryption_id &&
		    tls12_kdf[i].prf_id == args->prf_id)
			return &tls12_kdf[i];
	}

	return NULL;
}

static const struct tls12_kdf_info *
get_tls12_kdf_info_partial(struct smw_keymgr_tls12_args *args,
			   struct seco_tls12_partial_data *partial)
{
	unsigned int i = 0;

	for (; i < ARRAY_SIZE(tls12_kdf); i++) {
		if (tls12_kdf[i].encryption_id == args->encryption_id &&
		    tls12_kdf[i].key_exchange_id == partial->key_exchange_id &&
		    tls12_kdf[i].prf_id == partial->prf_id)
			return &tls12_kdf[i];
	}

	return NULL;
}

static void delete_db_shared_keys(unsigned int *ids_array, int nb_shared_keys)
{
	int idx = 0;
	struct smw_keymgr_identifier key_identifier = { 0 };
	struct smw_key_attributes *key_attributes =
		&key_identifier.key_attributes;

	key_identifier.s_id = INVALID_KEY_ID;
	key_identifier.subsystem_id = SUBSYSTEM_ID_SECO;
	/* Only transient key are generated */
	key_attributes->attributes =
		SMW_ATTR_SET_TRANSIENT(key_attributes->attributes);

	/* Delete all keys from the database */
	for (; idx < nb_shared_keys && ids_array[idx] != INVALID_KEY_ID;
	     idx++) {
		(void)smw_keymgr_db_delete(ids_array[idx], &key_identifier);
	}
}

static int add_update_db_shared_keys(struct smw_keymgr_derive_key_args *args,
				     int nb_shared_keys,
				     unsigned int *new_key_ids,
				     unsigned int *shared_key_ids,
				     unsigned int key_group,
				     struct seco_tls12_partial_data *partial)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
	int idx = 0;
	unsigned int *new_key_id = new_key_ids;
	unsigned int *shared_key_id = shared_key_ids;
	struct smw_keymgr_identifier key_identifier = { 0 };
	struct smw_key_attributes *key_attributes =
		&key_identifier.key_attributes;
	struct smw_keymgr_tls12_args *tls_args = NULL;
	const struct tls12_kdf_info *kdf_info = NULL;

	tls_args = args->kdf_args;
	kdf_info = partial ? get_tls12_kdf_info_partial(tls_args, partial) :
			     get_tls12_kdf_info(tls_args);
	if (!kdf_info)
		return status;

	/* Initialize the new_key_ids with invalid key ids */
	for (; !shared_key_id && idx < nb_shared_keys; idx++)
		new_key_ids[idx] = INVALID_KEY_ID;

	key_identifier.s_id = INVALID_KEY_ID;
	key_identifier.subsystem_id = SUBSYSTEM_ID_SECO;
	/* Only transient key are generated */
	key_attributes->attributes =
		SMW_ATTR_SET_TRANSIENT(key_attributes->attributes);
	if (SET_OVERFLOW(key_group, key_identifier.group))
		return SMW_STATUS_OPERATION_FAILURE;

	if (nb_shared_keys == TLS12_NB_KEYS_WITH_MAC) {
		/*
		 * Create the Client and Server MAC write keys
		 */
		key_identifier.type_id = kdf_info->mac_key_id;
		key_identifier.security_size = kdf_info->mac_security_size;

		status = smw_keymgr_get_privacy_id(key_identifier.type_id,
						   &key_identifier.privacy_id);
		if (status != SMW_STATUS_OK)
			goto end;

		if (!shared_key_id) {
			/* Create the Client MAC write Key */
			status = smw_keymgr_db_create(new_key_id,
						      &key_identifier);
		} else {
			/* Update the Client MAC write Key */
			key_identifier.s_id = *shared_key_id++;
			smw_keymgr_tls12_set_client_mac_key_id(tls_args,
							       *new_key_id);
			status = smw_keymgr_db_update(*new_key_id,
						      &key_identifier);
		}

		if (status != SMW_STATUS_OK) {
			SMW_DBG_PRINTF(ERROR,
				       "%s Key DB Client MAC key error\n",
				       (shared_key_id) ? "Update" : "Create");
			goto end;
		}
		new_key_id++;

		if (!shared_key_id) {
			/* Create the Server MAC write Key */
			status = smw_keymgr_db_create(new_key_id,
						      &key_identifier);
		} else {
			/* Update the Server MAC write Key */
			key_identifier.s_id = *shared_key_id++;
			smw_keymgr_tls12_set_server_mac_key_id(tls_args,
							       *new_key_id);
			status = smw_keymgr_db_update(*new_key_id,
						      &key_identifier);
		}
		new_key_id++;

		if (status != SMW_STATUS_OK) {
			SMW_DBG_PRINTF(ERROR,
				       "%s Key DB Server MAC key error\n",
				       (shared_key_id) ? "Update" : "Create");
			goto end;
		}
	}

	/*
	 * Create Client and Server encryption write keys
	 */
	key_identifier.type_id = kdf_info->enc_key_id;
	key_identifier.security_size = kdf_info->enc_security_size;
	status = smw_keymgr_get_privacy_id(key_identifier.type_id,
					   &key_identifier.privacy_id);
	if (status != SMW_STATUS_OK)
		goto end;

	if (!shared_key_id) {
		/* Create the Client Encryption write Key */
		status = smw_keymgr_db_create(new_key_id, &key_identifier);
	} else {
		/* Update the Client Encryption write Key */
		key_identifier.s_id = *shared_key_id++;
		smw_keymgr_tls12_set_client_enc_key_id(tls_args, *new_key_id);
		status = smw_keymgr_db_update(*new_key_id, &key_identifier);
	}
	new_key_id++;

	if (status != SMW_STATUS_OK) {
		SMW_DBG_PRINTF(ERROR, "%s Key DB Client Encryption key error\n",
			       (shared_key_id) ? "Update" : "Create");
		goto end;
	}

	if (!shared_key_id) {
		/* Create the Server Encryption write Key */
		status = smw_keymgr_db_create(new_key_id, &key_identifier);
	} else {
		/* Update the Server Encryption write Key */
		key_identifier.s_id = *shared_key_id++;
		smw_keymgr_tls12_set_server_enc_key_id(tls_args, *new_key_id);
		status = smw_keymgr_db_update(*new_key_id, &key_identifier);
	}
	new_key_id++;

	if (status != SMW_STATUS_OK) {
		SMW_DBG_PRINTF(ERROR, "%s Key DB Server Encryption key error\n",
			       (shared_key_id) ? "Update" : "Create");
		goto end;
	}

	/*
	 * Create the Master Key
	 */
	key_identifier.type_id = SMW_CONFIG_KEY_TYPE_ID_TLS_MASTER;
	key_identifier.security_size = TLS12_MASTER_SECRET_SEC_SIZE;
	status = smw_keymgr_get_privacy_id(key_identifier.type_id,
					   &key_identifier.privacy_id);
	if (status != SMW_STATUS_OK)
		goto end;

	if (!shared_key_id) {
		/* Create the Master Key */
		status = smw_keymgr_db_create(new_key_id, &key_identifier);
	} else {
		/* Update the Master Key */
		key_identifier.s_id = *shared_key_id;
		if (partial) {
			status = smw_keymgr_db_update(args->key_base.pub->id,
						      &key_identifier);
		} else {
			smw_keymgr_tls12_set_master_sec_key_id(tls_args,
							       *new_key_id);
			status = smw_keymgr_db_update(*new_key_id,
						      &key_identifier);
		}
	}

	if (status != SMW_STATUS_OK) {
		SMW_DBG_PRINTF(ERROR, "%s Key DB Master key error\n",
			       (shared_key_id) ? "Update" : "Create");
	}

end:
	if (status != SMW_STATUS_OK && !shared_key_id)
		delete_db_shared_keys(new_key_ids, nb_shared_keys);

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

static int check_kdf_input_length(op_key_exchange_args_t *op_args,
				  enum smw_config_hash_algo_id prf_id)
{
	if ((op_args->flags & HSM_OP_KEY_EXCHANGE_FLAGS_USE_TLS_EMS) ==
	    HSM_OP_KEY_EXCHANGE_FLAGS_USE_TLS_EMS) {
		switch (prf_id) {
		case SMW_CONFIG_HASH_ALGO_ID_SHA256:
			if (op_args->kdf_input_size !=
			    TLS12_KDF_EMS_SHA256_INPUT_SIZE)
				return SMW_STATUS_INVALID_PARAM;

			return SMW_STATUS_OK;

		case SMW_CONFIG_HASH_ALGO_ID_SHA384:
			if (op_args->kdf_input_size !=
			    TLS12_KDF_EMS_SHA384_INPUT_SIZE)
				return SMW_STATUS_INVALID_PARAM;

			return SMW_STATUS_OK;

		default:
			return SMW_STATUS_INVALID_PARAM;
		}
	}

	if (op_args->kdf_input_size != TLS12_KDF_INPUT_SIZE)
		return SMW_STATUS_INVALID_PARAM;

	return SMW_STATUS_OK;
}

int seco_derive_tls12(struct subsystem_context *seco_ctx,
		      struct smw_keymgr_derive_key_args *args)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
	int tmp_status = SMW_STATUS_OK;

	struct smw_keymgr_identifier *key_derived_id = NULL;
	struct smw_keymgr_tls12_args *tls_args = NULL;
	const struct tls12_kdf_info *kdf_info = NULL;

	unsigned char kdf_output[TLS12_KDF_OUTPUT_SIZE] = { 0 };
	unsigned char *key_base = NULL;
	unsigned char *hex_key_base = NULL;
	unsigned char *tmp_key_exchange = NULL;
	unsigned int *shared_key_ids = NULL;
	unsigned int *new_key_ids = NULL;
	unsigned int key_base_len = 0;
	unsigned int hex_key_base_len = 0;
	unsigned short key_size = 0;
	int nb_shared_keys = 0;
	unsigned int key_group = 0;

	hsm_err_t err = HSM_NO_ERROR;
	hsm_hdl_t key_mgt_hdl = 0;
	op_key_exchange_args_t op_args = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	key_derived_id = &args->key_derived.identifier;
	tls_args = args->kdf_args;

	kdf_info = get_tls12_kdf_info(args->kdf_args);
	if (!kdf_info)
		goto end;

	nb_shared_keys = kdf_info->nb_shared_key_id;

	status = get_tls_key_exchange_ids(key_derived_id, &op_args);
	if (status != SMW_STATUS_OK)
		goto end;

	status = check_reallocate_key_exchange_buffer(&tmp_key_exchange,
						      &key_size,
						      &args->key_derived);
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
	op_args.kdf_output_size = sizeof(kdf_output);
	op_args.kdf_output = kdf_output;

	op_args.ke_output = tmp_key_exchange;
	op_args.ke_output_size = key_size;

	op_args.kdf_algorithm = kdf_info->kdf;
	if (MUL_OVERFLOW(nb_shared_keys, sizeof(unsigned int),
			 &op_args.shared_key_identifier_array_size)) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	/*
	 * Shared key identifier array size depends if KDF is HMAC or not.
	 * Hence if cipher encryption is GCM, KDF is a SHA not HMAC.
	 *
	 * Allocate a double buffer to handle the OSAL Key IDs pre-added
	 * in the database and the TLS 1.2 shared keys
	 */
	new_key_ids =
		SMW_UTILS_MALLOC(nb_shared_keys * sizeof(*new_key_ids) +
				 op_args.shared_key_identifier_array_size);
	if (!new_key_ids) {
		SMW_DBG_PRINTF(ERROR, "Allocation failure\n");
		status = SMW_STATUS_ALLOC_FAILURE;
		goto end;
	}

	if (ADD_OVERFLOW((uintptr_t)new_key_ids,
			 nb_shared_keys * sizeof(*new_key_ids),
			 (uintptr_t *)&shared_key_ids)) {
		status = SMW_STATUS_OPERATION_FAILURE;
		goto end;
	}

	status = add_update_db_shared_keys(args, nb_shared_keys, new_key_ids,
					   NULL, key_group, NULL);
	if (status != SMW_STATUS_OK)
		goto end;

	op_args.flags = kdf_info->flags;

	/* Add extended Master secret key flag if requested */
	if (smw_keymgr_tls12_get_ext_master_key(tls_args))
		op_args.flags |= HSM_OP_KEY_EXCHANGE_FLAGS_USE_TLS_EMS;

	op_args.kdf_input_size =
		smw_keymgr_tls12_get_kdf_input_length(tls_args);

	status = check_kdf_input_length(&op_args, kdf_info->prf_id);
	if (status != SMW_STATUS_OK)
		goto end;

	op_args.kdf_input = smw_keymgr_tls12_get_kdf_input(tls_args);
	if (!op_args.kdf_input) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	op_args.shared_key_identifier_array = (uint8_t *)shared_key_ids;

	key_base = smw_keymgr_get_public_data(&args->key_base);
	key_base_len = smw_keymgr_get_public_length(&args->key_base);

	if (args->key_base.format_id == SMW_KEYMGR_FORMAT_ID_BASE64) {
		status = smw_utils_base64_decode(key_base, key_base_len,
						 &hex_key_base,
						 &hex_key_base_len);
		if (status != SMW_STATUS_OK)
			goto end;

		op_args.ke_input = hex_key_base;
		op_args.ke_input_size = hex_key_base_len;
	} else {
		op_args.ke_input = key_base;
		op_args.ke_input_size = key_base_len;
	}

	/* Only Transient keys generated */
	op_args.shared_key_info = HSM_KEY_INFO_TRANSIENT;

	status = seco_open_key_mgmt_service(&seco_ctx->hdl, &key_mgt_hdl);
	if (status != SMW_STATUS_OK)
		goto end;

	do {
		status = seco_get_key_group(seco_ctx, false, &key_group);
		if (status != SMW_STATUS_OK)
			goto end;

		if (SET_OVERFLOW(key_group, op_args.shared_key_group)) {
			status = SMW_STATUS_OPERATION_FAILURE;
			goto end;
		}

		SMW_DBG_PRINTF(VERBOSE,
			       "[%s (%d)] Call hsm_key_exchange()\n"
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
			       __func__, __LINE__, op_args.key_identifier,
			       op_args.shared_key_identifier_array,
			       op_args.shared_key_identifier_array_size,
			       op_args.ke_input, op_args.ke_input_size,
			       op_args.ke_output, op_args.ke_output_size,
			       op_args.kdf_input, op_args.kdf_input_size,
			       op_args.kdf_output, op_args.kdf_output_size,
			       op_args.shared_key_group,
			       op_args.shared_key_info, op_args.shared_key_type,
			       op_args.initiator_public_data_type,
			       op_args.key_exchange_scheme,
			       op_args.kdf_algorithm, op_args.flags,
			       op_args.signed_message, op_args.signed_msg_size);

		err = hsm_key_exchange(key_mgt_hdl, &op_args);

		SMW_DBG_PRINTF(DEBUG, "hsm_key_exchange returned %d\n", err);
		/*
		 * There is no specific SECO error code indicating that the
		 * NVM Storage is full, hence let's assume that the NVM_KEY_STORE_ERROR
		 * will be returned only in case of key group full.
		 */
		if (err == HSM_KEY_STORE_ERROR) {
			status = seco_set_key_group_state(seco_ctx, key_group,
							  false, true);
			if (status != SMW_STATUS_OK)
				goto end;

			if (INC_OVERFLOW(key_group, 1)) {
				status = SMW_STATUS_OPERATION_FAILURE;
				goto end;
			}
		}
	} while (err == HSM_KEY_STORE_ERROR);

	status = seco_convert_err(err);
	if (status != SMW_STATUS_OK) {
		delete_db_shared_keys(new_key_ids, nb_shared_keys);
		goto end;
	}

	/* Update the ephemeral key exchange public buffer */
	status = smw_keymgr_update_shared_secret(&args->key_derived,
						 tmp_key_exchange, key_size);
	if (status != SMW_STATUS_OK)
		goto end;

	/* Extract Client and Server write IVs */
	if (smw_keymgr_tls12_is_encryption_aead(tls_args->encryption_id)) {
		SMW_UTILS_MEMCPY(smw_keymgr_tls12_get_client_w_iv(tls_args),
				 kdf_output, TLS12_CLIENT_W_IV_SIZE);
		smw_keymgr_tls12_set_client_w_iv_length(tls_args,
							TLS12_CLIENT_W_IV_SIZE);

		SMW_UTILS_MEMCPY(smw_keymgr_tls12_get_server_w_iv(tls_args),
				 &kdf_output[TLS12_CLIENT_W_IV_SIZE],
				 TLS12_SERVER_W_IV_SIZE);
		smw_keymgr_tls12_set_server_w_iv_length(tls_args,
							TLS12_SERVER_W_IV_SIZE);
	}

	/* Update the key database with the shared key ids */
	status = add_update_db_shared_keys(args, nb_shared_keys, new_key_ids,
					   shared_key_ids, key_group, NULL);
	if (status != SMW_STATUS_OK)
		goto end;

	if (args->key_attributes && (args->key_attributes->permitted_algo ||
				     args->key_attributes->usage_flags)) {
		args->key_attributes->permitted_algo = 0;
		args->key_attributes->usage_flags = 0;
		status = SMW_STATUS_KEY_POLICY_WARNING_IGNORED;
	}

end:
	if (new_key_ids)
		SMW_UTILS_FREE(new_key_ids);

	if (tmp_key_exchange &&
	    tmp_key_exchange !=
		    smw_keymgr_get_shared_secret_buffer(&args->key_derived))
		SMW_UTILS_FREE(tmp_key_exchange);

	if (hex_key_base)
		SMW_UTILS_FREE(hex_key_base);

	tmp_status = seco_close_key_mgt_service(key_mgt_hdl);
	if (status == SMW_STATUS_OK)
		status = tmp_status;

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static unsigned char *seco_memdup(const unsigned char *in, unsigned int len)
{
	unsigned char *out = NULL;

	if (!in || !len)
		return NULL;

	out = SMW_UTILS_MALLOC(len);
	if (!out)
		return NULL;

	SMW_UTILS_MEMCPY(out, in, len);

	return out;
}

static int tls12_op_copy_partial_data(struct smw_keymgr_derive_key_args *args)
{
	int status = SMW_STATUS_INVALID_PARAM;
	struct smw_keymgr_tls12_args *tls_args = args->kdf_args;
	struct smw_op_context *ctx = NULL;
	struct seco_tls12_partial_data *partial_data = NULL;
	const struct key_def *key_def = NULL;
	unsigned int hex_public_key_len = 0;
	unsigned char *hex_public_key = NULL;
	unsigned int public_key_len =
		smw_keymgr_get_public_length(&args->key_base);
	unsigned char *public_key = smw_keymgr_get_public_data(&args->key_base);

	SMW_DBG_TRACE_FUNCTION_CALL;

	ctx = smw_keymgr_tls12_get_context(tls_args);
	if (!ctx)
		return status;

	partial_data = SMW_UTILS_CALLOC(1, sizeof(*partial_data));
	if (!partial_data) {
		status = SMW_STATUS_ALLOC_FAILURE;
		goto end;
	}

	key_def = get_key_def(&args->key_base.identifier);
	if (!key_def) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	partial_data->initiator_public_data_type = key_def->key_initiator;
	partial_data->key_exchange_scheme = key_def->key_exchange;

	partial_data->key_exchange_id = tls_args->key_exchange_id;
	partial_data->prf_id = tls_args->prf_id;
	partial_data->ext_master_key =
		smw_keymgr_tls12_get_ext_master_key(tls_args);

	partial_data->peer_public_buffer_length =
		smw_keymgr_get_peer_pub_buffer_len(args);
	partial_data->peer_public_buffer =
		seco_memdup(smw_keymgr_get_peer_pub_buffer(args),
			    partial_data->peer_public_buffer_length);
	if (!partial_data->peer_public_buffer)
		goto end;

	status = smw_keymgr_set_hex_key_buffer(args->key_base.format_id,
					       public_key, public_key_len,
					       &hex_public_key,
					       &hex_public_key_len);
	if (status != SMW_STATUS_OK)
		goto end;

	partial_data->self_public_buffer_length = hex_public_key_len;
	partial_data->self_public_buffer =
		seco_memdup(hex_public_key,
			    partial_data->self_public_buffer_length);
	if (!partial_data->self_public_buffer)
		goto end;

	if (partial_data->ext_master_key) {
		partial_data->session_hash_length =
			smw_keymgr_tls12_get_session_hash_length(tls_args);
		partial_data->session_hash =
			seco_memdup(smw_keymgr_tls12_get_session_hash(tls_args),
				    partial_data->session_hash_length);
		if (!partial_data->session_hash)
			goto end;
	}

	ctx->op_id = SMW_CRYPTO_OP_ID_TLS12;
	ctx->op_state = CTX_OP_STATE_INIT;
	ctx->subsystem_context = partial_data;

	args->key_derived.identifier.type_id =
		SMW_CONFIG_KEY_TYPE_ID_TLS_MASTER;
	args->key_derived.identifier.s_id = (uint32_t)-1;
	args->key_derived.identifier.privacy_id = SMW_KEYMGR_PRIVACY_ID_PRIVATE;
	args->key_derived.identifier.security_size =
		TLS12_MASTER_SECRET_SEC_SIZE;

	status = SMW_STATUS_OK;

end:
	if (status != SMW_STATUS_OK && partial_data) {
		if (partial_data->session_hash)
			SMW_UTILS_FREE(partial_data->session_hash);

		if (partial_data->self_public_buffer)
			SMW_UTILS_FREE(partial_data->self_public_buffer);

		if (partial_data->peer_public_buffer)
			SMW_UTILS_FREE(partial_data->peer_public_buffer);

		SMW_UTILS_FREE(partial_data);
	}

	if (args->key_base.format_id == SMW_KEYMGR_FORMAT_ID_BASE64 &&
	    hex_public_key)
		SMW_UTILS_FREE(hex_public_key);

	return status;
}

static int tls12_op_derive(struct subsystem_context *seco_ctx,
			   struct smw_keymgr_derive_key_args *args)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
	int tmp_status = SMW_STATUS_OK;

	struct smw_keymgr_tls12_args *tls_args = args->kdf_args;
	const struct tls12_kdf_info *kdf_info = NULL;
	struct smw_op_context *ctx = NULL;

	unsigned char kdf_output[TLS12_KDF_OUTPUT_SIZE] = { 0 };
	unsigned int *shared_key_ids = NULL;
	unsigned int *new_key_ids = NULL;
	int nb_shared_keys = 0;
	unsigned int key_group = 0;
	struct seco_tls12_partial_data *partial_data = NULL;
	unsigned char *p = NULL;

	unsigned char *client_random =
		smw_keymgr_tls12_get_client_random(tls_args);
	unsigned int client_random_length =
		smw_keymgr_tls12_get_client_random_length(tls_args);
	unsigned char *server_random =
		smw_keymgr_tls12_get_server_random(tls_args);
	unsigned int server_random_length =
		smw_keymgr_tls12_get_server_random_length(tls_args);

	hsm_err_t err = HSM_NO_ERROR;
	hsm_hdl_t key_mgt_hdl = 0;
	op_key_exchange_args_t op_args = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	ctx = smw_keymgr_tls12_get_context(tls_args);
	if (!ctx)
		return status;

	partial_data = (struct seco_tls12_partial_data *)ctx->subsystem_context;

	kdf_info = get_tls12_kdf_info_partial(args->kdf_args, partial_data);
	if (!kdf_info)
		goto end;

	nb_shared_keys = kdf_info->nb_shared_key_id;
	if (sizeof(unsigned int) * nb_shared_keys > UINT8_MAX) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	get_tls_key_exchange_ids_partial(partial_data, &op_args);

	if (smw_keymgr_tls12_is_encryption_aead(tls_args->encryption_id)) {
		status = check_ivs_length(tls_args);
		if (status != SMW_STATUS_OK)
			goto end;
	}

	/*
	 * Client and Server write IVs
	 * KDF output can't be NULL even if IV's are not expected
	 */
	op_args.kdf_output_size = sizeof(kdf_output);
	op_args.kdf_output = kdf_output;

	op_args.ke_output = partial_data->peer_public_buffer;
	if (SET_OVERFLOW(partial_data->peer_public_buffer_length,
			 op_args.ke_output_size)) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	op_args.kdf_algorithm = kdf_info->kdf;
	if (SET_OVERFLOW(sizeof(unsigned int) * nb_shared_keys,
			 op_args.shared_key_identifier_array_size)) {
		status = SMW_STATUS_TOO_LARGE_NUMBER;
		goto end;
	}

	/*
	 * Shared key identifier array size depends if KDF is HMAC or not.
	 * Hence if cipher encryption is GCM, KDF is a SHA not HMAC.
	 *
	 * Allocate a double buffer to handle the OSAL Key IDs pre-added
	 * in the database and the TLS 1.2 shared keys
	 */
	new_key_ids =
		SMW_UTILS_MALLOC(nb_shared_keys * sizeof(*new_key_ids) +
				 op_args.shared_key_identifier_array_size);
	if (!new_key_ids) {
		SMW_DBG_PRINTF(ERROR, "Allocation failure\n");
		status = SMW_STATUS_ALLOC_FAILURE;
		goto end;
	}

	if (ADD_OVERFLOW((uintptr_t)new_key_ids,
			 nb_shared_keys * sizeof(*new_key_ids),
			 (uintptr_t *)&shared_key_ids)) {
		status = SMW_STATUS_OPERATION_FAILURE;
		goto end;
	}

	status = add_update_db_shared_keys(args, nb_shared_keys, new_key_ids,
					   NULL, key_group, partial_data);
	if (status != SMW_STATUS_OK)
		goto end;

	op_args.flags = kdf_info->flags;

	/* Add extended Master secret key flag if requested */
	if (partial_data->ext_master_key)
		op_args.flags |= HSM_OP_KEY_EXCHANGE_FLAGS_USE_TLS_EMS;

	if (partial_data->ext_master_key) {
		op_args.kdf_input_size = partial_data->session_hash_length;
	} else {
		if (ADD_OVERFLOW(client_random_length, server_random_length,
				 &op_args.kdf_input_size)) {
			status = SMW_STATUS_TOO_LARGE_NUMBER;
			goto end;
		}
	}

	if (ADD_OVERFLOW(op_args.kdf_input_size, server_random_length,
			 &op_args.kdf_input_size)) {
		status = SMW_STATUS_TOO_LARGE_NUMBER;
		goto end;
	}

	if (ADD_OVERFLOW(op_args.kdf_input_size, client_random_length,
			 &op_args.kdf_input_size)) {
		status = SMW_STATUS_TOO_LARGE_NUMBER;
		goto end;
	}

	op_args.kdf_input = SMW_UTILS_CALLOC(1, op_args.kdf_input_size);
	if (!op_args.kdf_input) {
		status = SMW_STATUS_SUBSYSTEM_OUT_OF_MEMORY;
		goto end;
	}

	p = op_args.kdf_input;

	if (partial_data->ext_master_key) {
		SMW_UTILS_MEMCPY(p, partial_data->session_hash,
				 partial_data->session_hash_length);
		p += partial_data->session_hash_length;
	} else {
		SMW_UTILS_MEMCPY(p, client_random, client_random_length);
		p += client_random_length;

		SMW_UTILS_MEMCPY(p, server_random, server_random_length);
		p += server_random_length;
	}

	SMW_UTILS_MEMCPY(p, server_random, server_random_length);
	p += server_random_length;

	SMW_UTILS_MEMCPY(p, client_random, client_random_length);

	op_args.shared_key_identifier_array = (uint8_t *)shared_key_ids;

	op_args.ke_input = partial_data->self_public_buffer;
	op_args.ke_input_size = partial_data->self_public_buffer_length;

	/* Only Transient keys generated */
	op_args.shared_key_info = HSM_KEY_INFO_TRANSIENT;

	status = seco_open_key_mgmt_service(&seco_ctx->hdl, &key_mgt_hdl);
	if (status != SMW_STATUS_OK)
		goto end;

	do {
		status = seco_get_key_group(seco_ctx, false, &key_group);
		if (status != SMW_STATUS_OK)
			goto end;

		if (SET_OVERFLOW(key_group, op_args.shared_key_group)) {
			status = SMW_STATUS_OPERATION_FAILURE;
			goto end;
		}

		SMW_DBG_PRINTF(VERBOSE,
			       "[%s (%d)] Call hsm_key_exchange()\n"
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
			       __func__, __LINE__, op_args.key_identifier,
			       op_args.shared_key_identifier_array,
			       op_args.shared_key_identifier_array_size,
			       op_args.ke_input, op_args.ke_input_size,
			       op_args.ke_output, op_args.ke_output_size,
			       op_args.kdf_input, op_args.kdf_input_size,
			       op_args.kdf_output, op_args.kdf_output_size,
			       op_args.shared_key_group,
			       op_args.shared_key_info, op_args.shared_key_type,
			       op_args.initiator_public_data_type,
			       op_args.key_exchange_scheme,
			       op_args.kdf_algorithm, op_args.flags,
			       op_args.signed_message, op_args.signed_msg_size);

		err = hsm_key_exchange(key_mgt_hdl, &op_args);

		SMW_DBG_PRINTF(DEBUG, "hsm_key_exchange returned %d\n", err);
		/*
		 * There is no specific SECO error code indicating that the
		 * NVM Storage is full, hence let's assume that the NVM_KEY_STORE_ERROR
		 * will be returned only in case of key group full.
		 */
		if (err == HSM_KEY_STORE_ERROR) {
			status = seco_set_key_group_state(seco_ctx, key_group,
							  false, true);
			if (status != SMW_STATUS_OK)
				goto end;

			if (INC_OVERFLOW(key_group, 1)) {
				status = SMW_STATUS_OPERATION_FAILURE;
				goto end;
			}
		}
	} while (err == HSM_KEY_STORE_ERROR);

	status = seco_convert_err(err);
	if (status != SMW_STATUS_OK) {
		delete_db_shared_keys(new_key_ids, nb_shared_keys);
		goto end;
	}

	/* Extract Client and Server write IVs */
	if (smw_keymgr_tls12_is_encryption_aead(tls_args->encryption_id)) {
		SMW_UTILS_MEMCPY(smw_keymgr_tls12_get_client_w_iv(tls_args),
				 kdf_output, TLS12_CLIENT_W_IV_SIZE);
		smw_keymgr_tls12_set_client_w_iv_length(tls_args,
							TLS12_CLIENT_W_IV_SIZE);

		SMW_UTILS_MEMCPY(smw_keymgr_tls12_get_server_w_iv(tls_args),
				 &kdf_output[TLS12_CLIENT_W_IV_SIZE],
				 TLS12_SERVER_W_IV_SIZE);
		smw_keymgr_tls12_set_server_w_iv_length(tls_args,
							TLS12_SERVER_W_IV_SIZE);
	}

	/* Update the key database with the shared key ids */
	status = add_update_db_shared_keys(args, nb_shared_keys, new_key_ids,
					   shared_key_ids, key_group,
					   partial_data);
	if (status != SMW_STATUS_OK)
		goto end;

	if (args->key_attributes && (args->key_attributes->permitted_algo ||
				     args->key_attributes->usage_flags)) {
		args->key_attributes->permitted_algo = 0;
		args->key_attributes->usage_flags = 0;
		status = SMW_STATUS_KEY_POLICY_WARNING_IGNORED;
	}

end:
	if (new_key_ids)
		SMW_UTILS_FREE(new_key_ids);

	if (op_args.kdf_input)
		SMW_UTILS_FREE(op_args.kdf_input);

	tmp_status = seco_close_key_mgt_service(key_mgt_hdl);
	if (status == SMW_STATUS_OK)
		status = tmp_status;

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int seco_derive_tls12_op(struct subsystem_context *seco_ctx,
			 struct smw_keymgr_derive_key_args *args)
{
	int status = SMW_STATUS_INVALID_PARAM;
	struct smw_keymgr_tls12_args *tls12_args = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!args || !args->kdf_args)
		goto end;

	tls12_args = args->kdf_args;

	switch (tls12_args->op_id) {
	case SMW_TLS12_OPERATION_ID_MASTER_SECRET:
		status = tls12_op_copy_partial_data(args);
		break;

	case SMW_TLS12_OPERATION_ID_KEY_EXPANSION:
		status = tls12_op_derive(seco_ctx, args);
		break;

	default:
		status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
		break;
	}

end:
	return status;
}
