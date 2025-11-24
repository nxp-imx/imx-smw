// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include "smw_osal.h"
#include "smw_status.h"

#include "builtin_macros.h"
#include "debug.h"
#include "utils.h"
#include "subsystems.h"
#include "keymgr_derive_tls12.h"
#include "keymgr_db.h"

#include "common.h"
#include "key_group.h"

#define TLS12_ALGO(_hashid, _op_id)                                            \
	{                                                                      \
		.hash_id = SMW_CONFIG_HASH_ALGO_ID_##_hashid, .op_id = _op_id, \
		.tls_algo = HSM_KEY_DERIVATION_TLS1_2_##_op_id##_##_hashid,    \
	}

#define TLS12_CIPHERSUITE(_encryptionid, _algoid, _bits, _mac_size, _iv_size)  \
	{                                                                      \
		.encryption_id = SMW_TLS12_ENCRYPTION_ID_##_encryptionid,      \
		.permitted_algo = PERMITTED_ALGO_##_algoid, .bits = _bits,     \
		.mac_size = _mac_size, .iv_size = _iv_size                     \
	}

enum tls12_ele_operation { MASTER_SECRET, KEY_BLOCK, IV };

static const struct tls12_algorithm {
	enum smw_config_hash_algo_id hash_id;
	enum tls12_ele_operation op_id;
	const hsm_op_key_derivation_tls1_2_algo_t tls_algo;
} tls12_algorithms[] = { TLS12_ALGO(SHA256, MASTER_SECRET),
			 TLS12_ALGO(SHA384, MASTER_SECRET),
			 TLS12_ALGO(SHA256, KEY_BLOCK),
			 TLS12_ALGO(SHA384, KEY_BLOCK),
			 TLS12_ALGO(SHA256, IV),
			 TLS12_ALGO(SHA384, IV) };

static const struct tls12_ciphersuite {
	enum smw_tls12_encryption_id encryption_id;
	hsm_permitted_algo_t permitted_algo;
	uint16_t bits;
	unsigned int mac_size;
	unsigned int iv_size;
} tls12_ciphersuites[] = {
	TLS12_CIPHERSUITE(AES_128_CBC, CBC_NO_PADDING, 128, 32, 16),
	TLS12_CIPHERSUITE(AES_256_CBC, CBC_NO_PADDING, 256, 64, 16),
	TLS12_CIPHERSUITE(AES_128_CCM, CCM, 128, 0, 12),
	TLS12_CIPHERSUITE(AES_256_CCM, CCM, 256, 0, 12),
	TLS12_CIPHERSUITE(AES_128_GCM, GCM, 128, 0, 4),
	TLS12_CIPHERSUITE(AES_256_GCM, GCM, 256, 0, 4),
	TLS12_CIPHERSUITE(CHACHA20_POLY1305, CHACHA20_POLY1305, 256, 0, 12),
};

static int get_tls12_algo(struct smw_keymgr_tls12_args *tls12_args,
			  enum tls12_ele_operation op_id,
			  hsm_op_key_derivation_tls1_2_algo_t *tls12_algo)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
	size_t i = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (; i < ARRAY_SIZE(tls12_algorithms); i++) {
		if (tls12_algorithms[i].op_id == op_id &&
		    tls12_algorithms[i].hash_id == tls12_args->prf_id) {
			*tls12_algo = tls12_algorithms[i].tls_algo;

			status = SMW_STATUS_OK;
			break;
		}
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int get_tls12_ciphersuite(struct smw_keymgr_tls12_args *tls_args,
				 struct tls12_ciphersuite *cipher)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
	size_t i = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (; i < ARRAY_SIZE(tls12_ciphersuites); i++) {
		if (tls12_ciphersuites[i].encryption_id ==
		    tls_args->encryption_id) {
			*cipher = tls12_ciphersuites[i];

			status = SMW_STATUS_OK;
			break;
		}
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int build_user_info(unsigned char **output, unsigned int *output_length,
			   unsigned char *in1, unsigned int len1,
			   unsigned char *in2, unsigned int len2,
			   unsigned char *in3, unsigned int len3)
{
	unsigned char *p = NULL;

	*output_length = len1;
	if (ADD_OVERFLOW(*output_length, len2, output_length))
		return SMW_STATUS_TOO_LARGE_NUMBER;
	if (ADD_OVERFLOW(*output_length, len3, output_length))
		return SMW_STATUS_TOO_LARGE_NUMBER;

	*output = SMW_UTILS_CALLOC(1, *output_length);
	if (!*output)
		return SMW_STATUS_ALLOC_FAILURE;

	p = *output;
	if (in1 && len1) {
		SMW_UTILS_MEMCPY(p, in1, len1);
		p += len1;
	}

	if (in2 && len2) {
		SMW_UTILS_MEMCPY(p, in2, len2);
		p += len2;
	}

	if (in3 && len3)
		SMW_UTILS_MEMCPY(p, in3, len3);

	return SMW_STATUS_OK;
}

static int tls12_store_key_id(struct smw_keymgr_derive_key_args *args,
			      enum smw_config_key_type_id type_id,
			      unsigned int bits, uint32_t *key_id)
{
	struct smw_keymgr_identifier key_identifier = { 0 };
	struct smw_key_attributes *key_attributes =
		&key_identifier.key_attributes;

	if (!args->store_key)
		return SMW_STATUS_OK;

	key_identifier.type_id = type_id;
	key_identifier.s_id = *key_id;
	/*
	 * In case of key derivation, the key group is unknown.
	 * The FW selects the key group.
	 */
	key_identifier.group = ELE_UNDEFINED_KEY_GROUP;
	key_identifier.subsystem_id = SUBSYSTEM_ID_ELE;
	key_identifier.security_size = bits;
	key_attributes->attributes =
		SMW_ATTR_SET_TRANSIENT(key_attributes->attributes);
	key_attributes->attributes =
		SMW_ATTR_SET_SENSITIVE(key_attributes->attributes);
	key_identifier.privacy_id = SMW_KEYMGR_PRIVACY_ID_PRIVATE;

	return smw_keymgr_db_create(key_id, &key_identifier);
}

static int tls12_extract_key_ids(struct smw_keymgr_derive_key_args *args,
				 op_key_exchange_args_t *key_ex_args)
{
	enum smw_status_code status = SMW_STATUS_SUBSYSTEM_FAILURE;
	struct smw_keymgr_tls12_args *tls12_args = args->kdf_args;
	struct tls12_ciphersuite cipher = { 0 };
	uint32_t *key_ids = (uint32_t *)key_ex_args->output;
	uint32_t client_enc_key_id = 0;
	uint32_t server_enc_key_id = 0;
	uint32_t client_mac_key_id = 0;
	uint32_t server_mac_key_id = 0;

	if (!key_ids)
		goto end;

	status = get_tls12_ciphersuite(tls12_args, &cipher);
	if (status != SMW_STATUS_OK)
		goto end;

	if (cipher.mac_size) {
		client_mac_key_id = SMW_UTILS_BSWAP_32(key_ids[0]);
		server_mac_key_id = SMW_UTILS_BSWAP_32(key_ids[1]);
		client_enc_key_id = SMW_UTILS_BSWAP_32(key_ids[2]);
		server_enc_key_id = SMW_UTILS_BSWAP_32(key_ids[3]);
	} else {
		client_enc_key_id = SMW_UTILS_BSWAP_32(key_ids[0]);
		server_enc_key_id = SMW_UTILS_BSWAP_32(key_ids[1]);
	}

	status = tls12_store_key_id(args, SMW_CONFIG_KEY_TYPE_ID_AES,
				    cipher.bits, &client_enc_key_id);
	if (status != SMW_STATUS_OK)
		goto end;

	smw_keymgr_tls12_set_client_enc_key_id(tls12_args, client_enc_key_id);

	status = tls12_store_key_id(args, SMW_CONFIG_KEY_TYPE_ID_AES,
				    cipher.bits, &server_enc_key_id);
	if (status != SMW_STATUS_OK)
		goto end;

	smw_keymgr_tls12_set_server_enc_key_id(tls12_args, server_enc_key_id);

	if (!smw_keymgr_tls12_is_encryption_aead(tls12_args->encryption_id)) {
		status =
			tls12_store_key_id(args, SMW_CONFIG_KEY_TYPE_ID_HMAC,
					   cipher.mac_size, &client_mac_key_id);
		if (status != SMW_STATUS_OK)
			goto end;

		smw_keymgr_tls12_set_client_mac_key_id(tls12_args,
						       client_mac_key_id);

		status =
			tls12_store_key_id(args, SMW_CONFIG_KEY_TYPE_ID_HMAC,
					   cipher.mac_size, &server_mac_key_id);
		if (status != SMW_STATUS_OK)
			goto end;

		smw_keymgr_tls12_set_server_mac_key_id(tls12_args,
						       server_mac_key_id);
	}

end:
	return status;
}

static int tls12_extract_ivs(struct smw_keymgr_tls12_args *tls12_args,
			     op_key_exchange_args_t *key_ex_args,
			     struct tls12_ciphersuite *cipher)
{
	if (cipher->iv_size == 0)
		return SMW_STATUS_OK;

	if (smw_keymgr_tls12_get_client_w_iv_length(tls12_args) <
		    cipher->iv_size ||
	    smw_keymgr_tls12_get_server_w_iv_length(tls12_args) <
		    cipher->iv_size) {
		return SMW_STATUS_INVALID_IV_SIZE;
	}

	if (!key_ex_args->output)
		return SMW_STATUS_SUBSYSTEM_FAILURE;

	smw_keymgr_tls12_set_client_w_iv_length(tls12_args, cipher->iv_size);
	smw_keymgr_tls12_set_server_w_iv_length(tls12_args, cipher->iv_size);

	SMW_UTILS_MEMCPY(smw_keymgr_tls12_get_client_w_iv(tls12_args),
			 key_ex_args->output, cipher->iv_size);
	SMW_UTILS_MEMCPY(smw_keymgr_tls12_get_server_w_iv(tls12_args),
			 key_ex_args->output + cipher->iv_size,
			 cipher->iv_size);

	return SMW_STATUS_OK;
}

static int tls12_extract_result(struct smw_keymgr_derive_key_args *args,
				enum tls12_ele_operation op,
				op_key_exchange_args_t *key_ex_args)
{
	struct smw_keymgr_tls12_args *tls12_args = args->kdf_args;
	enum smw_status_code status = SMW_STATUS_OK;

	struct tls12_ciphersuite cipher = { 0 };

	switch (op) {
	case MASTER_SECRET:
		/* Nothing to do */
		break;

	case KEY_BLOCK:
		status = tls12_extract_key_ids(args, key_ex_args);
		break;

	case IV:
		status = get_tls12_ciphersuite(tls12_args, &cipher);
		if (status != SMW_STATUS_OK)
			return status;

		status = tls12_extract_ivs(tls12_args, key_ex_args, &cipher);
		break;

	default:
		status = SMW_STATUS_INVALID_PARAM;
		break;
	}

	return status;
}

static int tls12_set_derive_args(struct smw_keymgr_derive_key_args *args,
				 enum tls12_ele_operation op, void *payload,
				 unsigned int payload_len,
				 op_key_exchange_args_t *key_ex_args)
{
	int status = SMW_STATUS_OK;
	key_ex_args->flags = HSM_OP_KEY_EXCHANGE_FLAGS_INPUT_PLAINTEXT_CONTENT;

	key_ex_args->in_content_sz = payload_len;
	key_ex_args->in_content = (uint8_t *)payload;

	switch (op) {
	case MASTER_SECRET:
		key_ex_args->in_pub_buffer_sz =
			smw_keymgr_get_peer_pub_buffer_len(args);
		key_ex_args->in_pub_buffer =
			smw_keymgr_get_peer_pub_buffer(args);
		break;

	case KEY_BLOCK:
		/* ELE returns maximum of 4 key IDs */
		key_ex_args->output_sz = 4 * sizeof(uint32_t);
		key_ex_args->output =
			SMW_UTILS_CALLOC(1, key_ex_args->output_sz);
		if (!key_ex_args->output)
			status = SMW_STATUS_ALLOC_FAILURE;

		break;

	case IV:
		/* ELE returns maximum 2 IVs, at most 16 bytes each => 32 bytes */
		key_ex_args->output_sz = 32;
		key_ex_args->output =
			SMW_UTILS_CALLOC(1, key_ex_args->output_sz);
		if (!key_ex_args->output)
			status = SMW_STATUS_ALLOC_FAILURE;

		break;

	default:
		status = SMW_STATUS_OPERATION_FAILURE;
		break;
	}

	return status;
}

static int
tls12_op_derive_master_secret(struct smw_keymgr_derive_key_args *args,
			      hsm_hdl_t *key_mgt_hdl)
{
	int status = SMW_STATUS_ALLOC_FAILURE;
	struct tls12_ms_ele_op_payload *payload = NULL;
	op_key_exchange_args_t key_ex_args = { 0 };
	struct smw_keymgr_tls12_args *tls_args = args->kdf_args;
	struct smw_keymgr_identifier *key_derived_identifier =
		&args->key_derived.identifier;
	struct smw_key_attributes *key_derived_attributes =
		&key_derived_identifier->key_attributes;
	hsm_err_t err = HSM_NO_ERROR;

	unsigned char *session_hash = NULL;
	unsigned int session_hash_len = 0;
	unsigned char *client_random = NULL;
	unsigned int client_random_len = 0;
	unsigned char *server_random = NULL;
	unsigned int server_random_len = 0;
	unsigned char *salt = NULL;
	unsigned int salt_len = 0;

	payload = SMW_UTILS_CALLOC(1, sizeof(*payload));
	if (!payload)
		goto end;

	payload->ver = 1;
	payload->key_id = args->key_base.identifier.s_id;

	status = ele_get_key_store_id(&payload->keystore_id);
	if (status != SMW_STATUS_OK)
		goto end;

	status = get_tls12_algo(tls_args, MASTER_SECRET, &payload->tls1_2_algo);
	if (status != SMW_STATUS_OK)
		goto end;

	salt = smw_keymgr_get_salt(args);
	salt_len = smw_keymgr_get_salt_len(args);
	if (!salt || !salt_len) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	if (smw_keymgr_tls12_get_ext_master_key(tls_args)) {
		session_hash = smw_keymgr_tls12_get_session_hash(tls_args);
		session_hash_len =
			smw_keymgr_tls12_get_session_hash_length(tls_args);

		status = build_user_info(&key_ex_args.user_fixed_info,
					 &key_ex_args.user_fixed_info_sz, salt,
					 salt_len, session_hash,
					 session_hash_len, NULL, 0);
	} else {
		client_random = smw_keymgr_tls12_get_client_random(tls_args);
		client_random_len =
			smw_keymgr_tls12_get_client_random_length(tls_args);
		server_random = smw_keymgr_tls12_get_server_random(tls_args);
		server_random_len =
			smw_keymgr_tls12_get_server_random_length(tls_args);

		status = build_user_info(&key_ex_args.user_fixed_info,
					 &key_ex_args.user_fixed_info_sz, salt,
					 salt_len, client_random,
					 client_random_len, server_random,
					 server_random_len);
	}

	if (status != SMW_STATUS_OK)
		goto end;

	status = tls12_set_derive_args(args, MASTER_SECRET, payload,
				       (unsigned int)(sizeof(*payload)),
				       &key_ex_args);
	if (status != SMW_STATUS_OK)
		goto end;

	SMW_DBG_PRINTF(VERBOSE,
		       " Call hsm_key_exchange()\n"
		       "  TLS1.2 Master Secret\n"
		       "  flags: 0x%04X\n"
		       "  in_pub_buffer_sz: %d\n"
		       "  user_fixed_info_sz: %d\n"
		       "  in_content_sz: %d\n"
		       "  in_content (payload): %p\n"
		       "  out_derived_key_id: 0x%08X\n"
		       "  expected_out_sz: %d\n"
		       "  output_sz: %d\n"
		       "  output: %p\n",
		       key_ex_args.flags, key_ex_args.in_pub_buffer_sz,
		       key_ex_args.user_fixed_info_sz,
		       key_ex_args.in_content_sz, key_ex_args.in_content,
		       key_ex_args.out_derived_key_id,
		       key_ex_args.exp_output_sz, key_ex_args.output_sz,
		       key_ex_args.output);

	err = hsm_key_exchange(*key_mgt_hdl, &key_ex_args);
	SMW_DBG_PRINTF(DEBUG, "hsm_key_exchange returned %d\n", err);

	status = ele_convert_err(err);
	if (status != SMW_STATUS_OK)
		goto end;

	key_derived_identifier->s_id = key_ex_args.out_derived_key_id;
	/*
	 * In case of key derivation, the key group is unknown.
	 * The FW selects the key group.
	 */
	key_derived_identifier->group = ELE_UNDEFINED_KEY_GROUP;
	key_derived_identifier->security_size = TLS12_MASTER_SECRET_SEC_SIZE;
	key_derived_identifier->subsystem_id = SUBSYSTEM_ID_ELE;
	key_derived_identifier->type_id = SMW_CONFIG_KEY_TYPE_ID_TLS_MASTER;

	args->key_derived.pub->format_name = SMW_KEY_FORMAT_NAME_HEX;
	args->key_derived.pub->id = key_ex_args.out_derived_key_id;
	args->key_derived.pub->security_size = TLS12_MASTER_SECRET_SEC_SIZE;
	args->key_derived.pub->type_name = SMW_KEY_TYPE_NAME_TLS_MASTER;

	key_derived_attributes->attributes =
		SMW_ATTR_SET_SENSITIVE(key_derived_attributes->attributes);

end:
	if (key_ex_args.user_fixed_info)
		SMW_UTILS_FREE(key_ex_args.user_fixed_info);

	if (key_ex_args.output)
		SMW_UTILS_FREE(key_ex_args.output);

	if (payload)
		SMW_UTILS_FREE(payload);

	return status;
}

static int
tls12_op_derive_key_expansion(struct smw_keymgr_derive_key_args *args,
			      hsm_hdl_t *key_mgt_hdl)
{
	int status = SMW_STATUS_ALLOC_FAILURE;
	struct tls12_kb_ele_op_payload *payload = NULL;
	op_key_exchange_args_t key_ex_args = { 0 };
	struct smw_keymgr_tls12_args *tls_args = args->kdf_args;
	struct tls12_ciphersuite ciphersuite = { 0 };
	hsm_err_t err = HSM_NO_ERROR;

	unsigned char *client_random =
		smw_keymgr_tls12_get_client_random(tls_args);
	unsigned int client_random_len =
		smw_keymgr_tls12_get_client_random_length(tls_args);
	unsigned char *server_random =
		smw_keymgr_tls12_get_server_random(tls_args);
	unsigned int server_random_len =
		smw_keymgr_tls12_get_server_random_length(tls_args);

	payload = SMW_UTILS_CALLOC(1, sizeof(*payload));
	if (!payload)
		goto end;

	payload->ver = 1;
	payload->key_id = args->key_base.identifier.s_id;

	status = ele_get_key_store_id(&payload->keystore_id);
	if (status != SMW_STATUS_OK)
		goto end;

	status = get_tls12_algo(tls_args, KEY_BLOCK, &payload->tls1_2_algo);
	if (status != SMW_STATUS_OK)
		goto end;

	status = get_tls12_ciphersuite(tls_args, &ciphersuite);
	if (status != SMW_STATUS_OK)
		goto end;

	payload->cipher_algo = ciphersuite.permitted_algo;
	payload->cipher_bits = ciphersuite.bits;

	status = build_user_info(&key_ex_args.user_fixed_info,
				 &key_ex_args.user_fixed_info_sz,
				 smw_keymgr_get_salt(args),
				 smw_keymgr_get_salt_len(args), server_random,
				 server_random_len, client_random,
				 client_random_len);
	if (status != SMW_STATUS_OK)
		goto end;

	status = tls12_set_derive_args(args, KEY_BLOCK, payload,
				       (unsigned int)(sizeof(*payload)),
				       &key_ex_args);
	if (status != SMW_STATUS_OK)
		goto end;

	SMW_DBG_PRINTF(VERBOSE,
		       " Call hsm_key_exchange()\n"
		       "  TLS1.2 Key Expansion\n"
		       "  flags: 0x%04X\n"
		       "  in_pub_buffer_sz: %d\n"
		       "  user_fixed_info_sz: %d\n"
		       "  in_content_sz: %d\n"
		       "  in_content (payload): %p\n"
		       "  out_derived_key_id: 0x%08X\n"
		       "  expected_out_sz: %d\n"
		       "  output_sz: %d\n"
		       "  output: %p\n",
		       key_ex_args.flags, key_ex_args.in_pub_buffer_sz,
		       key_ex_args.user_fixed_info_sz,
		       key_ex_args.in_content_sz, key_ex_args.in_content,
		       key_ex_args.out_derived_key_id,
		       key_ex_args.exp_output_sz, key_ex_args.output_sz,
		       key_ex_args.output);

	err = hsm_key_exchange(*key_mgt_hdl, &key_ex_args);
	SMW_DBG_PRINTF(DEBUG, "hsm_key_exchange returned %d\n", err);

	status = ele_convert_err(err);
	if (status != SMW_STATUS_OK)
		goto end;

	status = tls12_extract_result(args, KEY_BLOCK, &key_ex_args);

end:
	if (key_ex_args.user_fixed_info)
		SMW_UTILS_FREE(key_ex_args.user_fixed_info);

	if (key_ex_args.output)
		SMW_UTILS_FREE(key_ex_args.output);

	if (payload)
		SMW_UTILS_FREE(payload);

	return status;
}

static int tls12_op_derive_ivs(struct smw_keymgr_derive_key_args *args,
			       hsm_hdl_t *key_mgt_hdl)
{
	int status = SMW_STATUS_ALLOC_FAILURE;
	struct tls12_kb_ele_op_payload *payload = NULL;
	op_key_exchange_args_t key_ex_args = { 0 };
	struct smw_keymgr_tls12_args *tls_args = args->kdf_args;
	struct tls12_ciphersuite ciphersuite = { 0 };
	hsm_err_t err = HSM_NO_ERROR;

	unsigned char *client_random =
		smw_keymgr_tls12_get_client_random(tls_args);
	unsigned int client_random_len =
		smw_keymgr_tls12_get_client_random_length(tls_args);
	unsigned char *server_random =
		smw_keymgr_tls12_get_server_random(tls_args);
	unsigned int server_random_len =
		smw_keymgr_tls12_get_server_random_length(tls_args);

	payload = SMW_UTILS_CALLOC(1, sizeof(*payload));
	if (!payload)
		goto end;

	payload->ver = 1;
	payload->key_id = args->key_base.identifier.s_id;

	status = ele_get_key_store_id(&payload->keystore_id);
	if (status != SMW_STATUS_OK)
		goto end;

	status = get_tls12_algo(tls_args, IV, &payload->tls1_2_algo);
	if (status != SMW_STATUS_OK)
		goto end;

	status = get_tls12_ciphersuite(tls_args, &ciphersuite);
	if (status != SMW_STATUS_OK)
		goto end;

	payload->cipher_algo = ciphersuite.permitted_algo;
	payload->cipher_bits = ciphersuite.bits;

	/* Allocate and fill the user fixed info with: label + server_random + client_random */
	status = build_user_info(&key_ex_args.user_fixed_info,
				 &key_ex_args.user_fixed_info_sz,
				 smw_keymgr_get_salt(args),
				 smw_keymgr_get_salt_len(args), server_random,
				 server_random_len, client_random,
				 client_random_len);
	if (status != SMW_STATUS_OK)
		goto end;

	status = tls12_set_derive_args(args, IV, payload,
				       (unsigned int)(sizeof(*payload)),
				       &key_ex_args);
	if (status != SMW_STATUS_OK)
		goto end;

	SMW_DBG_PRINTF(VERBOSE,
		       " Call hsm_key_exchange()\n"
		       "  TLS1.2 IVs\n"
		       "  flags: 0x%04X\n"
		       "  in_pub_buffer_sz: %d\n"
		       "  user_fixed_info_sz: %d\n"
		       "  in_content_sz: %d\n"
		       "  in_content (payload): %p\n"
		       "  out_derived_key_id: 0x%08X\n"
		       "  expected_out_sz: %d\n"
		       "  output_sz: %d\n"
		       "  output: %p\n",
		       key_ex_args.flags, key_ex_args.in_pub_buffer_sz,
		       key_ex_args.user_fixed_info_sz,
		       key_ex_args.in_content_sz, key_ex_args.in_content,
		       key_ex_args.out_derived_key_id,
		       key_ex_args.exp_output_sz, key_ex_args.output_sz,
		       key_ex_args.output);

	err = hsm_key_exchange(*key_mgt_hdl, &key_ex_args);
	SMW_DBG_PRINTF(DEBUG, "hsm_key_exchange returned %d\n", err);

	status = ele_convert_err(err);
	if (status != SMW_STATUS_OK)
		goto end;

	status = tls12_extract_result(args, IV, &key_ex_args);

end:
	if (key_ex_args.user_fixed_info)
		SMW_UTILS_FREE(key_ex_args.user_fixed_info);

	if (key_ex_args.output)
		SMW_UTILS_FREE(key_ex_args.output);

	if (payload)
		SMW_UTILS_FREE(payload);

	return status;
}

int derive_tls12_op(struct hdl *hdl, struct smw_keymgr_derive_key_args *args)
{
	int status = SMW_STATUS_INVALID_PARAM;
	int tmp_status = SMW_STATUS_OK;
	hsm_hdl_t key_mgt_hdl = 0;
	struct smw_keymgr_tls12_args *tls12_args = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!args || !args->kdf_args)
		goto end;

	if (args->key_base.identifier.s_id == INVALID_KEY_ID)
		goto end;

	tls12_args = args->kdf_args;

	status = open_key_mgmt_service(hdl, &key_mgt_hdl);
	if (status != SMW_STATUS_OK)
		goto end;

	switch (tls12_args->op_id) {
	case SMW_TLS12_OPERATION_ID_MASTER_SECRET:
		status = tls12_op_derive_master_secret(args, &key_mgt_hdl);
		break;

	case SMW_TLS12_OPERATION_ID_KEY_EXPANSION:
		status = tls12_op_derive_key_expansion(args, &key_mgt_hdl);
		if (status != SMW_STATUS_OK)
			goto end;

		status = tls12_op_derive_ivs(args, &key_mgt_hdl);
		break;

	default:
		break;
	}

end:
	if (key_mgt_hdl) {
		tmp_status = close_key_mgt_service(key_mgt_hdl);
		if (status == SMW_STATUS_OK)
			status = tmp_status;
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	// coverity[missing_unlock]
	return status;
}
