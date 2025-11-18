// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024-2025 NXP
 */

#include <tee_client_api.h>
#include <tee_api_defines_extensions.h>

#include "operations.h"
#include "subsystems.h"
#include "debug.h"
#include "utils.h"
#include "base64.h"
#include "config.h"
#include "tee.h"
#include "smw_status.h"
#include "keymgr_derive.h"

#define HKDF_ALGO_ID(_id)                                                      \
	{                                                                      \
		.hash_id = SMW_CONFIG_HASH_ALGO_ID_##_id,                      \
		.tee_algo = TEE_ALG_HKDF_##_id##_DERIVE_KEY                    \
	}

/**
 * struct - HKDF algorithm IDs
 * @hash_id: Hash algorithm ID as defined in SMW.
 * @tee_algo: Hash algorithm ID as defined in TEE subsystem.
 */
static const struct {
	enum smw_config_hash_algo_id hash_id;
	uint32_t tee_algo;
} tee_algo_ids[] = { HKDF_ALGO_ID(MD5),	   HKDF_ALGO_ID(SHA1),
		     HKDF_ALGO_ID(SHA224), HKDF_ALGO_ID(SHA256),
		     HKDF_ALGO_ID(SHA384), HKDF_ALGO_ID(SHA512) };

static int get_tee_hkdf_algo_id(enum smw_config_hash_algo_id hash_id,
				uint32_t *tee_algo)
{
	unsigned int i = 0;

	for (; i < ARRAY_SIZE(tee_algo_ids); i++) {
		if (hash_id == tee_algo_ids[i].hash_id) {
			*tee_algo = tee_algo_ids[i].tee_algo;
			return SMW_STATUS_OK;
		}
	}

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

/**
 * fill_shared_key_memory() - Fill shared memory with salt and info buffers.
 * @shared_mem: Pointer to TEEC shared memory structure.
 * @hkdf_args: Pointer to internal HKDF structure.
 * @shared_params: Pointer to derive key operation shared parameters.
 *
 * Return:
 * None
 */
static void fill_shared_memory(TEEC_SharedMemory *shared_mem,
			       struct smw_keymgr_derive_key_args *key_args,
			       struct key_derive_shared_params *shared_params)
{
	void *buffer = shared_mem->buffer;
	unsigned char *salt = smw_keymgr_get_salt(key_args);
	unsigned char *info = smw_keymgr_get_info(key_args);

	if (salt)
		SMW_UTILS_MEMCPY(buffer, salt, shared_params->salt_length);

	if (info)
		SMW_UTILS_MEMCPY(buffer + shared_params->salt_length, info,
				 shared_params->info_length);
}

/**
 * is_base_key_type_supported() - Check if the base key type is supported.
 * @type_id: Key type ID.
 * @kdf_id: KDF ID.
 *
 * Depending on the @kdf_id, check if @type_id is supported to perform the key
 * derivation operation.
 *
 * Return:
 * True, if key is supported.
 * False, otherwise
 */
static bool is_base_key_type_supported(enum smw_config_key_type_id type_id,
				       enum smw_config_kdf_id kdf_id)
{
	bool status = false;

	if (kdf_id == SMW_CONFIG_KDF_ID_HKDF) {
		switch (type_id) {
		case SMW_CONFIG_KEY_TYPE_ID_RAW:
		case SMW_CONFIG_KEY_TYPE_ID_HKDF_IKM:
			status = true;
			break;

		default:
			break;
		}
	} else if (kdf_id == SMW_CONFIG_KDF_ID_ECDH) {
		switch (type_id) {
		case SMW_CONFIG_KEY_TYPE_ID_SECP_R1:
			status = true;
			break;

		default:
			break;
		}
	}

	return status;
}

/**
 * get_base_key_public_buffer() - Get the base key public buffer in HEX format.
 * @key_desc: Pointer to internal Key descriptor structure
 * @hex_key: Pointer to the HEX buffer to update
 * @hex_key_len: @hex_key length to update
 *
 * Return:
 * SMW_STATUS_OK             - Success.
 * SMW_STATUS_INVALID_PARAM  - One of the parameters is invalid.
 * SMW_STATUS_ALLOC_FAILURE  - Memory allocation failed.
 */
static int get_base_key_public_buffer(struct smw_keymgr_descriptor *key_desc,
				      unsigned char **hex_key,
				      unsigned int *hex_key_len)
{
	int status = SMW_STATUS_INVALID_PARAM;

	unsigned char *key = NULL;
	unsigned int key_len = 0;

	key = smw_keymgr_get_public_data(key_desc);
	key_len = smw_keymgr_get_public_length(key_desc);
	if (!key || !key_len)
		goto exit;

	status = smw_utils_key_set_hex_buffer(key_desc->format_id, key, key_len,
					      hex_key, hex_key_len);

exit:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * get_base_key_private_buffer() - Get the base key private buffers in HEX format.
 * @key_desc: Pointer to internal Key descriptor structure
 * @hex_key: Pointer to the HEX buffer to update
 * @hex_key_len: @hex_key length to update
 *
 * Return:
 * SMW_STATUS_OK             - Success.
 * SMW_STATUS_INVALID_PARAM  - One of the parameters is invalid.
 * SMW_STATUS_ALLOC_FAILURE  - Memory allocation failed.
 */
static int get_base_key_private_buffer(struct smw_keymgr_descriptor *key_desc,
				       unsigned char **hex_key,
				       unsigned int *hex_key_len)
{
	int status = SMW_STATUS_INVALID_PARAM;

	unsigned char *key = NULL;
	unsigned int key_len = 0;

	key = smw_keymgr_get_private_data(key_desc);
	key_len = smw_keymgr_get_private_length(key_desc);
	if (!key || !key_len)
		goto exit;

	status = smw_utils_key_set_hex_buffer(key_desc->format_id, key, key_len,
					      hex_key, hex_key_len);

exit:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * get_base_key_pair_buffer() - Get the base key pair buffers in HEX format.
 * @key_desc: Pointer to internal Key descriptor structure
 * @hex_key: Pointer to the HEX buffer to update
 * @hex_key_len: @hex_key length to update
 *
 * Return:
 * SMW_STATUS_OK             - Success.
 * SMW_STATUS_INVALID_PARAM  - One of the parameters is invalid.
 * SMW_STATUS_ALLOC_FAILURE  - Memory allocation failed.
 */
static int get_base_key_pair_buffer(struct smw_keymgr_descriptor *key_desc,
				    unsigned char **hex_key,
				    unsigned int *hex_key_len)
{
	int status = SMW_STATUS_OK;
	unsigned char *hex_key_base_public = NULL;
	unsigned char *hex_key_base_private = NULL;
	unsigned int hex_key_base_public_len = 0;
	unsigned int hex_key_base_private_len = 0;

	status = get_base_key_public_buffer(key_desc, &hex_key_base_public,
					    &hex_key_base_public_len);
	if (status != SMW_STATUS_OK)
		goto exit;

	status = get_base_key_private_buffer(key_desc, &hex_key_base_private,
					     &hex_key_base_private_len);
	if (status != SMW_STATUS_OK)
		goto exit;

	if (ADD_OVERFLOW(hex_key_base_public_len, hex_key_base_private_len,
			 hex_key_len)) {
		status = SMW_STATUS_INVALID_PARAM;
		goto exit;
	}

	*hex_key = SMW_UTILS_MALLOC(*hex_key_len);
	if (!*hex_key) {
		status = SMW_STATUS_ALLOC_FAILURE;
		goto exit;
	}

	SMW_UTILS_MEMCPY(*hex_key, hex_key_base_public,
			 hex_key_base_public_len);
	SMW_UTILS_MEMCPY(*hex_key + hex_key_base_public_len,
			 hex_key_base_private, hex_key_base_private_len);

exit:
	if (key_desc->format_id == SMW_KEYMGR_FORMAT_ID_BASE64) {
		if (hex_key_base_public)
			SMW_UTILS_FREE(hex_key_base_public);
		if (hex_key_base_private)
			SMW_UTILS_FREE(hex_key_base_private);
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * get_derived_key_buffer() - Get the derived key buffer in HEX format
 * @key_desc: Pointer to internal derived Key descriptor structure
 * @hex_key: Pointer to the HEX buffer to update
 * @hex_key_len: @hex_key length to update
 *
 * Return the derived key buffer in HEX format if the derived key is to be
 * exported.
 *
 * Return:
 * SMW_STATUS_OK             - Success.
 * SMW_STATUS_INVALID_PARAM  - One of the parameters is invalid.
 * SMW_STATUS_ALLOC_FAILURE  - Memory allocation failed.
 */
static int get_derived_key_buffer(struct smw_keymgr_derived_key_desc *key_desc,
				  unsigned char **hex_key,
				  unsigned int *hex_key_len)
{
	int status = SMW_STATUS_INVALID_PARAM;

	unsigned char *key = NULL;
	unsigned int key_len = 0;

	key = smw_keymgr_get_shared_secret_buffer(key_desc);
	key_len = smw_keymgr_get_shared_secret_len(key_desc);

	if ((!key && key_len) || (key && !key_len))
		goto exit;
	else if (key && key_len)
		status = smw_utils_key_set_hex_buffer(key_desc->format_id, key,
						      key_len, hex_key,
						      hex_key_len);
	else
		status = SMW_STATUS_OK;

exit:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * tee_key_derived_type() - Get the TEE key type of expected derived key
 * @key_identifier: [in] Pointer to the derived key identifier
 * @permitted_algo: [in] Derived key permitted algorithm
 * @key_type: [out] TEE key type
 *
 * Return:
 * SMW_STATUS_OK                      - Success.
 * SMW_STATUS_OPERATION_NOT_SUPPORTED - Key type not supported
 */
static int tee_key_derived_type(struct smw_keymgr_identifier *key_identifier,
				smw_attr_algo_t permitted_algo,
				enum tee_key_type *key_type)
{
	int status = SMW_STATUS_OK;
	enum smw_config_hash_algo_id hash_id = SMW_CONFIG_HASH_ALGO_ID_INVALID;

	status = smw_utils_hash_attr_to_algo_id(permitted_algo, &hash_id);
	if (status == SMW_STATUS_OK)
		status =
			tee_convert_key_type(key_identifier, hash_id, key_type);

	return status;
}

/**
 * hkdf_derive_key() - Derive a key from base key using HKDF algo.
 * @args: Key derive arguments.
 *
 * The derived key is stored in the tee subsystem storage.
 * Depending on the derived key attributes set by the user, the derived key is
 * transient or persistent object.
 *
 * Return:
 * SMW_STATUS_OK                      - Success.
 * SMW_STATUS_INVALID_PARAM           - One of the parameters is invalid.
 * SMW_STATUS_ALLOC_FAILURE           - Memory allocation failure.
 * SMW_STATUS_OUTPUT_TOO_SHORT        - Output buffer is too short.
 * SMW_STATUS_OPERATION_FAILURE       - Operation failed.
 * SMW_STATUS_SUBSYSTEM_FAILURE       - Subsytem failed.
 * SMW_STATUS_OPERATION_NOT_SUPPORTED - Operation is not supported.
 */
static int hkdf_derive_key(void *args)
{
	int status = SMW_STATUS_INVALID_PARAM;
	int temp_status = SMW_STATUS_OK;

	struct smw_keymgr_derive_key_args *key_args = args;
	struct smw_keymgr_hkdf_args *hkdf_args = NULL;
	struct key_derive_shared_params shared_params = { 0 };
	struct smw_keymgr_identifier *key_id_base = NULL;
	struct smw_keymgr_identifier *key_id_derived = NULL;
	struct smw_key_attributes *key_attrs_derived = NULL;
	struct smw_key_attributes *key_attrs = NULL;
	smw_attr_usage_t actual_usage_flags = 0;

	unsigned int key_len = 0;
	unsigned char *key_derived = NULL;
	unsigned char *hex_key_derived = NULL;
	unsigned char *hex_key_base = NULL;
	unsigned int hex_key_base_len = 0;
	unsigned int hex_key_derived_len = 0;
	size_t size = 0;

	TEEC_Result result = TEEC_SUCCESS;
	TEEC_Operation op = { 0 };
	TEEC_SharedMemory shared_mem = { 0 };
	uint32_t param_type = TEEC_NONE;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!key_args)
		goto exit;

	key_id_base = &key_args->key_base.identifier;
	key_id_derived = &key_args->key_derived.identifier;
	hkdf_args = key_args->kdf_args;
	if (!hkdf_args || !key_id_base || !key_id_derived)
		goto exit;

	key_attrs_derived = &key_id_derived->key_attributes;

	if (key_args->kdf_id != SMW_CONFIG_KDF_ID_HKDF) {
		status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
		goto exit;
	}

	if (!is_base_key_type_supported(key_id_base->type_id,
					key_args->kdf_id)) {
		SMW_DBG_PRINTF(ERROR, "%s unsupported base key type\n",
			       __func__);
		status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
		goto exit;
	}

	status = get_tee_hkdf_algo_id(hkdf_args->prf_id,
				      &shared_params.derive_algo);
	if (status != SMW_STATUS_OK)
		goto exit;

	key_attrs = key_args->key_attributes;
	if (key_attrs) {
		status = check_persistence(key_attrs->attributes,
					   &shared_params.persistent);
		if (status != SMW_STATUS_OK)
			goto exit;

		key_usage_to_tee(key_attrs->usage_flags,
				 &shared_params.key_usage);
		key_usage_to_smw(shared_params.key_usage, &actual_usage_flags);
	} else if (smw_keymgr_is_store_key_set(key_args)) {
		SMW_DBG_PRINTF(ERROR, "Missing key derivation attributes");
		status = SMW_STATUS_INVALID_PARAM;
		goto exit;
	}

	/*
	 * params[0] = Pointer to derive key shared params structure.
	 * params[1] = Pointer to base key buffer or none.
	 * params[2] = Pointer to derived key buffer or none.
	 * params[3] = Salt/info buffer or none.
	 */

	shared_params.derived_key_id = key_id_derived->s_id;
	shared_params.base_key_id = key_id_base->s_id;
	shared_params.salt_length = smw_keymgr_get_salt_len(key_args);
	shared_params.info_length = smw_keymgr_get_info_len(key_args);
	shared_params.base_key_sec_size = key_id_base->security_size;
	shared_params.store_derived_key = smw_keymgr_is_store_key_set(key_args);

	op.params[DER_SHARED_PARAM_IDX].tmpref.buffer = &shared_params;
	op.params[DER_SHARED_PARAM_IDX].tmpref.size = sizeof(shared_params);

	SET_TEEC_PARAMS_TYPE(op.paramTypes, TEEC_MEMREF_TEMP_INPUT,
			     DER_SHARED_PARAM_IDX);

	if (shared_params.base_key_id == INVALID_KEY_ID) {
		status = get_base_key_public_buffer(&key_args->key_base,
						    &hex_key_base,
						    &hex_key_base_len);
		if (status != SMW_STATUS_OK)
			goto exit;
	}

	status = set_tmpref_buffer(TEEC_MEMREF_TEMP_INPUT,
				   DER_BASE_KEY_PARAM_IDX, hex_key_base,
				   hex_key_base_len, &op);

	status = get_derived_key_buffer(&key_args->key_derived,
					&hex_key_derived, &hex_key_derived_len);
	if (status != SMW_STATUS_OK)
		goto exit;

	status = set_tmpref_buffer(TEEC_MEMREF_TEMP_OUTPUT,
				   DER_DERIVED_KEY_PARAM_IDX, hex_key_derived,
				   hex_key_derived_len, &op);

	/*
	 * If the derived key security size is not defined by the user and derived
	 * key to be exported, calculate the derived key security size based on the
	 * derived key buffer length.
	 */
	if (key_id_derived->security_size) {
		shared_params.derived_key_sec_size =
			key_id_derived->security_size;
	} else if (hex_key_derived && hex_key_derived_len) {
		if (MUL_OVERFLOW(hex_key_derived_len, 8,
				 &shared_params.derived_key_sec_size)) {
			status = SMW_STATUS_INVALID_PARAM;
			goto exit;
		}
	}

	if (shared_params.store_derived_key) {
		/* Get TEE key type of derived key */
		status = tee_key_derived_type(key_id_derived,
					      key_attrs->permitted_algo,
					      &shared_params.key_type);
		if (status != SMW_STATUS_OK)
			goto exit;
	}

	size = shared_params.salt_length + shared_params.info_length;

	/* If salt and info buffers are set, allocate a shared memory */
	if (size) {
		shared_mem.size = size;
		shared_mem.flags = TEEC_MEM_INPUT;

		result = TEEC_AllocateSharedMemory(get_tee_context_ptr(),
						   &shared_mem);
		if (result != TEEC_SUCCESS) {
			status = tee_convert_result(result);
			goto exit;
		}

		fill_shared_memory(&shared_mem, key_args, &shared_params);

		op.params[DER_SHARED_MEM_IDX].memref.parent = &shared_mem;
		op.params[DER_SHARED_MEM_IDX].memref.offset = 0;
		op.params[DER_SHARED_MEM_IDX].memref.size = size;

		param_type = TEEC_MEMREF_PARTIAL_INPUT;
	}

	SET_TEEC_PARAMS_TYPE(op.paramTypes, param_type, DER_SHARED_MEM_IDX);

	/* Invoke TA */
	status = execute_tee_cmd(CMD_DERIVE_KEY, &op);
	if (status != SMW_STATUS_OK)
		goto exit;

	/* Update derived key_identifier struct if user has requested to store the
	 * derived key, else return the derived key buffer if derived key buffer
	 * is set.
	 */
	if (shared_params.store_derived_key) {
		key_id_derived->subsystem_id = SUBSYSTEM_ID_TEE;
		key_id_derived->s_id = shared_params.derived_key_id;
		key_id_derived->security_size =
			shared_params.derived_key_sec_size;
		key_id_derived->type_id =
			key_type_tee_to_smw(shared_params.key_type);
		status = smw_keymgr_get_privacy_id(key_id_derived->type_id,
						   &key_id_derived->privacy_id);
		if (status != SMW_STATUS_OK)
			goto exit;

		key_attrs_derived->attributes =
			SMW_ATTR_SET_SENSITIVE(key_attrs_derived->attributes);

		SMW_DBG_PRINTF(DEBUG, "%s: Key #%d is generated.\n", __func__,
			       key_id_derived->s_id);
	}

	if (SET_OVERFLOW(op.params[DER_DERIVED_KEY_PARAM_IDX].tmpref.size,
			 key_len)) {
		status = SMW_STATUS_OPERATION_FAILURE;
		goto exit;
	}

	key_derived = op.params[DER_DERIVED_KEY_PARAM_IDX].tmpref.buffer;
	temp_status = smw_keymgr_update_shared_secret(&key_args->key_derived,
						      key_derived, key_len);

	if (temp_status != SMW_STATUS_OK)
		status = temp_status;

exit:
	if (key_args &&
	    key_args->key_base.format_id == SMW_KEYMGR_FORMAT_ID_BASE64 &&
	    hex_key_base)
		SMW_UTILS_FREE(hex_key_base);

	if (hex_key_derived &&
	    key_args->key_derived.format_id == SMW_KEYMGR_FORMAT_ID_BASE64)
		SMW_UTILS_FREE(hex_key_derived);

	if (status != SMW_STATUS_OK) {
		if (shared_params.derived_key_id)
			(void)tee_delete_key(shared_params.derived_key_id);
	} else if (key_attrs &&
		   (key_attrs->permitted_algo ||
		    key_attrs->usage_flags != actual_usage_flags)) {
		key_attrs->permitted_algo = 0;
		key_attrs->usage_flags = actual_usage_flags;

		status = SMW_STATUS_KEY_POLICY_WARNING_IGNORED;
	}

	TEEC_ReleaseSharedMemory(&shared_mem);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * ecdh_derive_key() - Derive a key from base key using ECDH algo.
 * @args: Key derive arguments.
 *
 * The derived key is stored in the tee subsystem storage.
 * Depending on the derived key attributes set by the user, the derived key is
 * transient or persistent object.
 *
 * Return:
 * SMW_STATUS_OK                - Success.
 * SMW_STATUS_INVALID_PARAM     - One of the parameters is invalid.
 * SMW_STATUS_ALLOC_FAILURE     - Memory allocation failure.
 * SMW_STATUS_OUTPUT_TOO_SHORT  - Output buffer is too short
 * SMW_STATUS_OPERATION_FAILURE - Operation failed
 * SMW_STATUS_SUBSYSTEM_FAILURE - Subsytem failed.
 */
static int ecdh_derive_key(void *args)
{
	int status = SMW_STATUS_INVALID_PARAM;
	int temp_status = SMW_STATUS_OK;

	struct smw_keymgr_derive_key_args *key_args = args;
	struct smw_keymgr_ecdh_args *ecdh_args = NULL;
	struct key_derive_shared_params shared_params = { 0 };
	struct smw_keymgr_identifier *key_id_base = NULL;
	struct smw_keymgr_identifier *key_id_derived = NULL;
	struct smw_key_attributes *key_attrs_derived = NULL;
	struct smw_key_attributes *key_attrs = NULL;
	smw_attr_usage_t actual_usage_flags = 0;

	unsigned int key_len = 0;
	unsigned char *key_derived = NULL;
	unsigned char *hex_key_derived = NULL;
	unsigned char *hex_key_base = NULL;
	unsigned char *peer_public_buffer = NULL;
	unsigned int hex_key_base_len = 0;
	unsigned int hex_key_derived_len = 0;
	unsigned int peer_public_buffer_len = 0;

	TEEC_Operation op = { 0 };
	TEEC_SharedMemory shared_mem = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!key_args)
		goto exit;

	key_id_base = &key_args->key_base.identifier;
	key_id_derived = &key_args->key_derived.identifier;
	ecdh_args = key_args->kdf_args;
	if (!ecdh_args || !key_id_base || !key_id_derived)
		goto exit;

	key_attrs_derived = &key_id_derived->key_attributes;

	peer_public_buffer = smw_keymgr_get_peer_pub_buffer(key_args);
	if (!peer_public_buffer)
		goto exit;

	peer_public_buffer_len = smw_keymgr_get_peer_pub_buffer_len(key_args);
	if (!peer_public_buffer_len)
		goto exit;

	if (!is_base_key_type_supported(key_id_base->type_id,
					key_args->kdf_id)) {
		SMW_DBG_PRINTF(ERROR, "%s unsupported base key type\n",
			       __func__);
		status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
		goto exit;
	}

	shared_params.derive_algo = TEE_ALG_ECDH_DERIVE_SHARED_SECRET;

	key_attrs = key_args->key_attributes;
	if (key_attrs) {
		status = check_persistence(key_attrs->attributes,
					   &shared_params.persistent);
		if (status != SMW_STATUS_OK)
			goto exit;

		key_usage_to_tee(key_attrs->usage_flags,
				 &shared_params.key_usage);
		key_usage_to_smw(shared_params.key_usage, &actual_usage_flags);
	} else if (smw_keymgr_is_store_key_set(key_args)) {
		SMW_DBG_PRINTF(ERROR, "Missing key derivation attributes");
		status = SMW_STATUS_INVALID_PARAM;
		goto exit;
	}

	/*
	 * params[0] = Pointer to derive key shared params structure.
	 * params[1] = Pointer to public key buffer.
	 * params[2] = Pointer to derived key buffer.
	 * params[3] = Pointer to peer public buffer.
	 */

	shared_params.derived_key_id = key_id_derived->s_id;
	shared_params.base_key_id = key_id_base->s_id;
	shared_params.base_key_sec_size = key_id_base->security_size;
	shared_params.store_derived_key = smw_keymgr_is_store_key_set(key_args);

	op.params[DER_SHARED_PARAM_IDX].tmpref.buffer = &shared_params;
	op.params[DER_SHARED_PARAM_IDX].tmpref.size = sizeof(shared_params);

	SET_TEEC_PARAMS_TYPE(op.paramTypes, TEEC_MEMREF_TEMP_INPUT,
			     DER_SHARED_PARAM_IDX);

	if (shared_params.base_key_id == INVALID_KEY_ID) {
		status = get_base_key_pair_buffer(&key_args->key_base,
						  &hex_key_base,
						  &hex_key_base_len);
		if (status != SMW_STATUS_OK)
			goto exit;
	}

	status = set_tmpref_buffer(TEEC_MEMREF_TEMP_INPUT,
				   DER_BASE_KEY_PARAM_IDX, hex_key_base,
				   hex_key_base_len, &op);
	if (status != SMW_STATUS_OK)
		goto exit;

	status = get_derived_key_buffer(&key_args->key_derived,
					&hex_key_derived, &hex_key_derived_len);
	if (status != SMW_STATUS_OK)
		goto exit;

	status = set_tmpref_buffer(TEEC_MEMREF_TEMP_OUTPUT,
				   DER_DERIVED_KEY_PARAM_IDX, hex_key_derived,
				   hex_key_derived_len, &op);
	if (status != SMW_STATUS_OK)
		goto exit;

	status = set_tmpref_buffer(TEEC_MEMREF_TEMP_INPUT, DER_SHARED_MEM_IDX,
				   peer_public_buffer, peer_public_buffer_len,
				   &op);
	if (status != SMW_STATUS_OK)
		goto exit;

	/*
	 * If the derived key security size is not defined by the user and derived
	 * key to be exported, calculate the derived key security size based on the
	 * derived key buffer length.
	 */
	if (key_id_derived->security_size) {
		shared_params.derived_key_sec_size =
			key_id_derived->security_size;
	} else if (hex_key_derived && hex_key_derived_len) {
		if (MUL_OVERFLOW(hex_key_derived_len, 8,
				 &shared_params.derived_key_sec_size)) {
			status = SMW_STATUS_INVALID_PARAM;
			goto exit;
		}
	}

	if (shared_params.store_derived_key) {
		/* Get TEE key type of derived key */
		status = tee_key_derived_type(key_id_derived,
					      key_attrs->permitted_algo,
					      &shared_params.key_type);
		if (status != SMW_STATUS_OK)
			goto exit;
	}

	/* Invoke TA */
	status = execute_tee_cmd(CMD_DERIVE_KEY, &op);
	if (status != SMW_STATUS_OK)
		goto exit;

	/* Update derived key_identifier struct if user has requested to store the
	 * derived key, else return the derived key buffer if derived key buffer
	 * is set.
	 */
	if (shared_params.store_derived_key) {
		key_id_derived->subsystem_id = SUBSYSTEM_ID_TEE;
		key_id_derived->s_id = shared_params.derived_key_id;
		key_id_derived->security_size =
			shared_params.derived_key_sec_size;
		key_id_derived->type_id =
			key_type_tee_to_smw(shared_params.key_type);
		status = smw_keymgr_get_privacy_id(key_id_derived->type_id,
						   &key_id_derived->privacy_id);
		if (status != SMW_STATUS_OK)
			goto exit;

		key_attrs_derived->attributes =
			SMW_ATTR_SET_SENSITIVE(key_attrs_derived->attributes);

		SMW_DBG_PRINTF(DEBUG, "%s: Key #%d is generated.\n", __func__,
			       key_id_derived->s_id);
	}

	if (SET_OVERFLOW(op.params[DER_DERIVED_KEY_PARAM_IDX].tmpref.size,
			 key_len)) {
		status = SMW_STATUS_OPERATION_FAILURE;
		goto exit;
	}

	key_derived = op.params[DER_DERIVED_KEY_PARAM_IDX].tmpref.buffer;
	temp_status = smw_keymgr_update_shared_secret(&key_args->key_derived,
						      key_derived, key_len);
	if (temp_status != SMW_STATUS_OK)
		status = temp_status;

exit:
	if (hex_key_base)
		SMW_UTILS_FREE(hex_key_base);

	if (hex_key_derived &&
	    key_args->key_derived.format_id == SMW_KEYMGR_FORMAT_ID_BASE64)
		SMW_UTILS_FREE(hex_key_derived);

	if (status != SMW_STATUS_OK) {
		if (shared_params.derived_key_id)
			(void)tee_delete_key(shared_params.derived_key_id);
	} else if (key_attrs &&
		   (key_attrs->permitted_algo ||
		    key_attrs->usage_flags != actual_usage_flags)) {
		key_attrs->permitted_algo = 0;
		key_attrs->usage_flags = actual_usage_flags;

		status = SMW_STATUS_KEY_POLICY_WARNING_IGNORED;
	}

	TEEC_ReleaseSharedMemory(&shared_mem);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int derive_key(void *args)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	struct smw_keymgr_derive_key_args *key_args = args;

	SMW_DBG_TRACE_FUNCTION_CALL;

	switch (key_args->kdf_id) {
	case SMW_CONFIG_KDF_ID_HKDF:
		status = hkdf_derive_key(args);
		break;

	case SMW_CONFIG_KDF_ID_ECDH:
		status = ecdh_derive_key(args);
		break;

	default:
		break;
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}
