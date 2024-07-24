// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024 NXP
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
			       struct smw_keymgr_hkdf_args *hkdf_args,
			       struct key_derive_shared_params *shared_params)
{
	void *buffer = shared_mem->buffer;
	unsigned char *salt = smw_keymgr_get_salt(hkdf_args);
	unsigned char *info = smw_keymgr_get_info(hkdf_args);

	if (salt)
		SMW_UTILS_MEMCPY(buffer, salt, shared_params->salt_length);

	if (info)
		SMW_UTILS_MEMCPY(buffer + shared_params->salt_length, info,
				 shared_params->info_length);
}

/**
 * is_key_type_supported() - Check if key type is supported for key derivation.
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
static bool is_key_type_supported(enum smw_config_key_type_id type_id,
				  enum smw_config_kdf_id kdf_id)
{
	bool status = false;

	if (kdf_id == SMW_CONFIG_KDF_HKDF) {
		switch (type_id) {
		case SMW_CONFIG_KEY_TYPE_ID_AES:
		case SMW_CONFIG_KEY_TYPE_ID_DES:
		case SMW_CONFIG_KEY_TYPE_ID_DES3:
		case SMW_CONFIG_KEY_TYPE_ID_SM4:
		case SMW_CONFIG_KEY_TYPE_ID_HMAC:
		case SMW_CONFIG_KEY_TYPE_ID_HMAC_MD5:
		case SMW_CONFIG_KEY_TYPE_ID_HMAC_SHA1:
		case SMW_CONFIG_KEY_TYPE_ID_HMAC_SHA224:
		case SMW_CONFIG_KEY_TYPE_ID_HMAC_SHA256:
		case SMW_CONFIG_KEY_TYPE_ID_HMAC_SHA384:
		case SMW_CONFIG_KEY_TYPE_ID_HMAC_SHA512:
		case SMW_CONFIG_KEY_TYPE_ID_HMAC_SM3:
		case SMW_CONFIG_KEY_TYPE_ID_GENERIC_SECRET:
			status = true;
			break;

		default:
			break;
		}
	}

	return status;
}

/**
 * get_derived_key_length() - Get the derived key length.
 * @key_len: Pointer to derived key length.
 * @okm_len: Output key material (derived key) length set by the user.
 * @key_derived: Pointer to internal derived key descriptor structure.
 *
 * Return:
 * SMW_STATUS_OK                - Success.
 * SMW_STATUS_INVALID_PARAM	    - One of the parameters is invalid.
 * SMW_STATUS_OUTPUT_TOO_SHORT  - Output buffer is too short
 */
static int
get_derived_key_length(unsigned int *key_len, unsigned int okm_len,
		       struct smw_keymgr_derived_key_desc *key_derived)
{
	int status = SMW_STATUS_INVALID_PARAM;

	unsigned int shared_secret_len =
		smw_keymgr_get_shared_secret_len(key_derived);

	if (!okm_len && !shared_secret_len) {
		SMW_DBG_PRINTF(ERROR,
			       "%s: shared secret and OKM length are set to 0",
			       __func__);
		goto end;
	}

	if (smw_keymgr_get_shared_secret_buffer(key_derived) &&
	    shared_secret_len < okm_len) {
		*key_len = okm_len;
		status = SMW_STATUS_OUTPUT_TOO_SHORT;
		goto end;
	}

	if (okm_len)
		*key_len = okm_len;
	else if (shared_secret_len)
		*key_len = shared_secret_len;

	status = SMW_STATUS_OK;

end:
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
 * SMW_STATUS_OK                - Success.
 * SMW_STATUS_INVALID_PARAM     - One of the parameters is invalid.
 * SMW_STATUS_ALLOC_FAILURE     - Memory allocation failure.
 * SMW_STATUS_OUTPUT_TOO_SHORT  - Output buffer is too short
 * SMW_STATUS_OPERATION_FAILURE - Operation failed
 * SMW_STATUS_SUBSYSTEM_FAILURE - Subsytem failed.
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
	struct smw_key_attributes *key_attrs = NULL;
	smw_attr_usage_t actual_usage_flags = 0;

	unsigned int key_len = 0;
	unsigned int okm_len = 0;
	unsigned char *key_base = NULL;
	unsigned char *key_derived = NULL;
	unsigned char *hex_key_base = NULL;
	unsigned int key_base_len = 0;
	unsigned int hex_key_base_len = 0;
	size_t size = 0;
	unsigned int temp_len = 0;
	unsigned char *buf = NULL;

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

	if (!is_key_type_supported(key_id_base->type_id, key_args->kdf_id)) {
		SMW_DBG_PRINTF(ERROR, "%s unsupported key type\n", __func__);
		status = SMW_STATUS_INVALID_PARAM;
		goto exit;
	}

	if (smw_keymgr_get_hkdf_step(hkdf_args) != HKDF_STEP_FULL) {
		status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
		goto exit;
	}

	status = get_tee_hkdf_algo_id(hkdf_args->prf_id,
				      &shared_params.hash_algo);
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
	}

	okm_len = smw_keymgr_get_okm_len(hkdf_args);
	status = get_derived_key_length(&key_len, okm_len,
					&key_args->key_derived);
	if (status == SMW_STATUS_OUTPUT_TOO_SHORT) {
		temp_status =
			smw_keymgr_update_shared_secret(&key_args->key_derived,
							NULL, key_len);
		if (temp_status != SMW_STATUS_OK)
			status = temp_status;
	}

	if (status != SMW_STATUS_OK)
		goto exit;

	if (key_id_derived->security_size) {
		shared_params.derived_key_sec_size =
			key_id_derived->security_size;
	} else {
		if (MUL_OVERFLOW(key_len, 8,
				 &shared_params.derived_key_sec_size)) {
			status = SMW_STATUS_INVALID_PARAM;
			goto exit;
		}
	}

	/*
	 * params[0] = Pointer to derive key shared params structure.
	 * params[1] = Pointer to base key buffer or none.
	 * params[2] = Pointer to derived key buffer or none.
	 * params[3] = Salt/info buffer or none.
	 */

	shared_params.derived_key_id = key_id_derived->id;
	shared_params.base_key_id = key_id_base->id;
	shared_params.salt_length = smw_keymgr_get_salt_len(hkdf_args);
	shared_params.info_length = smw_keymgr_get_info_len(hkdf_args);
	shared_params.base_key_sec_size = key_id_base->security_size;

	op.params[DER_SHARED_PARAM_IDX].tmpref.buffer = &shared_params;
	op.params[DER_SHARED_PARAM_IDX].tmpref.size = sizeof(shared_params);

	SET_TEEC_PARAMS_TYPE(op.paramTypes, TEEC_MEMREF_TEMP_INPUT,
			     DER_SHARED_PARAM_IDX);

	if (shared_params.base_key_id == INVALID_KEY_ID) {
		key_base = smw_keymgr_get_private_data(&key_args->key_base);
		key_base_len =
			smw_keymgr_get_private_length(&key_args->key_base);

		if (!key_base || !key_base_len) {
			status = SMW_STATUS_INVALID_PARAM;
			goto exit;
		}
	}

	status = set_hex_buffer(key_args->key_base.format_id, key_base,
				key_base_len, &hex_key_base, &hex_key_base_len);
	if (status != SMW_STATUS_OK)
		goto exit;

	status = set_tmpref_buffer(TEEC_MEMREF_TEMP_INPUT,
				   DER_BASE_KEY_PARAM_IDX, hex_key_base,
				   hex_key_base_len, &op);

	buf = smw_keymgr_get_shared_secret_buffer(&key_args->key_derived);
	if (buf)
		temp_len = key_len;

	status = set_tmpref_buffer(TEEC_MEMREF_TEMP_OUTPUT,
				   DER_DERIVED_KEY_PARAM_IDX, buf, temp_len,
				   &op);

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

		fill_shared_memory(&shared_mem, hkdf_args, &shared_params);

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

	/* Update derived key_identifier struct */
	key_id_derived->subsystem_id = SUBSYSTEM_ID_TEE;
	key_id_derived->id = shared_params.derived_key_id;
	key_id_derived->type_id = SMW_CONFIG_KEY_TYPE_ID_GENERIC_SECRET;
	key_id_derived->security_size = shared_params.derived_key_sec_size;
	status = smw_keymgr_get_privacy_id(key_id_derived->type_id,
					   &key_id_derived->privacy_id);
	if (status != SMW_STATUS_OK)
		goto exit;

	if (SET_OVERFLOW(op.params[DER_DERIVED_KEY_PARAM_IDX].tmpref.size,
			 key_len)) {
		status = SMW_STATUS_OPERATION_FAILURE;
		goto exit;
	}

	SMW_DBG_PRINTF(DEBUG, "%s: Key #%d is generated.\n", __func__,
		       key_id_derived->id);

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
	case SMW_CONFIG_KDF_HKDF:
		status = hkdf_derive_key(args);
		break;

	default:
		break;
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}
