// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include <util.h>
#include <string.h>
#include <tee_internal_api_extensions.h>

#include "common.h"
#include "tee_subsystem.h"
#include "keymgr.h"
#include "asymmetric_encryption.h"
#include "obj.h"

#define RSA_OAEP_ALGO_ID(_hash_algo)                                           \
	{                                                                      \
		.mode = TEE_ASYMM_ENC_MODE_RSAES_PKCS1_OAEP,                   \
		.hash_algo = TEE_ALGORITHM_ID_##_hash_algo,                    \
		.tee_algorithm_id = TEE_ALG_RSAES_PKCS1_OAEP_MGF1_##_hash_algo \
	}

static const struct {
	enum tee_asymm_enc_mode mode;
	enum tee_algorithm_id hash_algo;
	uint32_t tee_algorithm_id;
} rsa_algorithm_ids[] = { RSA_OAEP_ALGO_ID(SHA1),
			  RSA_OAEP_ALGO_ID(SHA224),
			  RSA_OAEP_ALGO_ID(SHA256),
			  RSA_OAEP_ALGO_ID(SHA384),
			  RSA_OAEP_ALGO_ID(SHA512),
			  { TEE_ASYMM_ENC_MODE_RSAES_PKCS1_V1_5,
			    TEE_ALGORITHM_ID_INVALID,
			    TEE_ALG_RSAES_PKCS1_V1_5 },
			  { TEE_ASYMM_ENC_MODE_RSA_NOPAD,
			    TEE_ALGORITHM_ID_INVALID, TEE_ALG_RSA_NOPAD } };

/**
 * get_rsa_algo_id() - Get sign verify algorithm ID from RSA key type.
 * @signature_type: Signature type.
 * @hash_algo: Hash algorithm used for the operation.
 * @digest_len: Length of the operation hashed message in bytes.
 * @algorithm_id: Pointer to the algorithm ID variable to update.
 *
 * If @hash_algo is TEE_ALGORITHM_ID_INVALID, @digest_len must be set. Else,
 * @digest_len is not necessary.
 *
 * Return:
 * TEE_SUCCESS			- Success.
 * TEE_ERROR_BAD_PARAMETERS	- One of the parameter is invalid.
 * TEE_ERROR_NOT_SUPPORTED	- Operation not supported.
 */
static TEE_Result get_rsa_algo_id(enum tee_asymm_enc_mode mode,
				  enum tee_algorithm_id hash_algo,
				  uint32_t *algorithm_id)
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	unsigned int i = 0;
	unsigned int size = ARRAY_SIZE(rsa_algorithm_ids);

	FMSG("Executing %s", __func__);

	if (!algorithm_id)
		goto end;

	for (; i < size; i++) {
		if (rsa_algorithm_ids[i].mode == mode &&
		    ((rsa_algorithm_ids[i].mode !=
			      TEE_ASYMM_ENC_MODE_RSAES_PKCS1_OAEP &&
		      rsa_algorithm_ids[i].hash_algo ==
			      TEE_ALGORITHM_ID_INVALID) ||
		     rsa_algorithm_ids[i].hash_algo == hash_algo)) {
			*algorithm_id = rsa_algorithm_ids[i].tee_algorithm_id;
			res = TEE_SUCCESS;
			break;
		}
	}

end:
	return res;
}

/**
 * set_key() - Set key handle for asymmetric encryption and decryption operation
 * @cmd_id: Command ID.
 * @ta_param: TA parameter. Contains key buffer or nothing.
 * @ta_param_type: @ta_param type.
 * @shared_params: Pointer to Asymmetric encryption shared parameters structure.
 * @key_handle: Pointer to key handle to update.
 * @persistent: Pointer to key info to update.
 * @algo_id: TEE algorithm ID
 *
 * If key is defined as buffer, it is imported as a new transient object. This
 * new key handle is returned and the key is deleted at the end of the
 * operation.
 * If key is defined as key ID, key handle is retrieved.
 *
 * Return:
 * TEE_SUCCESS              - Success.
 * TEE_ERROR_BAD_PARAMETERS	- One of the parameters is invalid.
 * Error code from ta_import_key().
 * Error code from ta_get_obj_handle().
 */
static TEE_Result set_key(uint32_t cmd_id, TEE_Param ta_param,
			  uint32_t ta_param_type,
			  struct asymm_enc_shared_params *shared_params,
			  TEE_ObjectHandle *key_handle, bool *persistent,
			  uint32_t algo_id)
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	unsigned char *pub_key = NULL;
	unsigned char *priv_key = NULL;
	unsigned char *modulus = NULL;
	unsigned char *ptr = NULL;
	size_t priv_key_len = 0;
	size_t modulus_len = 0;
	size_t key_size = BITS_TO_BYTES_SIZE(shared_params->security_size);
	uint32_t key_usage = 0;

	FMSG("Executing %s", __func__);

	switch (ta_param_type) {
	case TEE_PARAM_TYPE_MEMREF_INPUT:
		/* Set key buffers and lengths */
		pub_key = ta_param.memref.buffer;

		ptr = pub_key + shared_params->pub_key_len;

		if (cmd_id == CMD_ASYMM_ENCRYPT) {
			key_usage = TEE_USAGE_ENCRYPT;

			if (algo_id == TEE_ALG_RSA_NOPAD)
				key_usage |= TEE_USAGE_VERIFY;
		} else {
			priv_key = ptr;
			priv_key_len = key_size;
			ptr = priv_key + priv_key_len;
			key_usage = TEE_USAGE_DECRYPT;

			if (algo_id == TEE_ALG_RSA_NOPAD)
				key_usage |= TEE_USAGE_SIGN;
		}

		if (shared_params->key_type == TEE_KEY_TYPE_ID_RSA) {
			modulus = ptr;
			modulus_len = key_size;
		}

		/* Import key */
		res = ta_import_key(key_handle, shared_params->key_type,
				    shared_params->security_size, key_usage,
				    priv_key, priv_key_len, pub_key,
				    shared_params->pub_key_len, modulus,
				    modulus_len);
		if (res)
			EMSG("Failed to import key: 0x%x", res);

		return res;

	case TEE_PARAM_TYPE_NONE:
		EMSG("Retrieve key handle");
		res = ta_get_obj_handle(key_handle, shared_params->id,
					persistent);
		if (res)
			EMSG("Key not found: 0x%x", res);

		return res;

	default:
		return res;
	}
}

TEE_Result asymm_encrypt_decrypt(uint32_t param_types,
				 TEE_Param params[TEE_NUM_PARAMS],
				 uint32_t cmd_id)
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	TEE_OperationHandle operation = TEE_HANDLE_NULL;
	TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
	TEE_Attribute attr = { 0 };
	TEE_ObjectInfo key_info = { 0 };
	uint32_t param0_type = TEE_PARAM_TYPE_GET(param_types, 0);
	uint32_t mode = 0;
	uint32_t algorithm_id = 0;
	bool persistent = false;
	struct asymm_enc_shared_params *shared_params = NULL;
	uint32_t op_max_key_size = 0;
	uint32_t attr_count = 1;
	size_t size = 0;

	FMSG("Executing %s (%d)", __func__, cmd_id);

	/*
	 * params[0] = Key buffer or none
	 * params[1] = Pointer to asymmetric encrypt/decrypt shared params structure
	 * params[2] = Input buffer and length
	 * params[3] = Output buffer and length
	 */

	if (cmd_id == CMD_ASYMM_ENCRYPT)
		mode = TEE_MODE_ENCRYPT;
	else
		mode = TEE_MODE_DECRYPT;

	if ((TEE_PARAM_TYPE_GET(param_types, 1) !=
	     TEE_PARAM_TYPE_MEMREF_INPUT) ||
	    params[1].memref.size < sizeof(*shared_params) ||
	    !params[1].memref.buffer ||
	    (TEE_PARAM_TYPE_GET(param_types, 2) !=
	     TEE_PARAM_TYPE_MEMREF_INPUT) ||
	    (TEE_PARAM_TYPE_GET(param_types, 3) !=
	     TEE_PARAM_TYPE_MEMREF_OUTPUT))
		goto err;

	shared_params = params[1].memref.buffer;

	if (ADD_OVERFLOW(sizeof(*shared_params), shared_params->salt_length,
			 &size))
		goto err;

	if (params[1].memref.size != size)
		goto err;

	op_max_key_size = shared_params->security_size;

	/* Get TEE algorithm ID */
	if (shared_params->key_type == TEE_KEY_TYPE_ID_RSA) {
		res = get_rsa_algo_id(shared_params->mode,
				      shared_params->hash_algorithm,
				      &algorithm_id);

		if (res) {
			EMSG("Failed to get algorithm ID: 0x%x", res);
			goto err;
		}

		/* Set salt length attribute if needed */
		if (shared_params->salt_length) {
			TEE_InitRefAttribute(&attr, TEE_ATTR_RSA_OAEP_LABEL,
					     shared_params->salt,
					     shared_params->salt_length);
		}
	} else {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto err;
	}

	res = set_key(cmd_id, params[0], param0_type, shared_params,
		      &key_handle, &persistent, algorithm_id);
	if (res)
		goto err;

	res = TEE_AllocateOperation(&operation, algorithm_id, mode,
				    op_max_key_size);
	if (res) {
		EMSG("Failed to alloc operation: 0x%x", res);
		goto err;
	}

	res = TEE_GetObjectInfo1(key_handle, &key_info);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to get key info (0x%x)", res);
		goto err;
	}

	res = check_operation_keys_usage(operation, &key_info, 1);
	if (res)
		goto err;

	res = TEE_SetOperationKey(operation, key_handle);
	if (res) {
		EMSG("Failed to set operation key: 0x%x", res);
		goto err;
	}

	if (cmd_id == CMD_ASYMM_ENCRYPT) {
		res = TEE_AsymmetricEncrypt(operation, &attr, attr_count,
					    params[2].memref.buffer,
					    params[2].memref.size,
					    params[3].memref.buffer,
					    &params[3].memref.size);
		if (res)
			EMSG("Failed to perform TEE_AsymmetricEncrypt: 0x%x",
			     res);
	} else {
		res = TEE_AsymmetricDecrypt(operation, &attr, attr_count,
					    params[2].memref.buffer,
					    params[2].memref.size,
					    params[3].memref.buffer,
					    &params[3].memref.size);
		if (res)
			EMSG("Failed to perform TEE_AsymmetricDecrypt: 0x%x",
			     res);
	}

err:
	if (key_handle != TEE_HANDLE_NULL) {
		if (persistent)
			TEE_CloseObject(key_handle);
		else if (param0_type == TEE_PARAM_TYPE_MEMREF_INPUT)
			TEE_FreeTransientObject(key_handle);
	}

	if (operation != TEE_HANDLE_NULL)
		TEE_FreeOperation(operation);

	return res;
}
