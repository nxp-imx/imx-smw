// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021 NXP
 */

#include <util.h>
#include <string.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "tee_subsystem.h"
#include "ta_keymgr.h"
#include "ta_hash.h"
#include "ta_sign_verify.h"

#define ALGORITHM_ID(_key_type_id, _security_size)                             \
	{                                                                      \
		.key_type_id = TEE_KEY_TYPE_ID_##_key_type_id,                 \
		.security_size = _security_size,                               \
		.tee_algorithm_id = TEE_ALG_##_key_type_id##_P##_security_size \
	}

#define RSA_ALGORITHM_ID(_sign_type, _rsa_algo, _hash_algo)                    \
	{                                                                      \
		.signature_type = TEE_SIGNATURE_TYPE_##_sign_type,             \
		.hash_algo = TEE_ALGORITHM_ID_##_hash_algo,                    \
		.tee_algorithm_id =                                            \
			TEE_ALG_RSASSA_PKCS1_##_rsa_algo##_##_hash_algo        \
	}

/* Key type IDs must be ordered from lowest to highest.
 * Security size must be ordered from lowest to highest
 * for 1 given Key type ID
 */
static struct {
	enum tee_key_type key_type_id;
	unsigned int security_size;
	uint32_t tee_algorithm_id;
} algorithm_ids[] = { ALGORITHM_ID(ECDSA, 192), ALGORITHM_ID(ECDSA, 224),
		      ALGORITHM_ID(ECDSA, 256), ALGORITHM_ID(ECDSA, 384),
		      ALGORITHM_ID(ECDSA, 521) };

/*
 * RSA algo must be ordered from lowest to highest.
 * Hash algo muste be ordered from lowest to hioghest for one given RSA algo.
 */
static struct {
	enum tee_signature_type signature_type;
	enum tee_algorithm_id hash_algo;
	uint32_t tee_algorithm_id;
} rsa_algorithm_ids[] = { RSA_ALGORITHM_ID(RSASSA_PKCS1_V1_5, V1_5, MD5),
			  RSA_ALGORITHM_ID(RSASSA_PKCS1_V1_5, V1_5, SHA1),
			  RSA_ALGORITHM_ID(RSASSA_PKCS1_V1_5, V1_5, SHA224),
			  RSA_ALGORITHM_ID(RSASSA_PKCS1_V1_5, V1_5, SHA256),
			  RSA_ALGORITHM_ID(RSASSA_PKCS1_V1_5, V1_5, SHA384),
			  RSA_ALGORITHM_ID(RSASSA_PKCS1_V1_5, V1_5, SHA512),
			  RSA_ALGORITHM_ID(RSASSA_PSS, PSS_MGF1, SHA1),
			  RSA_ALGORITHM_ID(RSASSA_PSS, PSS_MGF1, SHA224),
			  RSA_ALGORITHM_ID(RSASSA_PSS, PSS_MGF1, SHA256),
			  RSA_ALGORITHM_ID(RSASSA_PSS, PSS_MGF1, SHA384),
			  RSA_ALGORITHM_ID(RSASSA_PSS, PSS_MGF1, SHA512) };

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
static TEE_Result get_rsa_algo_id(enum tee_signature_type signature_type,
				  enum tee_algorithm_id hash_algo,
				  uint32_t digest_len, uint32_t *algorithm_id)
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	unsigned int i;
	unsigned int size = ARRAY_SIZE(rsa_algorithm_ids);
	enum tee_algorithm_id tee_hash_algo = hash_algo;

	FMSG("Executing %s", __func__);

	if (!algorithm_id)
		return res;

	if (tee_hash_algo == TEE_ALGORITHM_ID_INVALID) {
		res = ta_get_hash_ca_id(digest_len, &tee_hash_algo);
		if (res != TEE_SUCCESS)
			return res;
	}

	for (i = 0; i < size; i++) {
		if (rsa_algorithm_ids[i].signature_type < signature_type)
			continue;
		if (rsa_algorithm_ids[i].signature_type > signature_type)
			return TEE_ERROR_NOT_SUPPORTED;
		if (rsa_algorithm_ids[i].hash_algo < tee_hash_algo)
			continue;
		if (rsa_algorithm_ids[i].hash_algo > tee_hash_algo)
			return TEE_ERROR_NOT_SUPPORTED;

		*algorithm_id = rsa_algorithm_ids[i].tee_algorithm_id;
		break;
	}

	return TEE_SUCCESS;
}

static TEE_Result get_algorithm_id(enum tee_key_type key_type_id,
				   unsigned int security_size,
				   uint32_t *algorithm_id)
{
	unsigned int i;
	unsigned int size = ARRAY_SIZE(algorithm_ids);

	FMSG("Executing %s", __func__);

	if (!algorithm_id)
		return TEE_ERROR_BAD_PARAMETERS;

	for (i = 0; i < size; i++) {
		if (algorithm_ids[i].key_type_id < key_type_id)
			continue;
		if (algorithm_ids[i].key_type_id > key_type_id)
			return TEE_ERROR_NOT_SUPPORTED;
		if (algorithm_ids[i].security_size < security_size)
			continue;
		if (algorithm_ids[i].security_size > security_size)
			return TEE_ERROR_NOT_SUPPORTED;

		*algorithm_id = algorithm_ids[i].tee_algorithm_id;
		break;
	}

	return TEE_SUCCESS;
}

TEE_Result sign_verify(uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS],
		       uint32_t cmd_id)
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	TEE_OperationHandle operation = TEE_HANDLE_NULL;
	TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
	TEE_Attribute sign_verify_attr = { 0 };
	uint32_t param0_type = TEE_PARAM_TYPE_GET(param_types, 0);
	uint32_t exp_param3_type;
	uint32_t mode;
	unsigned int pub_key_len = 0;
	unsigned char *pub_key = NULL;
	uint32_t algorithm_id = 0;
	uint32_t hash_algo_id;
	uint32_t key_type_id;
	uint32_t security_size;
	void *digest = NULL;
	uint32_t digest_len = 0;
	bool persistent = false;
	uint32_t attr_count = 0;
	struct sign_verify_shared_params *shared_params = NULL;

	FMSG("Executing %s (%d)", __func__, cmd_id);

	if (cmd_id != CMD_SIGN && cmd_id != CMD_VERIFY)
		return res;

	/*
	 * params[0] = Key buffer or none
	 * params[1] = Pointer to sign verify shared params structure
	 * params[2] = Message buffer and message length
	 * params[3] = Signature buffer and signature length
	 */

	if (cmd_id == CMD_SIGN) {
		exp_param3_type = TEE_PARAM_TYPE_MEMREF_OUTPUT;
		mode = TEE_MODE_SIGN;
	} else { /* CMD_VERIFY */
		exp_param3_type = TEE_PARAM_TYPE_MEMREF_INPUT;
		mode = TEE_MODE_VERIFY;
	}
	if ((TEE_PARAM_TYPE_GET(param_types, 1) !=
	     TEE_PARAM_TYPE_MEMREF_INPUT) ||
	    params[1].memref.size != sizeof(*shared_params) ||
	    !params[1].memref.buffer ||
	    (TEE_PARAM_TYPE_GET(param_types, 2) !=
	     TEE_PARAM_TYPE_MEMREF_INPUT) ||
	    (TEE_PARAM_TYPE_GET(param_types, 3) != exp_param3_type))
		return res;

	shared_params = params[1].memref.buffer;
	hash_algo_id = shared_params->hash_algorithm;
	key_type_id = shared_params->key_type;
	security_size = shared_params->security_size;

	switch (param0_type) {
	case TEE_PARAM_TYPE_MEMREF_INPUT:
		pub_key = params[0].memref.buffer;
		pub_key_len = params[0].memref.size;

		if (cmd_id == CMD_SIGN) {
			EMSG("Key import not supported with Sign operation");
			return res;
		}
		res = ta_import_key(&key_handle, key_type_id, security_size,
				    NULL, 0, pub_key, pub_key_len, NULL, 0);
		if (res) {
			EMSG("Failed to import key: 0x%x", res);
			goto err;
		}

		break;

	case TEE_PARAM_TYPE_NONE:
		res = ta_get_key_handle(&key_handle, shared_params->id,
					&persistent);
		if (res) {
			EMSG("Key not found: 0x%x", res);
			goto err;
		}
		break;

	default:
		return res;
	}

	if (hash_algo_id != TEE_ALGORITHM_ID_INVALID) {
		res = ta_get_digest_length(hash_algo_id, &digest_len);
		if (res)
			goto err;

		digest = TEE_Malloc(digest_len, TEE_USER_MEM_HINT_NO_FILL_ZERO);
		if (digest) {
			res = ta_compute_digest(hash_algo_id,
						params[2].memref.buffer,
						params[2].memref.size, digest,
						&digest_len);
		} else {
			EMSG("TEE_Malloc failed");
			res = TEE_ERROR_OUT_OF_MEMORY;
		}

		if (res)
			goto err;
	} else {
		digest = params[2].memref.buffer;
		digest_len = params[2].memref.size;
	}

	/* Get TEE algorithm ID */
	if (key_type_id == TEE_KEY_TYPE_ID_RSA) {
		res = get_rsa_algo_id(shared_params->signature_type,
				      hash_algo_id, digest_len, &algorithm_id);

		/* Set salt length attribute if needed */
		if (!res && shared_params->salt_length) {
			TEE_InitValueAttribute(&sign_verify_attr,
					       TEE_ATTR_RSA_PSS_SALT_LENGTH,
					       shared_params->salt_length, 0);
			attr_count = 1;
		}
	} else {
		res = get_algorithm_id(key_type_id, security_size,
				       &algorithm_id);
	}

	if (res) {
		EMSG("Failed to get algorithm ID: 0x%x", res);
		goto err;
	}

	res = TEE_AllocateOperation(&operation, algorithm_id, mode,
				    security_size);
	if (res) {
		EMSG("Failed to alloc operation: 0x%x", res);
		goto err;
	}

	res = TEE_SetOperationKey(operation, key_handle);
	if (res) {
		EMSG("Failed to set operation key: 0x%x", res);
		goto err;
	}

	if (cmd_id == CMD_SIGN) {
		res = TEE_AsymmetricSignDigest(operation, &sign_verify_attr,
					       attr_count, digest, digest_len,
					       params[3].memref.buffer,
					       &params[3].memref.size);
		if (res)
			EMSG("Failed to sign digest: 0x%x", res);
	} else { /* CMD_VERIFY */
		res = TEE_AsymmetricVerifyDigest(operation, &sign_verify_attr,
						 attr_count, digest, digest_len,
						 params[3].memref.buffer,
						 params[3].memref.size);
		if (res)
			EMSG("Failed to verify digest: 0x%x", res);
	}

err:
	if (key_handle != TEE_HANDLE_NULL) {
		if (persistent)
			TEE_CloseObject(key_handle);
		else if (param0_type == TEE_PARAM_TYPE_MEMREF_INPUT)
			TEE_FreeTransientObject(key_handle);
	}

	if (hash_algo_id != TEE_ALGORITHM_ID_INVALID && digest)
		if (digest)
			TEE_Free(digest);

	if (operation != TEE_HANDLE_NULL)
		TEE_FreeOperation(operation);

	return res;
}
