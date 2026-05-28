// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2026 NXP
 */

#include <util.h>
#include <string.h>
#include <tee_internal_api_extensions.h>
#include <utee_defines.h>

#include "common.h"
#include "tee_subsystem.h"
#include "keymgr.h"
#include "hash.h"
#include "sign_verify.h"
#include "obj.h"

static const uint8_t sm2_a_b_xg_yg[] = {
	/* a */
	0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC,
	/* b */
	0x28, 0xE9, 0xFA, 0x9E, 0x9D, 0x9F, 0x5E, 0x34, 0x4D, 0x5A, 0x9E, 0x4B,
	0xCF, 0x65, 0x09, 0xA7, 0xF3, 0x97, 0x89, 0xF5, 0x15, 0xAB, 0x8F, 0x92,
	0xDD, 0xBC, 0xBD, 0x41, 0x4D, 0x94, 0x0E, 0x93,
	/* xg */
	0x32, 0xC4, 0xAE, 0x2C, 0x1F, 0x19, 0x81, 0x19, 0x5F, 0x99, 0x04, 0x46,
	0x6A, 0x39, 0xC9, 0x94, 0x8F, 0xE3, 0x0B, 0xBF, 0xF2, 0x66, 0x0B, 0xE1,
	0x71, 0x5A, 0x45, 0x89, 0x33, 0x4C, 0x74, 0xC7,
	/* yg */
	0xBC, 0x37, 0x36, 0xA2, 0xF4, 0xF6, 0x77, 0x9C, 0x59, 0xBD, 0xCE, 0xE3,
	0x6B, 0x69, 0x21, 0x53, 0xD0, 0xA9, 0x87, 0x7C, 0xC6, 0x2A, 0x47, 0x40,
	0x02, 0xDF, 0x32, 0xE5, 0x21, 0x39, 0xF0, 0xA0
};

#define ECDSA_ALGORITHM_ID(_security_size, _hash_algo)                         \
	{                                                                      \
		.security_size = _security_size,                               \
		.tee_algorithm_id = TEE_ALG_ECDSA_##_hash_algo                 \
	}

#define RSA_ALGORITHM_ID(_sign_type, _rsa_algo, _hash_algo)                    \
	{                                                                      \
		.signature_type = TEE_SIGNATURE_TYPE_##_sign_type,             \
		.hash_algo = TEE_ALGORITHM_ID_##_hash_algo,                    \
		.tee_algorithm_id =                                            \
			TEE_ALG_RSASSA_PKCS1_##_rsa_algo##_##_hash_algo        \
	}

/* Security size must be ordered from lowest to highest */
static const struct {
	unsigned int security_size;
	uint32_t tee_algorithm_id;
} ecdsa_algorithm_ids[] = { ECDSA_ALGORITHM_ID(192, SHA1),
			    ECDSA_ALGORITHM_ID(224, SHA224),
			    ECDSA_ALGORITHM_ID(256, SHA256),
			    ECDSA_ALGORITHM_ID(384, SHA384),
			    ECDSA_ALGORITHM_ID(521, SHA512) };

/*
 * RSA algo must be ordered from lowest to highest.
 * Hash algo muste be ordered from lowest to hioghest for one given RSA algo.
 */
static const struct {
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
				  size_t digest_len,
				  enum tee_algorithm_id *algorithm_id)
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	unsigned int i = 0;
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

	for (; i < size; i++) {
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

static TEE_Result get_ecdsa_algo_id(unsigned int security_size,
				    enum tee_algorithm_id *algorithm_id)
{
	unsigned int i = 0;
	unsigned int size = ARRAY_SIZE(ecdsa_algorithm_ids);

	FMSG("Executing %s", __func__);

	if (!algorithm_id)
		return TEE_ERROR_BAD_PARAMETERS;

	for (; i < size; i++) {
		if (ecdsa_algorithm_ids[i].security_size < security_size)
			continue;
		if (ecdsa_algorithm_ids[i].security_size > security_size)
			return TEE_ERROR_NOT_SUPPORTED;

		*algorithm_id = ecdsa_algorithm_ids[i].tee_algorithm_id;
		break;
	}

	return TEE_SUCCESS;
}

/**
 * set_key() - Set key handle for signature operation.
 * @cmd_id: Command ID.
 * @ta_param: TA parameter. Contains key buffer or nothing.
 * @ta_param_type: @ta_param type.
 * @shared_params: Pointer to signature operation shared parameters structure.
 * @key_handle: Pointer to key handle to update.
 * @persistent: Pointer to key info to update.
 *
 * If key is defined as buffer, it is imported as a new transient object. This
 * new key handle is returned and the key is deleted at the end of the signature
 * operation.
 * If key is defined as key ID, key handle is retrieved.
 *
 * Return:
 * TEE_SUCCESS			- Success.
 * TEE_ERROR_BAD_PARAMETERS	- One of the parameters is invalid.
 * Error code from ta_import_key().
 * Error code from ta_get_obj_handle().
 */
static TEE_Result set_key(uint32_t cmd_id, TEE_Param ta_param,
			  uint32_t ta_param_type,
			  struct sign_verify_shared_params *shared_params,
			  TEE_ObjectHandle *key_handle, bool *persistent)
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

		if (cmd_id == CMD_SIGN) {
			priv_key = ptr;
			priv_key_len = key_size;
			ptr = priv_key + priv_key_len;
			key_usage = TEE_USAGE_SIGN;
		} else {
			key_usage = TEE_USAGE_VERIFY;
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
		if (res != TEE_SUCCESS)
			EMSG("Failed to import key: 0x%x", res);

		return res;

	case TEE_PARAM_TYPE_NONE:
		/* Retrieve key handle */
		res = ta_get_obj_handle(key_handle, shared_params->id,
					persistent);
		if (res != TEE_SUCCESS)
			EMSG("Key not found: 0x%x", res);

		return res;

	default:
		return res;
	}
}

static TEE_Result set_sm2_digest(TEE_ObjectHandle key_handle,
				 enum tee_algorithm_id hash_algo, void *msg,
				 size_t msg_len, uint8_t *id, uint16_t id_len,
				 uint8_t *digest, size_t *digest_len)
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	uint8_t *p = NULL;
	uint8_t *buf = NULL;
	size_t buf_len = 2;
	unsigned char *pub_key = NULL;
	size_t pub_key_size = 0;
	uint8_t *za = NULL;
	size_t za_len = TEE_SM3_HASH_SIZE;

	FMSG("Executing %s", __func__);

	if (ADD_OVERFLOW(za_len, msg_len, &za_len))
		goto err;

	res = get_ecc_public_key_size(key_handle, &pub_key_size);
	if (res != TEE_SUCCESS)
		return res;

	pub_key = TEE_Malloc(pub_key_size, TEE_USER_MEM_HINT_NO_FILL_ZERO);
	if (!pub_key) {
		EMSG("TEE_Malloc failed");
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto err;
	}

	/* Get public key buffer */
	res = export_public_key(key_handle, pub_key, &pub_key_size, NULL, NULL);
	if (res != TEE_SUCCESS || !pub_key || !pub_key_size)
		goto err;

	/* Concatenate ENTLA || IDA || a || b || xG || yG || xA || yA */
	if (ADD_OVERFLOW(buf_len, id_len, &buf_len)) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto err;
	}
	if (ADD_OVERFLOW(buf_len, ARRAY_SIZE(sm2_a_b_xg_yg), &buf_len)) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto err;
	}
	if (ADD_OVERFLOW(buf_len, pub_key_size, &buf_len)) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto err;
	}

	buf = TEE_Malloc(buf_len, TEE_USER_MEM_HINT_NO_FILL_ZERO);
	if (!buf) {
		EMSG("TEE_Malloc failed");
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto err;
	}

	p = buf;
	*p++ = ((id_len << 3) >> 8) & 0xFF;
	*p++ = (id_len << 3) & 0xFF;
	TEE_MemMove(p, id, id_len);
	p += id_len;
	TEE_MemMove(p, sm2_a_b_xg_yg, ARRAY_SIZE(sm2_a_b_xg_yg));
	p += ARRAY_SIZE(sm2_a_b_xg_yg);
	TEE_MemMove(p, pub_key, pub_key_size);

	/* Compute ZA = H256(ENTLA || IDA || a || b || xG || yG || xA || yA) */
	za = TEE_Malloc(za_len, TEE_USER_MEM_HINT_NO_FILL_ZERO);
	if (!za) {
		EMSG("TEE_Malloc failed");
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto err;
	}

	res = ta_compute_digest(hash_algo, buf, buf_len, za, &za_len);
	if (res != TEE_SUCCESS)
		goto err;

	if (za_len != TEE_SM3_HASH_SIZE) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto err;
	}

	/* Concatenate ZA || M */
	TEE_MemMove(za + za_len, msg, msg_len);

	/* Compute e = H256(ZA || M) */
	res = ta_compute_digest(hash_algo, za, za_len + msg_len, digest,
				digest_len);

err:
	if (pub_key)
		TEE_Free(pub_key);

	if (buf)
		TEE_Free(buf);

	if (za)
		TEE_Free(za);

	return res;
}

TEE_Result sign_verify(uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS],
		       uint32_t cmd_id)
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	TEE_OperationHandle operation = TEE_HANDLE_NULL;
	TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
	TEE_Attribute sign_verify_attr[2] = { 0 };
	TEE_ObjectInfo key_info = { 0 };
	uint32_t param0_type = TEE_PARAM_TYPE_GET(param_types, 0);
	uint32_t exp_param3_type = 0;
	uint32_t mode = 0;
	enum tee_algorithm_id algorithm_id = 0;
	enum tee_algorithm_id hash_algo = TEE_ALGORITHM_ID_INVALID;
	uint8_t *digest = NULL;
	size_t digest_len = 0;
	uint8_t *buf = NULL;
	size_t sign_len = 0;
	bool persistent = false;
	uint32_t attr_count = 0;
	struct sign_verify_shared_params *shared_params = NULL;
	uint32_t op_max_key_size = 0;
	bool sm2_compute_digest = false;

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
	    params[1].memref.size < sizeof(*shared_params) ||
	    !params[1].memref.buffer ||
	    (TEE_PARAM_TYPE_GET(param_types, 2) !=
	     TEE_PARAM_TYPE_MEMREF_INPUT) ||
	    (TEE_PARAM_TYPE_GET(param_types, 3) != exp_param3_type))
		return res;

	shared_params = params[1].memref.buffer;

	if (shared_params->sign_algorithm == TEE_ALGORITHM_ID_EDDSA &&
	    params[1].memref.size !=
		    sizeof(*shared_params) + shared_params->ctx_length)
		return res;

	if (shared_params->sign_algorithm == TEE_ALGORITHM_ID_SM2) {
		if (params[1].memref.size !=
		    sizeof(*shared_params) + shared_params->identifier_length) {
			return res;
		} else if (shared_params->identifier_length != 0) {
			if (shared_params->msg_hashed)
				return res;

			sm2_compute_digest = true;
		} else if (!shared_params->msg_hashed) {
			return res;
		}
	}

	res = set_key(cmd_id, params[0], param0_type, shared_params,
		      &key_handle, &persistent);
	if (res != TEE_SUCCESS)
		goto err;

	if (!shared_params->msg_hashed)
		hash_algo = shared_params->hash_algorithm;

	if (sm2_compute_digest) {
		res = ta_get_digest_length(hash_algo, &digest_len);
		if (res != TEE_SUCCESS)
			goto err;

		buf = TEE_Malloc(digest_len, TEE_USER_MEM_HINT_NO_FILL_ZERO);
		if (!buf) {
			EMSG("TEE_Malloc failed");
			res = TEE_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		res = set_sm2_digest(key_handle, hash_algo,
				     params[2].memref.buffer,
				     params[2].memref.size,
				     shared_params->identifier,
				     shared_params->identifier_length, buf,
				     &digest_len);
		if (res != TEE_SUCCESS)
			goto err;

		digest = buf;
	} else if (hash_algo != TEE_ALGORITHM_ID_INVALID) {
		res = ta_get_digest_length(hash_algo, &digest_len);
		if (res != TEE_SUCCESS)
			goto err;

		buf = TEE_Malloc(digest_len, TEE_USER_MEM_HINT_NO_FILL_ZERO);
		if (!buf) {
			EMSG("TEE_Malloc failed");
			res = TEE_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		res = ta_compute_digest(hash_algo, params[2].memref.buffer,
					params[2].memref.size, buf,
					&digest_len);
		if (res != TEE_SUCCESS)
			goto err;

		digest = buf;
	} else {
		digest = params[2].memref.buffer;
		digest_len = params[2].memref.size;
	}

	op_max_key_size = shared_params->security_size;

	/* Get TEE algorithm ID */
	switch (shared_params->sign_algorithm) {
	case TEE_ALGORITHM_ID_RSA:
		res = get_rsa_algo_id(shared_params->signature_type, hash_algo,
				      digest_len, &algorithm_id);

		if (!res)
			break;

		/* Set salt length attribute if needed */
		if (shared_params->salt_length) {
			TEE_InitValueAttribute(&sign_verify_attr[attr_count],
					       TEE_ATTR_RSA_PSS_SALT_LENGTH,
					       shared_params->salt_length, 0);
			attr_count++;
		}

		break;

	case TEE_ALGORITHM_ID_EDDSA:
		algorithm_id = TEE_ALG_ED25519;

		if (ROUNDUP_OVERFLOW(op_max_key_size, 2, &op_max_key_size)) {
			res = TEE_ERROR_GENERIC;
			goto err;
		}

		if (shared_params->signature_type ==
		    TEE_SIGNATURE_TYPE_EDDSA_PH) {
			TEE_InitValueAttribute(&sign_verify_attr[attr_count],
					       TEE_ATTR_EDDSA_PREHASH, 1, 0);
			attr_count++;
		}

		if ((shared_params->signature_type ==
			     TEE_SIGNATURE_TYPE_EDDSA_CTX ||
		     shared_params->signature_type ==
			     TEE_SIGNATURE_TYPE_EDDSA_PH) &&
		    shared_params->ctx_length) {
			TEE_InitRefAttribute(&sign_verify_attr[attr_count],
					     TEE_ATTR_EDDSA_CTX,
					     shared_params->ctx,
					     shared_params->ctx_length);
			attr_count++;
		}

		/* Workaround the TA dead */
		if (cmd_id == CMD_SIGN && params[3].memref.buffer) {
			res = ta_get_digest_length(TEE_ALGORITHM_ID_SHA512,
						   &sign_len);
			if (res != TEE_SUCCESS)
				goto err;

			if (params[3].memref.size < sign_len) {
				params[3].memref.size = sign_len;
				res = TEE_ERROR_SHORT_BUFFER;
				goto err;
			}
		}
		break;

	case TEE_ALGORITHM_ID_ECDSA:
		res = get_ecdsa_algo_id(shared_params->security_size,
					&algorithm_id);
		break;

	case TEE_ALGORITHM_ID_SM2:
		if (shared_params->hash_algorithm == TEE_ALGORITHM_ID_SM3)
			algorithm_id = TEE_ALG_SM2_DSA_SM3;
		break;

	default:
		res = TEE_ERROR_NOT_SUPPORTED;
		break;
	}

	if (res != TEE_SUCCESS) {
		EMSG("Failed to get algorithm ID: 0x%x", res);
		goto err;
	}

	res = TEE_AllocateOperation(&operation, algorithm_id, mode,
				    op_max_key_size);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to alloc operation: 0x%x", res);
		goto err;
	}

	res = TEE_GetObjectInfo1(key_handle, &key_info);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to get key info (0x%x)", res);
		goto err;
	}

	res = check_operation_keys_usage(operation, &key_info, 1);
	if (res != TEE_SUCCESS)
		goto err;

	res = TEE_SetOperationKey(operation, key_handle);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to set operation key: 0x%x", res);
		goto err;
	}

	if (cmd_id == CMD_SIGN) {
		res = TEE_AsymmetricSignDigest(operation, sign_verify_attr,
					       attr_count, digest, digest_len,
					       params[3].memref.buffer,
					       &params[3].memref.size);
		if (res != TEE_SUCCESS)
			EMSG("Failed to sign digest: 0x%x", res);
	} else { /* CMD_VERIFY */
		res = TEE_AsymmetricVerifyDigest(operation, sign_verify_attr,
						 attr_count, digest, digest_len,
						 params[3].memref.buffer,
						 params[3].memref.size);
		if (res != TEE_SUCCESS)
			EMSG("Failed to verify digest: 0x%x", res);
	}

err:
	if (key_handle != TEE_HANDLE_NULL) {
		if (persistent)
			TEE_CloseObject(key_handle);
		else if (param0_type == TEE_PARAM_TYPE_MEMREF_INPUT)
			TEE_FreeTransientObject(key_handle);
	}

	if (buf)
		TEE_Free(buf);

	if (operation != TEE_HANDLE_NULL)
		TEE_FreeOperation(operation);

	return res;
}
