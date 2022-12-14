/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2022 NXP
 */

#ifndef TEE_SUBSYSTEM_H
#define TEE_SUBSYSTEM_H

#include <tee_api_types.h>

/* Index of operation shared buffers parameters */
#define GEN_PUB_KEY_PARAM_IDX  1
#define GEN_PUB_EXP_PARAM_IDX  3
#define GEN_MOD_PARAM_IDX      2
#define IMP_PUB_KEY_PARAM_IDX  2
#define IMP_PRIV_KEY_PARAM_IDX 1
#define IMP_MOD_PARAM_IDX      3
#define EXP_PUB_KEY_PARAM_IDX  1
#define EXP_MOD_PARAM_IDX      2

/* TEE key type */
enum tee_key_type {
	TEE_KEY_TYPE_ID_ECDSA,
	TEE_KEY_TYPE_ID_AES,
	TEE_KEY_TYPE_ID_DES,
	TEE_KEY_TYPE_ID_DES3,
	TEE_KEY_TYPE_ID_HMAC_MD5,
	TEE_KEY_TYPE_ID_HMAC_SHA1,
	TEE_KEY_TYPE_ID_HMAC_SHA224,
	TEE_KEY_TYPE_ID_HMAC_SHA256,
	TEE_KEY_TYPE_ID_HMAC_SHA384,
	TEE_KEY_TYPE_ID_HMAC_SHA512,
	TEE_KEY_TYPE_ID_HMAC_SM3,
	TEE_KEY_TYPE_ID_RSA,
	TEE_KEY_TYPE_ID_NB,
	TEE_KEY_TYPE_ID_INVALID
};

/* TEE key usage */
#define TEE_KEY_USAGE_EXPORTABLE 0x00000001
#define TEE_KEY_USAGE_COPYABLE	 0x00000002
#define TEE_KEY_USAGE_ENCRYPT	 0x00000100
#define TEE_KEY_USAGE_DECRYPT	 0x00000200
#define TEE_KEY_USAGE_SIGN	 0x00000401
#define TEE_KEY_USAGE_VERIFY	 0x00000800
#define TEE_KEY_USAGE_DERIVE	 0x00001000
#define TEE_KEY_USAGE_MAC	 0x00002000

#define TEE_KEY_USAGE_ALL                                                      \
	(TEE_KEY_USAGE_EXPORTABLE | TEE_KEY_USAGE_COPYABLE |                   \
	 TEE_KEY_USAGE_ENCRYPT | TEE_KEY_USAGE_DECRYPT | TEE_KEY_USAGE_SIGN |  \
	 TEE_KEY_USAGE_VERIFY | TEE_KEY_USAGE_DERIVE | TEE_KEY_USAGE_MAC)

/* TEE algorithm ID */
enum tee_algorithm_id {
	TEE_ALGORITHM_ID_MD5,
	TEE_ALGORITHM_ID_SHA1,
	TEE_ALGORITHM_ID_SHA224,
	TEE_ALGORITHM_ID_SHA256,
	TEE_ALGORITHM_ID_SHA384,
	TEE_ALGORITHM_ID_SHA512,
	TEE_ALGORITHM_ID_SM3,
	TEE_ALGORITHM_ID_INVALID
};

/* TEE signature type */
enum tee_signature_type {
	TEE_SIGNATURE_TYPE_DEFAULT,
	TEE_SIGNATURE_TYPE_RSASSA_PKCS1_V1_5,
	TEE_SIGNATURE_TYPE_RSASSA_PSS,
};

/* TA commands */
#define CMD_GENERATE_KEY  0
#define CMD_DELETE_KEY	  1
#define CMD_IMPORT_KEY	  2
#define CMD_EXPORT_KEY	  3
#define CMD_HASH	  4
#define CMD_SIGN	  5
#define CMD_VERIFY	  6
#define CMD_HMAC	  7
#define CMD_RNG		  8
#define CMD_CIPHER_INIT	  9
#define CMD_CIPHER_UPDATE 10
#define CMD_CIPHER_FINAL  11
#define CMD_CANCEL_OP	  12
#define CMD_COPY_CTX	  13

struct hmac_shared_params {
	enum tee_key_type tee_key_type;
	enum tee_algorithm_id tee_algorithm_id;
	unsigned int security_size;
};

/**
 * struct keymgr_shared_params - Key manager operation shared parameters.
 * @security_size: Key security size.
 * @key_type: Key type.
 * @key_usage: Key usage.
 * @id: Key ID set by the TA.
 * @persistent_storage: Use persistent subsystem storage or not.
 */
struct keymgr_shared_params {
	unsigned int security_size;
	enum tee_key_type key_type;
	unsigned int key_usage;
	uint32_t id;
	bool persistent_storage;
};

/**
 * struct sign_verify_shared_params - Sign/verify operation shared parameters.
 * @id: Key ID. Not set if a buffer is used.
 * @key_type: Key type.
 * @security_size: Key security size.
 * @hash_algorithm: Hash algorithm.
 * @signature_type: Signature type.
 * @salt_length: Optional salt length (only for TEE_RSA_PKCS1_PSS_MGF1).
 * @pub_key_len: Key public length in bytes.
 */
struct sign_verify_shared_params {
	uint32_t id;
	enum tee_key_type key_type;
	unsigned int security_size;
	enum tee_algorithm_id hash_algorithm;
	enum tee_signature_type signature_type;
	uint32_t salt_length;
	unsigned int pub_key_len;
};

/**
 * struct shared_context - Context operation handle
 * @handle: Pointer to operation handle
 */
struct shared_context {
	void *handle;
};

#endif /* TEE_SUBSYSTEM_H */
