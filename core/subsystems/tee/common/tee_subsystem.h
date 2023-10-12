/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2023 NXP
 */

#ifndef TEE_SUBSYSTEM_H
#define TEE_SUBSYSTEM_H

#include <tee_api_types.h>

/* Index of operation shared buffers parameters */
#define GEN_PUB_KEY_PARAM_IDX		  1
#define GEN_PUB_EXP_PARAM_IDX		  3
#define GEN_MOD_PARAM_IDX		  2
#define IMP_PUB_KEY_PARAM_IDX		  2
#define IMP_PRIV_KEY_PARAM_IDX		  1
#define IMP_MOD_PARAM_IDX		  3
#define EXP_PUB_KEY_PARAM_IDX		  1
#define EXP_MOD_PARAM_IDX		  2
#define GET_KEY_LENGTHS_KEY_ID_IDX	  0
#define GET_KEY_LENGTHS_PUBKEYS_IDX	  1
#define GET_KEY_LENGTHS_PRIVKEY_IDX	  2
#define GET_KEY_ATTRS_KEY_ID_IDX	  0
#define GET_KEY_ATTRS_KEY_TYPE_IDX	  1
#define GET_KEY_ATTRS_KEY_USAGE_IDX	  1
#define GET_KEY_ATTRS_KEYPAIR_FLAG_IDX	  2
#define GET_KEY_ATTRS_PERSISTENT_FLAG_IDX 2
#define GET_KEY_ATTRS_KEY_SIZE_IDX	  3

/* TEE key privacy */
enum tee_key_privacy {
	TEE_KEY_PUBLIC = 0,
	TEE_KEY_PRIVATE,
	TEE_KEY_PAIR,
};

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
#define TEE_KEY_USAGE_SIGN	 0x00000400
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
	TEE_ALGORITHM_ID_CMAC,
	TEE_ALGORITHM_ID_INVALID
};

/* TEE signature type */
enum tee_signature_type {
	TEE_SIGNATURE_TYPE_DEFAULT,
	TEE_SIGNATURE_TYPE_RSASSA_PKCS1_V1_5,
	TEE_SIGNATURE_TYPE_RSASSA_PSS,
};

/* TA commands */
enum ta_commands {
	CMD_GENERATE_KEY,
	CMD_DELETE_KEY,
	CMD_IMPORT_KEY,
	CMD_EXPORT_KEY,
	CMD_HASH,
	CMD_SIGN,
	CMD_VERIFY,
	CMD_HMAC,
	CMD_RNG,
	CMD_CIPHER_INIT,
	CMD_CIPHER_UPDATE,
	CMD_CIPHER_FINAL,
	CMD_CANCEL_OP,
	CMD_COPY_CTX,
	CMD_MAC_COMPUTE,
	CMD_MAC_VERIFY,
	CMD_GET_KEY_LENGTHS,
	CMD_GET_KEY_ATTRIBUTES,
	CMD_AEAD_INIT,
	CMD_AEAD_UPDATE_AAD,
	CMD_AEAD_UPDATE,
	CMD_AEAD_ENCRYPT_FINAL,
	CMD_AEAD_DECRYPT_FINAL,
	CMD_INVALID,
};

struct mac_shared_params {
	enum tee_key_type tee_key_type;
	enum tee_algorithm_id tee_algorithm_id;
	unsigned int security_size;
};

/**
 * struct keymgr_shared_params - Key manager operation shared parameters.
 * @security_size: Key security size.
 * @key_type: Key type.
 * @key_usage: Key usage.
 * @id: [in/out] Key ID set by the caller if not 0 and value returned by the TA.
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
 * struct aead_shared_params - AEAD operation shared parameters.
 * @tag_len: Size of the tag in bits.
 * @aad_len: Size of the AAD in bytes(only for AES-CCM).
 * @payload_len: Length of the payload in bytes(only for AES-CCM).
 * @aead_algo: TEE Algo ID
 * @aead_op: TEE Operation
 */
struct aead_shared_params {
	uint32_t tag_len;
	size_t aad_len;
	size_t payload_len;
	uint32_t aead_algo;
	uint32_t aead_op;
};

/**
 * struct shared_context - Context operation handle
 * @handle: Pointer to operation handle
 */
struct shared_context {
	void *handle;
};

#endif /* TEE_SUBSYSTEM_H */
