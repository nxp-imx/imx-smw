/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021, 2023-2025 NXP
 */

#ifndef __KEYMGR_DERIVE_H__
#define __KEYMGR_DERIVE_H__

#include "smw_keymgr.h"

#include "config.h"
#include "keymgr.h"

/* The master secret is always exactly 48 bytes in length (cf RFC 5246)*/
#define TLS12_MASTER_SECRET_SEC_SIZE 384

enum hkdf_step {
	HKDF_STEP_INVALID,
	/* HKDF step 1 expand */
	HKDF_STEP_EXPAND,
	/* HKDF step 2 extract */
	HKDF_STEP_EXTRACT,
	/* HKDF Step 1 and step 2 combined */
	HKDF_STEP_FULL
};

enum smw_tls12_key_exchange_id {
	SMW_TLS12_KEY_EXCHANGE_ID_DH_DSS,
	SMW_TLS12_KEY_EXCHANGE_ID_DH_RSA,
	SMW_TLS12_KEY_EXCHANGE_ID_DHE_DSS,
	SMW_TLS12_KEY_EXCHANGE_ID_DHE_RSA,
	SMW_TLS12_KEY_EXCHANGE_ID_ECDH_ECDSA,
	SMW_TLS12_KEY_EXCHANGE_ID_ECDH_RSA,
	SMW_TLS12_KEY_EXCHANGE_ID_ECDHE_ECDSA,
	SMW_TLS12_KEY_EXCHANGE_ID_ECDHE_RSA,
	SMW_TLS12_KEY_EXCHANGE_ID_RSA,
	SMW_TLS12_KEY_EXCHANGE_ID_NB,
	SMW_TLS12_KEY_EXCHANGE_ID_INVALID
};

enum smw_tls12_encryption_id {
	SMW_TLS12_ENCRYPTION_ID_3DES_EDE_CBC,
	SMW_TLS12_ENCRYPTION_ID_AES_128_CBC,
	SMW_TLS12_ENCRYPTION_ID_AES_128_GCM,
	SMW_TLS12_ENCRYPTION_ID_AES_256_CBC,
	SMW_TLS12_ENCRYPTION_ID_AES_256_GCM,
	SMW_TLS12_ENCRYPTION_ID_RC4_128,
	SMW_TLS12_ENCRYPTION_ID_NB,
	SMW_TLS12_ENCRYPTION_ID_INVALID
};

/**
 * struct smw_keymgr_derived_key_desc - Derived key descriptor
 * @identifier: Key identifier
 * @format_id: Format ID of the key buffer
 * @pub: Pointer to public derived key descriptor
 */
struct smw_keymgr_derived_key_desc {
	struct smw_keymgr_identifier identifier;
	enum smw_keymgr_format_id format_id;
	struct smw_derived_key_descriptor *pub;
};

struct smw_keymgr_derive_key_args;

/**
 * struct smw_keymgr_kdf_ops - kdf with operations
 * @get_peer: Get peer public key buffer address
 * @get_peer_len: Get peer public key buffer length
 * @get_salt: Get salt buffer address
 * @get_salt_len: Get salt buffer length
 * @get_info: Get info buffer address
 * @get_info_len: Get info buffer length
 *
 * This structure is initialized by the specific convert_input_args
 * function.
 * The operations are function of the kdf algorithm.
 */
struct smw_keymgr_kdf_ops {
	unsigned char *(*get_peer)(struct smw_keymgr_derive_key_args *self);
	unsigned int (*get_peer_len)(struct smw_keymgr_derive_key_args *self);
	unsigned char *(*get_salt)(struct smw_keymgr_derive_key_args *self);
	unsigned int (*get_salt_len)(struct smw_keymgr_derive_key_args *self);
	unsigned char *(*get_info)(struct smw_keymgr_derive_key_args *self);
	unsigned int (*get_info_len)(struct smw_keymgr_derive_key_args *self);
};

/**
 * struct smw_keymgr_derive_key_args - Key derivation arguments
 * @key_base: Descriptor of the base key
 * @key_attributes: Pointer to the public Key attributes structure
 * @key_derived: Descriptor of the derived Key
 * @store_key: If true, store the derived Key
 * @kdf_id: Key Derivation Function id if any
 * @kdf_args: Key Derivation Function arguments (depend on KDF)
 */
struct smw_keymgr_derive_key_args {
	struct smw_keymgr_descriptor key_base;
	struct smw_key_attributes *key_attributes;
	struct smw_keymgr_derived_key_desc key_derived;
	bool store_key;
	enum smw_config_kdf_id kdf_id;
	void *kdf_args;
	struct smw_keymgr_kdf_ops ops;
};

struct smw_keymgr_tls12_args {
	enum smw_tls12_key_exchange_id key_exchange_id;
	enum smw_tls12_encryption_id encryption_id;
	enum smw_config_hash_algo_id prf_id;
	bool ephemeral_key;
	struct smw_kdf_tls12_args *pub_args;
};

struct smw_keymgr_hkdf_args {
	enum smw_config_hash_algo_id prf_id;
	struct smw_kdf_hkdf_args *pub_args;
};

struct smw_keymgr_ecdh_args {
	struct smw_kdf_ecdh_args *pub_args;
};

/**
 * smw_keymgr_tls12_get_client_w_iv() - Return the Client write IV buffer
 * @args: TLS 1.2 internal arguments
 *
 * Return:
 * Client write IV buffer reference
 */
static inline unsigned char *
smw_keymgr_tls12_get_client_w_iv(struct smw_keymgr_tls12_args *args)
{
	SMW_DBG_ASSERT(args && args->pub_args);

	return args->pub_args->client_w_iv;
}

/**
 * smw_keymgr_tls12_get_client_w_iv_length() - Return the length of Client
 *                                             write IV
 * @args: TLS 1.2 internal arguments
 *
 * Return:
 * Length in bytes of Client write IV
 */
static inline unsigned int
smw_keymgr_tls12_get_client_w_iv_length(struct smw_keymgr_tls12_args *args)
{
	SMW_DBG_ASSERT(args && args->pub_args);

	return args->pub_args->client_w_iv_length;
}

/**
 * smw_keymgr_tls12_set_client_w_iv_length() - Set the length of Client
 *                                             write IV
 * @args: TLS 1.2 internal arguments
 * @length: Length to set
 *
 */
static inline void
smw_keymgr_tls12_set_client_w_iv_length(struct smw_keymgr_tls12_args *args,
					unsigned int length)
{
	SMW_DBG_ASSERT(args && args->pub_args);

	args->pub_args->client_w_iv_length = length;
}

/**
 * smw_keymgr_tls12_get_server_w_iv() - Return the Server write IV buffer
 * @args: TLS 1.2 internal arguments
 *
 * Return:
 * Server write IV buffer reference
 */
static inline unsigned char *
smw_keymgr_tls12_get_server_w_iv(struct smw_keymgr_tls12_args *args)
{
	SMW_DBG_ASSERT(args && args->pub_args);

	return args->pub_args->server_w_iv;
}

/**
 * smw_keymgr_tls12_get_server_w_iv_length() - Return the length of Server
 *                                             write IV
 * @args: TLS 1.2 internal arguments
 *
 * Return:
 * Length in bytes of Server write IV
 */
static inline unsigned int
smw_keymgr_tls12_get_server_w_iv_length(struct smw_keymgr_tls12_args *args)
{
	SMW_DBG_ASSERT(args && args->pub_args);

	return args->pub_args->server_w_iv_length;
}

/**
 * smw_keymgr_tls12_set_server_w_iv_length() - Set the length of server
 *                                             write IV
 * @args: TLS 1.2 internal arguments
 * @length: Length to set
 *
 */
static inline void
smw_keymgr_tls12_set_server_w_iv_length(struct smw_keymgr_tls12_args *args,
					unsigned int length)
{
	SMW_DBG_ASSERT(args && args->pub_args);

	args->pub_args->server_w_iv_length = length;
}

/**
 * smw_keymgr_tls12_get_kdf_input_length() - Return the length of KDF input
 * @args: TLS 1.2 internal arguments
 *
 * Return:
 * Length in bytes of KDF input
 */
static inline unsigned int
smw_keymgr_tls12_get_kdf_input_length(struct smw_keymgr_tls12_args *args)
{
	SMW_DBG_ASSERT(args && args->pub_args);

	return args->pub_args->kdf_input_length;
}

/**
 * smw_keymgr_tls12_get_kdf_input() - Return the KDF input buffer
 * @args: TLS 1.2 internal arguments
 *
 * Return:
 * KDF input buffer reference
 */
static inline unsigned char *
smw_keymgr_tls12_get_kdf_input(struct smw_keymgr_tls12_args *args)
{
	SMW_DBG_ASSERT(args && args->pub_args);

	return args->pub_args->kdf_input;
}

/**
 * smw_keymgr_tls12_get_ext_master_key() - Return if extended master key
 * @args: TLS 1.2 internal arguments
 *
 * Return:
 * True, if extended master key
 * False, otherwise
 */
static inline bool
smw_keymgr_tls12_get_ext_master_key(struct smw_keymgr_tls12_args *args)
{
	SMW_DBG_ASSERT(args && args->pub_args);

	return args->pub_args->ext_master_key;
}

/**
 * smw_keymgr_tls12_set_client_w_mac_key_id() - Set the Client write MAC key id
 * @args: TLS 1.2 internal arguments
 * @id: Key id to set
 *
 */
static inline void
smw_keymgr_tls12_set_client_w_mac_key_id(struct smw_keymgr_tls12_args *args,
					 unsigned int id)
{
	SMW_DBG_ASSERT(args && args->pub_args);

	args->pub_args->client_w_mac_key_id = id;
}

/**
 * smw_keymgr_tls12_set_server_w_mac_key_id() - Set the Server write MAC key id
 * @args: TLS 1.2 internal arguments
 * @id: Key id to set
 *
 */
static inline void
smw_keymgr_tls12_set_server_w_mac_key_id(struct smw_keymgr_tls12_args *args,
					 unsigned int id)
{
	SMW_DBG_ASSERT(args && args->pub_args);

	args->pub_args->server_w_mac_key_id = id;
}

/**
 * smw_keymgr_tls12_set_client_w_enc_key_id() - Set the Client write encryption
 *                                              key id
 * @args: TLS 1.2 internal arguments
 * @id: Key id to set
 *
 */
static inline void
smw_keymgr_tls12_set_client_w_enc_key_id(struct smw_keymgr_tls12_args *args,
					 unsigned int id)
{
	SMW_DBG_ASSERT(args && args->pub_args);

	args->pub_args->client_w_enc_key_id = id;
}

/**
 * smw_keymgr_tls12_set_server_w_enc_key_id() - Set the Server write encryption
 *                                              key id
 * @args: TLS 1.2 internal arguments
 * @id: Key id to set
 *
 */
static inline void
smw_keymgr_tls12_set_server_w_enc_key_id(struct smw_keymgr_tls12_args *args,
					 unsigned int id)
{
	SMW_DBG_ASSERT(args && args->pub_args);

	args->pub_args->server_w_enc_key_id = id;
}

/**
 * smw_keymgr_tls12_set_master_sec_key_id() - Set the Master secret key id
 * @args: TLS 1.2 internal arguments
 * @id: Key id to set
 *
 */
static inline void
smw_keymgr_tls12_set_master_sec_key_id(struct smw_keymgr_tls12_args *args,
				       unsigned int id)
{
	SMW_DBG_ASSERT(args && args->pub_args);

	args->pub_args->master_sec_key_id = id;
}

/**
 * smw_keymgr_tls12_is_encryption_aead() - Return if the Cipher mode is AEAD
 * @id: Cipher encryption mode
 *
 * Function returns if the TLS cipher encryption mode is an Authentication
 * Encryption with Additional Data (AEAD), such as CCM, GCM.
 *
 * Return:
 * True if AEAD cipher mode,
 * False otherwise
 */
bool smw_keymgr_tls12_is_encryption_aead(enum smw_tls12_encryption_id id);

/**
 * smw_keymgr_is_store_key_set() - Return if store key flag is set
 * @args: Pointer to internal Key derivation arguments structure
 *
 * Return:
 * True if user has set the flag to store the derived key buffer
 * False otherwise
 */
bool smw_keymgr_is_store_key_set(struct smw_keymgr_derive_key_args *args);

/**
 * smw_keymgr_get_shared_secret_buffer() - Return shared secret buffer address.
 * @descriptor: Pointer to the internal derived key descriptor structure.
 *
 * Return:
 * NULL
 * address of the shared secret buffer
 */
unsigned char *
smw_keymgr_get_shared_secret_buffer(struct smw_keymgr_derived_key_desc *desc);

/**
 * smw_keymgr_get_shared_secret_len() - Return length of shared secret buffer.
 * @descriptor: Pointer to the internal derived key descriptor structure.
 *
 * Return:
 * 0
 * length of the shared secret buffer
 */
unsigned int
smw_keymgr_get_shared_secret_len(struct smw_keymgr_derived_key_desc *desc);

/**
 * smw_keymgr_set_shared_secret_len() - Set the length of shared secret buffer.
 * @desc: Pointer to the internal derived key descriptor structure.
 * @len: Length of the shared secret buffer.
 *
 * Return:
 * None
 */
void smw_keymgr_set_shared_secret_len(struct smw_keymgr_derived_key_desc *desc,
				      unsigned int len);

/**
 * smw_keymgr_update_shared_secret() - Update the derived key buffer fields.
 * @descriptor: Internal derived key descriptor structure.
 * @data: Data to be converted in base64 if key buffer's format is base64.
 * @length: Length of the @data.
 *
 * If the key buffer format is base64, the function converts the @data to
 * base64 and update the key buffer's data field. Otherwise, the key buffer's
 * data is assumed to be the same as the @data.
 *
 * Key buffer's length is updated if function returns
 * SMW_STATUS_OUTPUT_TOO_SHORT.
 *
 * If @data = NULL, only the key buffer's length is updated.
 *
 * Return:
 * SMW_STATUS_OK                 - Success
 * SMW_STATUS_OPERATION_FAILURE  - Operation failed
 * SMW_STATUS_OUTPUT_TOO_SHORT   - Output buffer is too short
 * SMW_STATUS_INVALID_PARAM      - One of the parameter is invalid
 */
int smw_keymgr_update_shared_secret(struct smw_keymgr_derived_key_desc *desc,
				    unsigned char *data, unsigned int length);

/**
 * smw_keymgr_set_shared_secret_id() - Update the derived key ID.
 * @descriptor: Internal derived key descriptor structure.
 * @id: Derived key ID.
 *
 * Return:
 * None
 */
void smw_keymgr_set_shared_secret_id(struct smw_keymgr_derived_key_desc *desc,
				     uint32_t id);

/**
 * smw_keymgr_get_hkdf_step() - Get the HKDF step
 * @args: Pointer to internal HKDF argument structure
 *
 * Return:
 * HKDF step type
 * HKDF_STEP_INVALID
 */
enum hkdf_step smw_keymgr_get_hkdf_step(struct smw_keymgr_hkdf_args *args);

/**
 * smw_keymgr_get_salt() - Get salt buffer address
 * @args: Pointer to internal argument structure
 *
 * Return:
 * address of salt buffer
 * NULL
 */
unsigned char *smw_keymgr_get_salt(struct smw_keymgr_derive_key_args *args);

/**
 * smw_keymgr_get_info() - Get info buffer address
 * @args: Pointer to internal argument structure
 *
 * Return:
 * address of info buffer
 * NULL
 */
unsigned char *smw_keymgr_get_info(struct smw_keymgr_derive_key_args *args);

/**
 * smw_keymgr_get_salt_len() - Get salt buffer length
 * @args: Pointer to internal arguments structure
 *
 * Return:
 * Salt buffer length
 * 0
 */
unsigned int smw_keymgr_get_salt_len(struct smw_keymgr_derive_key_args *args);

/**
 * smw_keymgr_get_info_len() - Get info buffer length
 * @args: Pointer to internal arguments structure
 *
 * Return:
 * Info buffer length
 * 0
 */
unsigned int smw_keymgr_get_info_len(struct smw_keymgr_derive_key_args *args);

/**
 * smw_keymgr_get_peer_pub_buffer() - Get peer public key buffer address
 * @args: Pointer to internal arguments structure
 *
 * Return:
 * Address of peer public key buffer
 * NULL
 */
unsigned char *
smw_keymgr_get_peer_pub_buffer(struct smw_keymgr_derive_key_args *args);

/**
 * smw_keymgr_get_peer_pub_buffer_len() - Get peer public key buffer length
 * @args: Pointer to internal arguments structure
 *
 * Return:
 * Length of peer public key buffer
 * 0
 */
unsigned int
smw_keymgr_get_peer_pub_buffer_len(struct smw_keymgr_derive_key_args *args);

#endif /* __KEYMGR_DERIVE_H__ */
