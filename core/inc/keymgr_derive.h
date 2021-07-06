/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021 NXP
 */

#ifndef __KEYMGR_DERIVE_H__
#define __KEYMGR_DERIVE_H__

#include "smw_keymgr.h"

#include "config.h"
#include "keymgr.h"

/* The master secret is always exactly 48 bytes in length (cf RFC 5246)*/
#define TLS12_MASTER_SECRET_SEC_SIZE 384

enum smw_tls12_key_exchange_id {
	SMW_TLS12_KEY_EXCHANGE_ID_RSA,
	SMW_TLS12_KEY_EXCHANGE_ID_DH_DSS,
	SMW_TLS12_KEY_EXCHANGE_ID_DH_RSA,
	SMW_TLS12_KEY_EXCHANGE_ID_DHE_DSS,
	SMW_TLS12_KEY_EXCHANGE_ID_DHE_RSA,
	SMW_TLS12_KEY_EXCHANGE_ID_ECDH_ECDSA,
	SMW_TLS12_KEY_EXCHANGE_ID_ECDH_RSA,
	SMW_TLS12_KEY_EXCHANGE_ID_ECDHE_ECDSA,
	SMW_TLS12_KEY_EXCHANGE_ID_ECDHE_RSA,
	SMW_TLS12_KEY_EXCHANGE_ID_NB,
	SMW_TLS12_KEY_EXCHANGE_ID_INVALID
};

enum smw_tls12_encryption_id {
	SMW_TLS12_ENCRYPTION_ID_RC4_128,
	SMW_TLS12_ENCRYPTION_ID_3DES_EDE_CBC,
	SMW_TLS12_ENCRYPTION_ID_AES_128_CBC,
	SMW_TLS12_ENCRYPTION_ID_AES_256_CBC,
	SMW_TLS12_ENCRYPTION_ID_AES_128_GCM,
	SMW_TLS12_ENCRYPTION_ID_AES_256_GCM,
	SMW_TLS12_ENCRYPTION_ID_NB,
	SMW_TLS12_ENCRYPTION_ID_INVALID
};

/**
 * struct smw_keymgr_derive_key_args - Key derivation arguments
 * @key_base: Descriptor of the base key
 * @key_attributes: Key attributes
 * @key_derived: Descriptor of the derived Key
 * @kdf_id: Key Derivation Function id if any
 * @kdf_args: Key Derivation Function arguments (depend on KDF)
 */
struct smw_keymgr_derive_key_args {
	struct smw_keymgr_descriptor key_base;
	struct smw_keymgr_attributes key_attributes;
	struct smw_keymgr_descriptor key_derived;
	enum smw_config_kdf_id kdf_id;
	void *kdf_args;
};

struct smw_keymgr_tls12_args {
	enum smw_tls12_key_exchange_id key_exchange_id;
	enum smw_tls12_encryption_id encryption_id;
	enum smw_config_hmac_algo_id prf_id;
	bool ephemeral_key;

	struct smw_kdf_tls12_args *pub_args;
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
					 unsigned long long id)
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
					 unsigned long long id)
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
					 unsigned long long id)
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
					 unsigned long long id)
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
				       unsigned long long id)
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

#endif /* __KEYMGR_DERIVE_H__ */
