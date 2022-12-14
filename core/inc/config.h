/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2023 NXP
 */

#ifndef __CONFIG_H__
#define __CONFIG_H__

#include <stdbool.h>

#include "subsystems.h"

enum smw_config_key_type_id {
	/* Key type IDs */
	SMW_CONFIG_KEY_TYPE_ID_ECDSA_NIST,
	SMW_CONFIG_KEY_TYPE_ID_ECDSA_BRAINPOOL_R1,
	SMW_CONFIG_KEY_TYPE_ID_ECDSA_BRAINPOOL_T1,
	SMW_CONFIG_KEY_TYPE_ID_ECDH_NIST,
	SMW_CONFIG_KEY_TYPE_ID_ECDH_BRAINPOOL_R1,
	SMW_CONFIG_KEY_TYPE_ID_ECDH_BRAINPOOL_T1,
	SMW_CONFIG_KEY_TYPE_ID_AES,
	SMW_CONFIG_KEY_TYPE_ID_DES,
	SMW_CONFIG_KEY_TYPE_ID_DES3,
	SMW_CONFIG_KEY_TYPE_ID_DSA_SM2_FP,
	SMW_CONFIG_KEY_TYPE_ID_SM4,
	SMW_CONFIG_KEY_TYPE_ID_HMAC,
	SMW_CONFIG_KEY_TYPE_ID_HMAC_MD5,
	SMW_CONFIG_KEY_TYPE_ID_HMAC_SHA1,
	SMW_CONFIG_KEY_TYPE_ID_HMAC_SHA224,
	SMW_CONFIG_KEY_TYPE_ID_HMAC_SHA256,
	SMW_CONFIG_KEY_TYPE_ID_HMAC_SHA384,
	SMW_CONFIG_KEY_TYPE_ID_HMAC_SHA512,
	SMW_CONFIG_KEY_TYPE_ID_HMAC_SM3,
	SMW_CONFIG_KEY_TYPE_ID_RSA,
	SMW_CONFIG_KEY_TYPE_ID_DH,
	SMW_CONFIG_KEY_TYPE_ID_TLS_MASTER_KEY,
	SMW_CONFIG_KEY_TYPE_ID_NB,
	SMW_CONFIG_KEY_TYPE_ID_INVALID
};

enum smw_config_hash_algo_id {
	SMW_CONFIG_HASH_ALGO_ID_MD5,
	SMW_CONFIG_HASH_ALGO_ID_SHA1,
	SMW_CONFIG_HASH_ALGO_ID_SHA224,
	SMW_CONFIG_HASH_ALGO_ID_SHA256,
	SMW_CONFIG_HASH_ALGO_ID_SHA384,
	SMW_CONFIG_HASH_ALGO_ID_SHA512,
	SMW_CONFIG_HASH_ALGO_ID_SM3,
	SMW_CONFIG_HASH_ALGO_ID_NB,
	SMW_CONFIG_HASH_ALGO_ID_INVALID
};

enum smw_config_hmac_algo_id {
	SMW_CONFIG_HMAC_ALGO_ID_MD5,
	SMW_CONFIG_HMAC_ALGO_ID_SHA1,
	SMW_CONFIG_HMAC_ALGO_ID_SHA224,
	SMW_CONFIG_HMAC_ALGO_ID_SHA256,
	SMW_CONFIG_HMAC_ALGO_ID_SHA384,
	SMW_CONFIG_HMAC_ALGO_ID_SHA512,
	SMW_CONFIG_HMAC_ALGO_ID_SM3,
	SMW_CONFIG_HMAC_ALGO_ID_NB,
	SMW_CONFIG_HMAC_ALGO_ID_INVALID
};

enum smw_config_mac_algo_id {
	SMW_CONFIG_MAC_ALGO_ID_CMAC,
	SMW_CONFIG_MAC_ALGO_ID_CMAC_TRUNCATED,
	SMW_CONFIG_MAC_ALGO_ID_HMAC,
	SMW_CONFIG_MAC_ALGO_ID_HMAC_TRUNCATED,
	SMW_CONFIG_MAC_ALGO_ID_NB,
	SMW_CONFIG_MAC_ALGO_ID_INVALID
};

enum smw_config_mac_op_type_id {
	SMW_CONFIG_MAC_OP_ID_COMPUTE,
	SMW_CONFIG_MAC_OP_ID_VERIFY,
	SMW_CONFIG_MAC_OP_ID_NB,
	SMW_CONFIG_MAC_OP_ID_INVALID
};

enum smw_config_sign_type_id {
	SMW_CONFIG_SIGN_TYPE_ID_DEFAULT,
	SMW_CONFIG_SIGN_TYPE_ID_RSASSA_PKCS1_V1_5,
	SMW_CONFIG_SIGN_TYPE_ID_RSASSA_PSS,
	SMW_CONFIG_SIGN_TYPE_ID_NB
};

enum smw_config_cipher_op_type_id {
	SMW_CONFIG_CIPHER_OP_ID_ENCRYPT,
	SMW_CONFIG_CIPHER_OP_ID_DECRYPT,
	SMW_CONFIG_CIPHER_OP_ID_NB,
	SMW_CONFIG_CIPHER_OP_ID_INVALID
};

enum smw_config_cipher_mode_id {
	SMW_CONFIG_CIPHER_MODE_ID_CBC,
	SMW_CONFIG_CIPHER_MODE_ID_CCM,
	SMW_CONFIG_CIPHER_MODE_ID_CTR,
	SMW_CONFIG_CIPHER_MODE_ID_CTS,
	SMW_CONFIG_CIPHER_MODE_ID_ECB,
	SMW_CONFIG_CIPHER_MODE_ID_GCM,
	SMW_CONFIG_CIPHER_MODE_ID_XTS,
	SMW_CONFIG_CIPHER_MODE_ID_NB,
	SMW_CONFIG_CIPHER_MODE_ID_INVALID
};

enum smw_config_kdf_id {
	SMW_CONFIG_KDF_TLS12_KEY_EXCHANGE,
	SMW_CONFIG_KDF_ID_NB,
	SMW_CONFIG_KDF_ID_INVALID
};

enum smw_config_tls_finish_label_id {
	SMW_CONFIG_TLS_FINISH_ID_CLIENT,
	SMW_CONFIG_TLS_FINISH_ID_SERVER,
	SMW_CONFIG_TLS_FINISH_ID_NB,
	SMW_CONFIG_TLS_FINISH_ID_INVALID
};

/**
 * struct smw_config_psa_config - PSA configuration
 * @subsystem_id: Default subsystem ID invoked with PSA API
 * @alt: Whether or not, subsystem fallback is enabled
 *
 */
struct smw_config_psa_config {
	enum subsystem_id subsystem_id;
	bool alt;
};

/**
 * smw_config_init() - Initialize the Configuration module.
 *
 * This function initializes the Configuration module.
 *
 * Return:
 * error code.
 */
int smw_config_init(void);

/**
 * smw_config_deinit() - Deinitialize the Configuration module.
 *
 * This function deinitializes the Configuration module.
 *
 * Return:
 * error code.
 */
int smw_config_deinit(void);

/**
 * smw_config_select_subsystem() - Select a subsystem for an operation.
 * @operation_id: Security Operation ID.
 * @args: Security Operation arguments.
 * @subsystem_id: Pointer to the Secure Subsystem ID.
 *
 * This function selects a Secure Subsystem to execute the Security Operation
 * given the arguments.
 *
 * Return:
 * error code.
 */
int smw_config_select_subsystem(enum operation_id operation_id, void *args,
				enum subsystem_id *subsystem_id);

/**
 * smw_config_load_subsystem() - Load a Secure Subsystem.
 * @id: Secure Subsystem ID.
 *
 * This function loads a Secure Subsystem.
 *
 * Return:
 * error code.
 */
int smw_config_load_subsystem(enum subsystem_id id);

/**
 * smw_config_unload_subsystem() - Unload a Secure Subsystem.
 * @id: Secure Subsystem ID.
 *
 * This function unloads a Secure Subsystem.
 *
 * Return:
 * error code.
 */
int smw_config_unload_subsystem(enum subsystem_id id);

/**
 * smw_config_notify_subsystem_failure() - Notify subsystem failure.
 * @id: ID of the subsystem.
 *
 * This function notifies about a subsystem failure.
 * It is called by the subsystem module when the subsystem has encountered
 * a failure so that the configuration module can take appropriate action.
 *
 * Return:
 * none.
 */
void smw_config_notify_subsystem_failure(enum subsystem_id id);

/**
 * smw_config_get_subsystem_func() - Get the Secure Subsystem functions.
 * @subsystem_id: Secure Subsystem ID.
 *
 * This function gets a Secure Subsystem functions.
 *
 * Return:
 * * pointer to the data structure containing the functions pointers
 *   associated with the Secure Subsystem.
 */
struct subsystem_func *smw_config_get_subsystem_func(enum subsystem_id id);

/**
 * smw_config_get_operation_name() - Get the Security Operation name.
 * @operation_id: Security Operation ID.
 *
 * This function gets the name of a Security Operation.
 *
 * Return:
 * pointer to the string that is the Security Operation name.
 */
const char *smw_config_get_operation_name(enum operation_id id);

/**
 * smw_config_get_subsystem_name() - Get the Secure Subsystem name.
 * @subsystem_id: Secure Subsystem ID.
 *
 * This function gets the name of a Secure Subsystem.
 *
 * Return:
 * pointer to the string that is the Secure Subsystem name.
 */
const char *smw_config_get_subsystem_name(enum subsystem_id id);

/**
 * smw_config_get_subsystem_id() - Get the ID associated to a name.
 * @name: Name of the Secure Subsystem.
 * @id: Pointer where the ID is written.
 *
 * This function gets the ID of a Secure Subsystem designated by its name.
 *
 * Return:
 * error code.
 */
int smw_config_get_subsystem_id(const char *name, enum subsystem_id *id);

/**
 * smw_config_get_key_type_id() - Get the ID associated to a Key type name.
 * @name: Name as a string.
 * @id: Pointer where the ID is written.
 *
 * This function gets the ID associated to a Key type name.
 *
 * Return:
 * error code.
 */
int smw_config_get_key_type_id(const char *name,
			       enum smw_config_key_type_id *id);

/**
 * smw_config_get_key_type_name() - Get the name associated to a Key type ID.
 * @id: Key type ID.
 * @name: Pointer to the Key type name.
 *
 * This function gets the name associated to a Key type ID.
 *
 * Return:
 * none.
 */
void smw_config_get_key_type_name(enum smw_config_key_type_id id,
				  const char **name);

/**
 * smw_config_get_hash_algo_id() - Get the Hash algo ID associated to a name.
 * @name: Name as a string.
 * @id: Pointer where the ID is written.
 *
 * This function gets the Hash algo ID associated to a name.
 *
 * Return:
 * error code.
 */
int smw_config_get_hash_algo_id(const char *name,
				enum smw_config_hash_algo_id *id);

/**
 * smw_config_get_hmac_algo_id() - Get the HMAC algo ID associated to a name.
 * @name: Name as a string.
 * @id: Pointer where the ID is written.
 *
 * This function gets the HMAC algo ID associated to a name.
 *
 * Return:
 * error code.
 */
int smw_config_get_hmac_algo_id(const char *name,
				enum smw_config_hmac_algo_id *id);

/**
 * smw_config_get_signature_type_id() - Get the signature type ID associated to
 *                                      a name.
 * @name: Name as a string.
 * @id: Pointer where the ID is written.
 *
 * Return:
 * SMW_STATUS_UNKNOWN_NAME	- @name is unknown
 * SMW_STATUS_OK		- Success
 */
int smw_config_get_signature_type_id(const char *name,
				     enum smw_config_sign_type_id *id);

/**
 * smw_config_get_cipher_mode_id() - Get the cipher mode ID associated to a name
 * @name: Name as a string.
 * @id: Pointer where the ID is written.
 *
 * Return:
 * SMW_STATUS_UNKNOWN_NAME	- @name is unknown
 * SMW_STATUS_OK		- Success
 */
int smw_config_get_cipher_mode_id(const char *name,
				  enum smw_config_cipher_mode_id *id);

/**
 * smw_config_get_cipher_op_type_id() - Get the cipher operation type ID
 *                                      associated to a name
 * @name: Name as a string.
 * @id: Pointer where the ID is written.
 *
 * Return:
 * SMW_STATUS_UNKNOWN_NAME	- @name is unknown
 * SMW_STATUS_OK		- Success
 */
int smw_config_get_cipher_op_type_id(const char *name,
				     enum smw_config_cipher_op_type_id *id);

/**
 * smw_config_get_kdf_id() - Get the id of the key derivation function name
 * @name: Name of the key derivation function
 * @id: Key derivation function id found
 *
 * Note: If name is NULL, the returned @id is set SMW_CONFIG_KDF_ID_INVALID
 *       and function return SMW_STATUS_OK.
 *
 * Return:
 * SMW_STATUS_UNKNOWN_NAME	- @name is unknown
 * SMW_STATUS_OK		- Success
 */
int smw_config_get_kdf_id(const char *name, enum smw_config_kdf_id *id);

/**
 * smw_config_get_tls_label_id() - Get TLS MAC finish label ID
 * @name: Label name as a string.
 * @id: Pointer where the ID is written.
 *
 * Return:
 * SMW_STATUS_UNKNOWN_NAME	- @name is unknown
 * SMW_STATUS_OK		- Success
 */
int smw_config_get_tls_label_id(const char *name,
				enum smw_config_tls_finish_label_id *id);

/**
 * smw_config_get_mac_algo_id() - Get MAC algo ID associated to a name.
 * @name: Name as a string.
 * @id: Pointer where the ID is written.
 *
 * This function gets the MAC algo ID associated to a name.
 *
 * Return:
 * error code.
 */
int smw_config_get_mac_algo_id(const char *name,
			       enum smw_config_mac_algo_id *id);
/**
 * smw_config_get_psa_config() - Get the PSA configuration.
 * @config: PSA configuration.
 *
 * This function gets the PSA configuration.
 *
 * Return:
 * none.
 */
void smw_config_get_psa_config(struct smw_config_psa_config *config);

#endif /* __CONFIG_H__ */
