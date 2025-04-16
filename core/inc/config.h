/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2025 NXP
 */

#ifndef __CONFIG_H__
#define __CONFIG_H__

#include <stdbool.h>

#include "smw/names.h"

#include "config_ids.h"
#include "subsystems.h"

/**
 * struct smw_config_psa_config - PSA configuration
 * @subsystem_name: Default subsystem name invoked with PSA API
 * @alt: Whether or not, subsystem fallback is enabled
 *
 */
struct smw_config_psa_config {
	smw_subsystem_t subsystem_name;
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
 * smw_config_is_operations_supported() - Check if subsystem support at least
 *                                        one operation
 * @op_ids: Array of Security Operation IDs.
 * @nb_op_ids: Number of @op_ids.
 * @subsystem_id: Secure Subsystem ID to check.
 *
 * This function checks if one of the operations given in the @op_ids is
 * supported.
 *
 * Return:
 * SMW_STATUS_OK                      - One of the operation is supported
 * SMW_STATUS_OPERATION_NOT_SUPPORTED - None of the operation is supported
 * other error code.
 */
int smw_config_is_operations_supported(enum operation_id op_ids[],
				       unsigned int nb_op_ids,
				       enum subsystem_id subsystem_id);

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
 * The Security Operation name.
 */
smw_operation_t smw_config_get_operation_name(enum operation_id id);

/**
 * smw_config_get_subsystem_name() - Get the Secure Subsystem name.
 * @subsystem_id: Secure Subsystem ID.
 *
 * This function gets the name of a Secure Subsystem.
 *
 * Return:
 * The Secure Subsystem name.
 */
smw_subsystem_t smw_config_get_subsystem_name(enum subsystem_id id);

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
int smw_config_get_subsystem_id(smw_subsystem_t name, enum subsystem_id *id);

/**
 * smw_config_get_key_type_id() - Get the ID associated to a Key type name.
 * @name: Name of the Key type.
 * @id: Pointer where the ID is written.
 *
 * This function gets the ID associated to a Key type name.
 *
 * Return:
 * error code.
 */
int smw_config_get_key_type_id(smw_key_type_t name,
			       enum smw_config_key_type_id *id);

/**
 * smw_config_get_key_type_name() - Get the name associated to a Key type ID.
 * @id: Key type ID.
 *
 * This function gets the name associated to a Key type ID.
 *
 * Return:
 * Key type name.
 */
smw_key_type_t smw_config_get_key_type_name(enum smw_config_key_type_id id);

/**
 * smw_config_get_signature_algo_id() - Get the signature algo ID associated to
 *                                      a name.
 * @name: Signature algorithm name.
 * @id: Pointer where the ID is written.
 *
 * Return:
 * SMW_STATUS_SIGN_TYPE_NAME	- @name is unknown
 * SMW_STATUS_OK		- Success
 */
int smw_config_get_signature_algo_id(smw_signature_algo_t name,
				     enum smw_config_sign_algo_id *id);

/**
 * smw_utils_sign_attr_to_ids() - Get the Signature algo and type IDs from the
 *                                algorithm attribute.
 * @attr: Algorithm attribute.
 * @algo_id: Pointer where the algorithm ID is written.
 * @type_id: Pointer where the signature type ID is written.
 *
 * Return:
 * SMW_STATUS_OK                       - Success
 * SMW_STATUS_OPERATION_NOT_SUPPORTED  - Not supported
 */
int smw_utils_sign_attr_to_ids(smw_attr_algo_t attr,
			       enum smw_config_sign_algo_id *algo_id,
			       enum smw_config_sign_type_id *type_id);

/**
 * smw_config_get_signature_type_id() - Get the signature type ID associated to
 *                                      a name.
 * @name: Signature type name.
 * @id: Pointer where the ID is written.
 *
 * Return:
 * SMW_STATUS_SIGN_TYPE_NAME	- @name is unknown
 * SMW_STATUS_OK		- Success
 */
int smw_config_get_signature_type_id(smw_signature_type_t name,
				     enum smw_config_sign_type_id *id);

/**
 * smw_config_get_kdf_id() - Get the id of the Key Derivation Function name
 * @name: Name of the Key Derivation Function
 * @id: Key Derivation Function id found
 *
 * Note: If name is NULL, the returned @id is set SMW_CONFIG_KDF_ID_INVALID
 *       and function return SMW_STATUS_OK.
 *
 * Return:
 * SMW_STATUS_UNKNOWN_KDF_NAME  - @name is unknown
 * SMW_STATUS_OK                - Success
 */
int smw_config_get_kdf_id(smw_kdf_t name, enum smw_config_kdf_id *id);

/**
 * smw_config_get_asymm_encrypt_algo_id() - Get the asymmetric encryption algo
 *                                          ID associated to a name.
 * @name: Asymmetric encryption algorithm name.
 * @id: Pointer where the ID is written.
 *
 * Return:
 * SMW_STATUS_UNKNOWN_ALGO_NAME	- @name is unknown
 * SMW_STATUS_OK		        - Success
 */
int smw_config_get_asymm_encrypt_algo_id(smw_asymmetric_encryption_algo_t name,
					 enum smw_config_asymm_enc_algo_id *id);

/**
 * smw_config_get_asymm_encrypt_mode_id() - Get the asymmetric encryption mode
 *                                          ID associated to a name.
 * @name: Asymmetric encryption mode name.
 * @id: Pointer where the ID is written.
 *
 * Return:
 * SMW_STATUS_UNKNOWN_MODE_NAME	- @name is unknown
 * SMW_STATUS_OK		        - Success
 */
int smw_config_get_asymm_encrypt_mode_id(smw_asymmetric_encryption_mode_t name,
					 enum smw_config_asymm_enc_mode_id *id);

/**
 * smw_utils_asymm_enc_attr_to_ids() - Get the asymmetric encryption algo and
 *                                     mode IDs from algorithm attribute.
 * @attr: Algorithm attribute.
 * @algo_id: Pointer where the algorithm ID is written.
 * @mode_id: Pointer where the encryption mode ID is written.
 * @key_type_id: Pointer where the key type ID is written.
 *
 * Return:
 * SMW_STATUS_OK                       - Success
 * SMW_STATUS_OPERATION_NOT_SUPPORTED  - Not supported
 */
int smw_utils_asymm_enc_attr_to_ids(smw_attr_algo_t attr,
				    enum smw_config_asymm_enc_algo_id *algo_id,
				    enum smw_config_asymm_enc_mode_id *mode_id,
				    enum smw_config_key_type_id *key_type_id);

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

/**
 * smw_config_read_strings() - Read a list of strings.
 * @start: Address of the pointer to the current char.
 * @end: Pointer to the last char of the buffer being parsed.
 * @bitmap: Bitmap representing the configured strings.
 * @array: Array associating an ID (index) to a string (value).
 * @size: Size of @array.
 *
 * This function reads a list of strings from the current char
 * of the buffer being parsed until a semicolon is detected.
 * The pointer to the current char is moved to the next char
 * after the semicolon.
 * Insignificant chars are skipped if any.
 *
 * Return:
 * error code.
 */
int smw_config_read_strings(char **start, char *end, unsigned long *bitmap,
			    const char *const array[], unsigned int size);

/**
 * smw_utils_get_hash_algo_id() - Get the Hash algo ID associated to a name.
 * @name: Hash algo name.
 * @id: Pointer where the ID is written.
 *
 * This function gets the Hash algo ID associated to a name.
 *
 * Return:
 * error code.
 */
int smw_utils_get_hash_algo_id(smw_hash_algo_t name,
			       enum smw_config_hash_algo_id *id);

/**
 * smw_utils_hash_attr_to_algo_id() - Get the Hash algo ID from the algorithm
 *                                    attribute.
 * @attr: Algorithm attribute.
 * @algo_id: Pointer where the ID is written.
 *
 * Return:
 * SMW_STATUS_OK                       - Success
 * SMW_STATUS_OPERATION_NOT_SUPPORTED  - Not supported
 */
int smw_utils_hash_attr_to_algo_id(smw_attr_algo_t attr,
				   enum smw_config_hash_algo_id *algo_id);

/**
 * smw_utils_get_cipher_mode_id() - Get the cipher mode ID associated to a name
 * @name: Cipher mode name.
 * @id: Pointer where the ID is written.
 *
 * Return:
 * SMW_STATUS_UNKNOWN_MODE_NAME	- @name is unknown
 * SMW_STATUS_OK		- Success
 */
int smw_utils_get_cipher_mode_id(smw_cipher_mode_t name,
				 enum smw_config_cipher_mode_id *id);

/**
 * smw_utils_get_cipher_op_type_id() - Get the cipher operation type ID
 *                                      associated to a name
 * @name: Cipher operation type name.
 * @id: Pointer where the ID is written.
 *
 * Return:
 * SMW_STATUS_UNKNOWN_OP_TYPE_NAME	- @name is unknown
 * SMW_STATUS_OK			- Success
 */
int smw_utils_get_cipher_op_type_id(smw_cipher_op_type_t name,
				    enum smw_config_cipher_op_type_id *id);

/**
 * smw_utils_get_mac_algo_id() - Get MAC algo ID associated to a name.
 * @name: MAC algo name.
 * @id: Pointer where the ID is written.
 *
 * This function gets the MAC algo ID associated to a name.
 *
 * Return:
 * error code.
 */
int smw_utils_get_mac_algo_id(smw_mac_algo_t name,
			      enum smw_config_mac_algo_id *id);

/**
 * smw_utils_get_aead_mode_id() - Get the AEAD mode ID associated to a name
 * @name: AEAD mode name.
 * @id: Pointer where the ID is written.
 *
 * Return:
 * SMW_STATUS_UNKNOWN_MODE_NAME	- @name is unknown
 * SMW_STATUS_OK		- Success
 */
int smw_utils_get_aead_mode_id(smw_aead_mode_t name,
			       enum smw_config_aead_mode_id *id);

/**
 * smw_utils_get_aead_op_type_id() - Get the AEAD operation type ID
 *                                      associated to a name
 * @name: AEAD operation type name.
 * @id: Pointer where the ID is written.
 *
 * Return:
 * SMW_STATUS_UNKNOWN_OP_TYPE_NAME	- @name is unknown
 * SMW_STATUS_OK			- Success
 */
int smw_utils_get_aead_op_type_id(smw_aead_op_type_t name,
				  enum smw_config_aead_op_type_id *id);

#endif /* __CONFIG_H__ */
