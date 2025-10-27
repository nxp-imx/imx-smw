/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2025 NXP
 */

#ifndef __SMW_CONFIG_H__
#define __SMW_CONFIG_H__

#include <stdbool.h>

#include "smw_status.h"
#include "smw/names.h"

/**
 * DOC:
 * The configuration APIs allow user of the library to:
 *  - Get information about the state of the Secure Subsystems.
 *  - Get the capabilities of the library operations.
 *  - Load/Unload library configuration.
 */

/**
 * smw_config_subsystem_present() - Check if the subsystem is present or not.
 * @subsystem: Name of the subsystem.
 *
 * Return:
 * See &enum smw_status_code
 *	- SMW_STATUS_OK:
 *		@subsystem is present
 *	- SMW_STATUS_INVALID_PARAM:
 *		@subsystem is SMW_SUBSYSTEM_NAME_NONE
 *	- SMW_STATUS_UNKNOWN_SUBSYSTEM_NAME:
 *		@subsystem is not valid
 */
enum smw_status_code smw_config_subsystem_present(smw_subsystem_t subsystem);

/**
 * smw_config_subsystem_loaded() - Return if the subsystem is loaded or not.
 * @subsystem: Name of the subsystem.
 *
 * Return:
 * See &enum smw_status_code
 *	- SMW_STATUS_SUBSYSTEM_LOADED:
 *		@subsystem is loaded
 *	- SMW_STATUS_SUBSYSTEM_NOT_LOADED:
 *		@subsystem is not loaded
 *	- SMW_STATUS_INVALID_PARAM:
 *		@subsystem is SMW_SUBSYSTEM_NAME_NONE
 *	- SMW_STATUS_UNKNOWN_SUBSYSTEM_NAME:
 *		@subsystem is not valid
 *	- SMW_STATUS_INVALID_LIBRARY_CONTEXT:
 *		Library context is not valid
 */
enum smw_status_code smw_config_subsystem_loaded(smw_subsystem_t subsystem);

/**
 * smw_config_check_digest() - Check if a digest @algo is supported
 * @subsystem: Name of the subsystem.
 * @algo: Digest algorithm name.
 *
 * Function checks if the digest @algo is supported on the given @subsystem.
 * If @subsystem is SMW_SUBSYSTEM_NAME_NONE, default subsystem digest
 * capability is checked.
 *
 * Return:
 * See &enum smw_status_code
 *	- SMW_STATUS_OK:
 *		@algo is supported
 *	- SMW_STATUS_INVALID_PARAM:
 *		@algo is SMW_HASH_ALGO_NAME_NONE
 *	- SMW_STATUS_UNKNOWN_ALGO_NAME:
 *		@algo is not valid
 *	- SMW_STATUS_OPERATION_NOT_CONFIGURED:
 *		@algo is not supported
 *	- SMW_STATUS_UNKNOWN_SUBSYSTEM_NAME:
 *		@subsystem is not valid
 */
enum smw_status_code smw_config_check_digest(smw_subsystem_t subsystem,
					     smw_hash_algo_t algo);

/**
 * struct smw_key_info - Key information
 * @key_type_name: Key type name. See &typedef smw_key_type_t
 * @security_size: Key security size in bits
 * @security_size_min: Key security size minimum in bits
 * @security_size_max: Key security size maximum in bits
 */
struct smw_key_info {
	smw_key_type_t key_type_name;
	unsigned int security_size;
	unsigned int security_size_min;
	unsigned int security_size_max;
};

/**
 * smw_config_check_generate_key() - Check generate key type
 * @subsystem: Name of the subsystem.
 * @info: Key information.
 *
 * Function checks if the key type provided in the @info structure is
 * supported on the given subsystem.
 *
 * If @info's security size field is equal 0, returns the security key
 * range size in bits supported by the subsystem for the key type. Else
 * checks if the security size is supported.
 *
 * If @subsystem is SMW_SUBSYSTEM_NAME_NONE, default subsystem key generation
 * is checked.
 *
 * Return:
 * See &enum smw_status_code
 *	- SMW_STATUS_OK:
 *		Key type is supported
 *	- SMW_STATUS_INVALID_PARAM:
 *		@info is NULL or @info->key_type_name is SMW_KEY_TYPE_NAME_NONE
 *	- SMW_STATUS_UNKNOWN_KEY_TYPE_NAME:
 *		@info->key_type_name is not valid
 *	- SMW_STATUS_OPERATION_NOT_CONFIGURED:
 *		Key type is not supported
 *	- SMW_STATUS_UNKNOWN_SUBSYSTEM_NAME:
 *		@subsystem is not valid
 */
enum smw_status_code smw_config_check_generate_key(smw_subsystem_t subsystem,
						   struct smw_key_info *info);

/**
 * smw_config_check_derive_key() - Check if KDF @kdf is supported.
 * @subsystem: Name of the subsystem.
 * @kdf: KDF name.
 *
 * Function checks if the KDF @kdf is supported on the given subsystem.
 *
 * If @subsystem is SMW_SUBSYSTEM_NAME_NONE, function checks if the KDF is
 * supported on the default subsystem.
 *
 * Return:
 * See &enum smw_status_code
 *	- SMW_STATUS_OK:
 *		KDF is supported
 *	- SMW_STATUS_INVALID_PARAM:
 *		@kdf is SMW_KDF_NAME_NONE
 *	- SMW_STATUS_UNKNOWN_KDF_NAME:
 *		@kdf is not valid KDF
 *	- SMW_STATUS_OPERATION_NOT_CONFIGURED:
 *		@kdf is not supported
 *	- SMW_STATUS_UNKNOWN_SUBSYSTEM_NAME:
 *		@subsystem is not valid
 */
enum smw_status_code smw_config_check_derive_key(smw_subsystem_t subsystem,
						 smw_kdf_t kdf);

/**
 * struct smw_signature_info - Signature operation information
 * @algo_name: Signature algo name. See &typedef smw_signature_algo_t
 * @type_name: Signature type name. See &typedef smw_signature_type_t
 * @hash_algo_name: Hash algorithm name. See &typedef smw_hash_algo_t
 */
struct smw_signature_info {
	smw_signature_algo_t algo_name;
	smw_signature_type_t type_name;
	smw_hash_algo_t hash_algo_name;
};

/**
 * smw_config_check_sign() - Check if signature generation operation is
 *                           supported
 * @subsystem: Name of the subsystem.
 * @info: Signature information.
 *
 * @info hash algorithm name and signature type name fields are optional.
 *
 * If set, function checks if the hash algorithm is supported on the given
 * @subsystem for the signature generation operation.
 * If set, function checks if the signature type is supported on the given
 * @subsystem for the signature generation operation.
 *
 * If @subsystem is SMW_SUBSYSTEM_NAME_NONE, default subsystem signature
 * generation capability is checked.
 *
 * Return:
 * See &enum smw_status_code
 *	- SMW_STATUS_OK:
 *		Signature operation is supported
 *	- SMW_STATUS_INVALID_PARAM:
 *		@info is NULL or @info->algo_name is
 *		SMW_SIGNATURE_ALGO_NAME_NONE
 *	- SMW_STATUS_OPERATION_NOT_CONFIGURED:
 *		Signature operation is not supported
 *	- SMW_STATUS_UNKNOWN_SUBSYSTEM_NAME:
 *		@subsystem is not valid
 */
enum smw_status_code smw_config_check_sign(smw_subsystem_t subsystem,
					   struct smw_signature_info *info);

/**
 * smw_config_check_verify() - Check if signature verification operation is
 *                             supported
 * @subsystem: Name of the subsystem.
 * @info: Signature information.
 *
 * @info hash algorithm name and signature type name fields are optional.
 *
 * If set, function checks if the hash algorithm is supported on the given
 * @subsystem for the signature verification operation.
 * If set, function checks if the signature type is supported on the given
 * @subsystem for the signature verification operation.
 *
 * If @subsystem is SMW_SUBSYSTEM_NAME_NONE, default subsystem signature
 * verification capability is checked.
 *
 * Return:
 * See &enum smw_status_code
 *	- SMW_STATUS_OK:
 *		Verify operation is supported
 *	- SMW_STATUS_INVALID_PARAM:
 *		@info is NULL or @info->algo_name is
 *		SMW_SIGNATURE_ALGO_NAME_NONE
 *	- SMW_STATUS_OPERATION_NOT_CONFIGURED:
 *		Verify operation is not supported
 */
enum smw_status_code smw_config_check_verify(smw_subsystem_t subsystem,
					     struct smw_signature_info *info);

/**
 * struct smw_cipher_info - Cipher operation information
 * @multipart: True if it's a cipher multi-part operation
 * @key_type_name: Key type name. See &typedef smw_key_type_t
 * @mode_name: Operation mode name. See &typedef smw_cipher_mode_t
 * @op_type_name: Operation type name. See &typedef smw_cipher_op_type_t
 */
struct smw_cipher_info {
	bool multipart;
	smw_key_type_t key_type_name;
	smw_cipher_mode_t mode_name;
	smw_cipher_op_type_t op_type_name;
};

/**
 * smw_config_check_cipher() - Check if cipher operation is supported
 * @subsystem: Name of the subsystem.
 * @info: Cipher information.
 *
 * Function checks if all fields provided in the @info structure are
 * supported on the given @subsystem for a cipher one-shot or multi-part
 * operation.
 *
 * If @subsystem is SMW_SUBSYSTEM_NAME_NONE, default subsystem cipher
 * capability is checked.
 *
 * Return:
 * See &enum smw_status_code
 *	- SMW_STATUS_OK:
 *		Cipher operation is supported
 *	- SMW_STATUS_INVALID_PARAM:
 *		@info is NULL or @info->key_type_name is SMW_KEY_TYPE_NAME_NONE
 *		or @info->mode_name is SMW_CIPHER_MODE_NAME_NONE or
 *		@info->op_type_name is SMW_CIPHER_OP_TYPE_NAME_NONE
 *	- SMW_STATUS_UNKNOWN_KEY_TYPE_NAME:
 *		@info->key_type_name is not valid
 *	- SMW_STATUS_UNKNOWN_MODE_NAME:
 *		 @info->mode is not valid
 *	- SMW_STATUS_UNKNOWN_OP_TYPE_NAME:
 *		@info->op_type is not valid
 *	- SMW_STATUS_OPERATION_NOT_CONFIGURED:
 *		Cipher operation is not supported
 *	- SMW_STATUS_UNKNOWN_SUBSYSTEM_NAME:
 *		@subsystem is not valid
 */
enum smw_status_code smw_config_check_cipher(smw_subsystem_t subsystem,
					     struct smw_cipher_info *info);

/**
 * struct smw_aead_info - AEAD operation information
 * @multipart: True if it's a AEAD multi-part operation
 * @key_type_name: Key type name. See &typedef smw_key_type_t
 * @mode_name: Operation mode name. See &typedef smw_aead_mode_t
 * @op_type_name: Operation type name. See &typedef smw_aead_op_type_t
 */
struct smw_aead_info {
	bool multipart;
	smw_key_type_t key_type_name;
	smw_aead_mode_t mode_name;
	smw_aead_op_type_t op_type_name;
};

/**
 * smw_config_check_aead() - Check if AEAD operation is supported
 * @subsystem: Name of the subsystem.
 * @info: AEAD information.
 *
 * Function checks if all fields provided in the @info structure are
 * supported on the given @subsystem for a AEAD one-shot or multi-part
 * operation.
 *
 * If @subsystem is SMW_SUBSYSTEM_NAME_NONE, default subsystem AEAD capability
 * is checked.
 *
 * Return:
 * See &enum smw_status_code
 *	- SMW_STATUS_OK:
 *		AEAD operation is supported
 *	- SMW_STATUS_INVALID_PARAM:
 *		@info is NULL or @info->key_type_name is SMW_KEY_TYPE_NAME_NONE
 *		or @info->mode_name is SMW_AEAD_MODE_NAME_NONE or
 *		@info->op_type_name is SMW_AEAD_OP_TYPE_NAME_NONE
 *	- SMW_STATUS_UNKNOWN_KEY_TYPE_NAME:
 *		@info->key_type_name is not valid
 *	- SMW_STATUS_UNKNOWN_MODE_NAME:
 *		 @info->mode is not valid
 *	- SMW_STATUS_UNKNOWN_OP_TYPE_NAME:
 *		@info->op_type is not valid
 *	- SMW_STATUS_OPERATION_NOT_CONFIGURED:
 *		AEAD operation is not supported
 *	- SMW_STATUS_UNKNOWN_SUBSYSTEM_NAME:
 *		@subsystem is not valid
 */
enum smw_status_code smw_config_check_aead(smw_subsystem_t subsystem,
					   struct smw_aead_info *info);

/**
 * struct smw_mac_info - MAC operation information
 * @key_type_name: Key type name. See &typedef smw_key_type_t
 * @mac_algo_name: MAC algorithm name. See &typedef smw_mac_algo_t
 * @hash_algo_name: Hash algorithm name. See &typedef smw_hash_algo_t
 */
struct smw_mac_info {
	smw_key_type_t key_type_name;
	smw_mac_algo_t mac_algo_name;
	smw_hash_algo_t hash_algo_name;
};

/**
 * smw_config_check_mac() - Check if MAC operation is supported
 * @subsystem: Name of the subsystem.
 * @info: MAC information.
 *
 * Function checks if all fields provided in the @info structure are
 * supported on the given @subsystem for MAC operation.
 * If set, function checks if the hash algorithm is supported on the given
 * @subsystem for the signature generation operation.
 * If set, function checks if the MAC algorithm is supported on the given
 * @subsystem for the signature generation operation.
 *
 * If @subsystem is SMW_SUBSYSTEM_NAME_NONE, default subsystem MAC capability
 * is checked.
 *
 * Return:
 * See &enum smw_status_code
 *	- SMW_STATUS_OK:
 *		MAC operation is supported
 *	- SMW_STATUS_INVALID_PARAM:
 *		@info is NULL or @info->key_type_name is SMW_KEY_TYPE_NAME_NONE
 *	- SMW_STATUS_UNKNOWN_KEY_TYPE_NAME:
 *		@info->key_type_name is not valid
 *	- SMW_STATUS_UNKNOWN_ALGO_NAME:
 *		 @info->mac_algo or @info->hash_algo is not valid
 *	- SMW_STATUS_OPERATION_NOT_CONFIGURED:
 *		MAC operation is not supported
 *	- SMW_STATUS_UNKNOWN_SUBSYSTEM_NAME:
 *		@subsystem is not valid
 */
enum smw_status_code smw_config_check_mac(smw_subsystem_t subsystem,
					  struct smw_mac_info *info);

/**
 * smw_config_load() - Load a configuration.
 * @buffer: pointer to the plaintext configuration.
 * @size: size of the plaintext configuration.
 * @offset: current offset in plaintext configuration.
 *
 * This function loads a configuration.
 * The plaintext configuration is parsed and
 * the content is stored in the Configuration database.
 * If the parsing of plaintext configuration fails, @offset points to
 * the number of characters that have been correctly parsed.
 * The beginning of the remaining plaintext which cannot be parsed is printed
 * out.
 *
 * Return:
 * SMW_STATUS_OK			- Configuration load is successful
 * SMW_STATUS_INVALID_LIBRARY_CONTEXT	- Library context is not valid
 * SMW_STATUS_INVALID_BUFFER		- @buffer is NULL or @size is 0
 * SMW_STATUS_CONFIG_ALREADY_LOADED	- A configuration is already loaded
 * error code otherwise
 */
enum smw_status_code smw_config_load(char *buffer, unsigned int size,
				     unsigned int *offset);

/**
 * smw_config_unload() - Unload the current configuration.
 *
 * This function unloads the current configuration.
 * It frees all memory dynamically allocated by SMW.
 *
 * Return:
 * SMW_STATUS_OK			- Configuration unload is successful
 * SMW_STATUS_INVALID_LIBRARY_CONTEXT	- Library context is not valid
 * SMW_STATUS_NO_CONFIG_LOADED		- No configuration is loaded
 */
enum smw_status_code smw_config_unload(void);

/**
 * struct smw_asymmetric_encrypt_info - Asymmetric encryption/decryption
 *                                      operation information
 * @algo_name: Encryption/decryption algorithm name.
 *             See &typedef smw_asymmetric_encryption_algo_t
 * @mode_name: Encryption/decryption mode (padding scheme) name.
 *             See &typedef smw_asymmetric_encryption_mode_t
 * @hash_algo_name: Hash algorithm name. See &typedef smw_hash_algo_t
 */
struct smw_asymmetric_encrypt_info {
	smw_asymmetric_encryption_algo_t algo_name;
	smw_asymmetric_encryption_mode_t mode_name;
	smw_hash_algo_t hash_algo_name;
};

/**
 * smw_config_check_asymmetric_encrypt() - Check if asymmetric encryption
 *                                         operation is supported
 * @subsystem: Name of the subsystem.
 * @info: Asymmetric encryption/decryption operation information.
 *
 * @info.hash_algo_name and @info.mode_name fields are optional.
 * @info.algo_name is mandatory filed and the function checks if the algorithm
 * is supported on the given @subsystem for the asymmetric encryption operation.
 * If @info.hash_algo_name is set, function checks if the hash algorithm is
 * supported on the given @subsystem for the asymmetric encryption operation.
 * If @info.mode_name is set, function checks if the encryption mode is
 * supported on the given @subsystem for the asymmetric encryption operation.
 *
 * If @subsystem is SMW_SUBSYSTEM_NAME_NONE, default subsystem asymmetric
 * encryption capability is checked.
 *
 * Return:
 * See &enum smw_status_code
 *	- SMW_STATUS_OK:
 *		Encryption operation is supported
 *	- SMW_STATUS_INVALID_PARAM:
 *		@info is NULL or @info->algo_name is
 *		SMW_ASYMMETRIC_ENCRYPTION_ALGO_NAME_NONE
 *	- SMW_STATUS_OPERATION_NOT_CONFIGURED:
 *		Encryption operation is not supported
 *	- SMW_STATUS_UNKNOWN_SUBSYSTEM_NAME:
 *		@subsystem is not valid
 */
enum smw_status_code
smw_config_check_asymmetric_encrypt(smw_subsystem_t subsystem,
				    struct smw_asymmetric_encrypt_info *info);

/**
 * smw_config_check_asymmetric_decrypt() - Check if asymmetric decryption
 *                                         operation is supported
 * @subsystem: Name of the subsystem.
 * @info: Asymmetric encryption/decryption operation information.
 *
 * @info.hash_algo_name and @info.mode_name fields are optional.
 * @info.algo_name is mandatory filed and the function checks if the algorithm
 * is supported on the given @subsystem for the asymmetric decryption operation.
 * If @info.hash_algo_name is set, function checks if the hash algorithm is
 * supported on the given @subsystem for the asymmetric decryption operation.
 * If @info.mode_name is set, function checks if the decryption mode is
 * supported on the given @subsystem for the asymmetric decryption operation.
 *
 * If @subsystem is SMW_SUBSYSTEM_NAME_NONE, default subsystem asymmetric
 * decryption capability is checked.
 *
 * Return:
 * See &enum smw_status_code
 *	- SMW_STATUS_OK:
 *		Decryption operation is supported
 *	- SMW_STATUS_INVALID_PARAM:
 *		@info is NULL or @info->algo_name is
 *		SMW_ASYMMETRIC_ENCRYPTION_ALGO_NAME_NONE
 *	- SMW_STATUS_OPERATION_NOT_CONFIGURED:
 *		Decryption operation is not supported
 *	- SMW_STATUS_UNKNOWN_SUBSYSTEM_NAME:
 *		@subsystem is not valid
 */
enum smw_status_code
smw_config_check_asymmetric_decrypt(smw_subsystem_t subsystem,
				    struct smw_asymmetric_encrypt_info *info);

#endif /* __SMW_CONFIG_H__ */
