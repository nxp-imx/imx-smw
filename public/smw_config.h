/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2021 NXP
 */

#ifndef __SMW_CONFIG_H__
#define __SMW_CONFIG_H__

#include <stdbool.h>

#include "smw_status.h"
#include "smw_strings.h"

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
 *		@subsystem is NULL
 *	- SMW_STATUS_UNKNOWN_NAME:
 *		@subsystem is not a valid string
 */
enum smw_status_code smw_config_subsystem_present(smw_subsystem_t subsystem);

/**
 * smw_config_check_digest() - Check if a digest @algo is supported
 * @subsystem: Name of the subsystem (if NULL default subsystem).
 * @algo: Digest algorithm name.
 *
 * Function checks if the digest @algo is supported on the given @subsystem.
 * If @subsystem is NULL, default subsystem digest capability is checked.
 *
 * Return:
 * See &enum smw_status_code
 *	- SMW_STATUS_OK:
 *		@algo is supported
 *	- SMW_STATUS_INVALID_PARAM:
 *		@algo is NULL
 *	- SMW_STATUS_UNKNOWN_NAME:
 *		@algo is not a valid string
 *	- SMW_STATUS_OPERATION_NOT_CONFIGURED:
 *		@algo is not supported
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
 * @subsystem: Name of the subsystem (if NULL default subsystem).
 * @info: Key information
 *
 * Function checks if the key type provided in the @info structure is
 * supported on the given subsystem.
 *
 * If @info's security size field is equal 0, returns the security key
 * range size in bits supported by the subsystem for the key type. Else
 * checks if the security size is supported.
 *
 * If @subsystem is NULL, default subsystem key generation is checked.
 *
 * Return:
 * See &enum smw_status_code
 *	- SMW_STATUS_OK:
 *		Key type is supported
 *	- SMW_STATUS_INVALID_PARAM:
 *		@info or @info->key_type_name is NULL
 *	- SMW_STATUS_UNKNOWN_NAME:
 *		@info->key_type_name is not a valid string
 *	- SMW_STATUS_OPERATION_NOT_CONFIGURED:
 *		Key type is not supported
 */
enum smw_status_code smw_config_check_generate_key(smw_subsystem_t subsystem,
						   struct smw_key_info *info);

/**
 * struct smw_signature_info - Signature operation information
 * @key_type_name: Key type name. See &typedef smw_key_type_t
 * @hash_algo: Hash algorithm name. See &typedef smw_hash_algo_t
 * @signature_type: Signature type name. See &typedef smw_signature_type_t
 */
struct smw_signature_info {
	smw_key_type_t key_type_name;
	smw_hash_algo_t hash_algo;
	smw_signature_type_t signature_type;
};

/**
 * smw_config_check_sign() - Check if signature generation operation is
 *                           supported
 * @subsystem: Name of the subsystem (if NULL default subsystem).
 * @info: Signature information
 *
 * @info key type name field is mandatory.
 * @info hash algorithm name and signature type name fields are optional.
 *
 * Function checks if the key type provided in the @info structure is
 * supported on the given @subsystem for a signature generation operation.
 * If set, function checks if the hash algorithm is supported on the given
 * @subsystem for the signature generation operation.
 * If set, function checks if the signature type is supported on the given
 * @subsystem for the signature generation operation.
 *
 * If @subsystem is NULL, default subsystem digest capability is checked.
 *
 * Return:
 * See &enum smw_status_code
 *	- SMW_STATUS_OK:
 *		Signature operation is supported
 *	- SMW_STATUS_INVALID_PARAM:
 *		@info or @info->key_type_name is NULL
 *	- SMW_STATUS_UNKNOWN_NAME:
 *		@info->key_type_name is not a valid string
 *	- SMW_STATUS_OPERATION_NOT_CONFIGURED:
 *		Signature operation is not supported
 */
enum smw_status_code smw_config_check_sign(smw_subsystem_t subsystem,
					   struct smw_signature_info *info);

/**
 * smw_config_check_verify() - Check if signature verification operation is
 *                             supported
 * @subsystem: Name of the subsystem (if NULL default subsystem).
 * @info: Signature information
 *
 * @info key type name field is mandatory.
 * @info hash algorithm name and signature type name fields are optional.
 *
 * Function checks if the key type provided in the @info structure is
 * supported on the given @subsystem for a signature verification operation.
 * If set, function checks if the hash algorithm is supported on the given
 * @subsystem for the signature verification operation.
 * If set, function checks if the signature type is supported on the given
 * @subsystem for the signature verification operation.
 *
 * If @subsystem is NULL, default subsystem digest capability is checked.
 *
 * Return:
 * See &enum smw_status_code
 *	- SMW_STATUS_OK:
 *		Verify operation is supported
 *	- SMW_STATUS_INVALID_PARAM:
 *		@info or @info->key_type_name is NULL
 *	- SMW_STATUS_UNKNOWN_NAME:
 *		@info->key_type_name is not a valid string
 *	- SMW_STATUS_OPERATION_NOT_CONFIGURED:
 *		Verify operation is not supported
 */
enum smw_status_code smw_config_check_verify(smw_subsystem_t subsystem,
					     struct smw_signature_info *info);

/**
 * struct smw_cipher_info - Cipher operation information
 * @multipart: True if it's a cipher multi-part operation
 * @key_type_name: Key type name. See &typedef smw_key_type_t
 * @mode: Operation mode name. See &typedef smw_cipher_mode_t
 * @op_type: Operation type name. See &typedef smw_cipher_operation_t
 */
struct smw_cipher_info {
	bool multipart;
	smw_key_type_t key_type_name;
	smw_cipher_mode_t mode;
	smw_cipher_operation_t op_type;
};

/**
 * smw_config_check_cipher() - Check if cipher operation is supported
 * @subsystem: Name of the subsystem (if NULL default subsystem).
 * @info: Cipher information
 *
 * Function checks if all fields provided in the @info structure are
 * supported on the given @subsystem for a cipher one-shot or multi-part
 * operation.
 *
 * If @subsystem is NULL, default subsystem cipher capability is checked.
 *
 * Return:
 * See &enum smw_status_code
 *	- SMW_STATUS_OK:
 *		Cipher operation is supported
 *	- SMW_STATUS_INVALID_PARAM:
 *		@info, @info->key_type_name, @info->mode or @info->op_type is NULL
 *	- SMW_STATUS_UNKNOWN_NAME:
 *		@info->key_type_name, @info->mode or @info->op_type is not a valid string
 *	- SMW_STATUS_OPERATION_NOT_CONFIGURED:
 *		Cipher operation is not supported
 */
enum smw_status_code smw_config_check_cipher(smw_subsystem_t subsystem,
					     struct smw_cipher_info *info);

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
 * SMW_STATUS_OK		- Configuration unload is successful
 * SMW_STATUS_NO_CONFIG_LOADED	- No configuration is loaded
 */
enum smw_status_code smw_config_unload(void);

#endif /* __SMW_CONFIG_H__ */
