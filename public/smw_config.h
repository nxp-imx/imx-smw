/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2021 NXP
 */
#ifndef __SMW_CONFIG_H__
#define __SMW_CONFIG_H__

#include <stdbool.h>

/**
 * smw_config_subsystem_present() - Check if the subsystem is present or not.
 * @subsystem: Name of the subsystem
 *
 * Return:
 * SMW_STATUS_OK  Subsystem is present
 * error code otherwise
 */
int smw_config_subsystem_present(const char *subsystem);

/**
 * smw_config_check_digest() - Check if a digest @algo is supported
 * @subsystem: Name of the subsystem (if NULL default subsystem)
 * @algo: Digest algorithm name
 *
 * Function checks if the digest @algo is supported on the given @subsytem.
 * If @subsystem is NULL, default subsystem digest capability is checked.
 *
 * Return:
 * SMW_STATUS_OK                       Subsystem is present
 * SMW_STATUS_OPERATION_NOT_CONFIGURED Algorithm not supported
 * error code otherwise
 */
int smw_config_check_digest(const char *subsystem, const char *algo);

/**
 * struct smw_key_info - Key information
 * @key_type_name: Key type name
 * @security_size: Key security size in bits
 * @security_size_min: Key security size minimum in bits
 * @security_size_max: Key security size maximum in bits
 */
struct smw_key_info {
	const char *key_type_name;
	unsigned int security_size;
	unsigned int security_size_min;
	unsigned int security_size_max;
};

/**
 * smw_config_check_generate_key() - Check generate key type
 * @subsystem: Name of the subsystem (if NULL default subsystem)
 * @info: Key information
 *
 * Function checks if the key type provided in the @info structure is
 * supported on the given subsystem.
 *
 * If @info's security size field is equal 0, returns the security key
 * range size in bits supported by the subsystem for the key type. Else
 * checks if the security size is supported.
 *
 * If @subsystem is NULL, default subsystem digest capability is checked.
 *
 * Return:
 * SMW_STATUS_OK                       Subsystem is present
 * SMW_STATUS_OPERATION_NOT_CONFIGURED Algorithm not supported
 * error code otherwise
 */
int smw_config_check_generate_key(const char *subsystem,
				  struct smw_key_info *info);

/**
 * struct smw_signature_info - Signature operation information
 * @key_type_name: Key type name
 * @hash_algo: Hash algorithm name
 * @signature_type: Signature type name
 */
struct smw_signature_info {
	const char *key_type_name;
	const char *hash_algo;
	const char *signature_type;
};

/**
 * smw_config_check_sign() - Check if signature generation operation is
 *                           supported
 * @subsystem: Name of the subsystem (if NULL default subsystem)
 * @info: Signature information
 *
 * @info key type name field is mandatory.
 * @info hash algorithm name and signature type name fields are optional.
 *
 * Function checks if the key type provided in the @info structure is
 * supported on the given @subsystem for a signature generation operation.
 * If set, function checks if the hash algorithm is supported on the given
 * @subsytem for the signature generation operation.
 * If set, function checks if the signature type is supported on the given
 * @subsytem for the signature generation operation.
 *
 * If @subsystem is NULL, default subsystem digest capability is checked.
 *
 * Return:
 * SMW_STATUS_OK			- Parameter(s) is(are) supported
 * SMW_STATUS_OPERATION_NOT_CONFIGURED	- One of the parameters is not supported
 * error code otherwise
 */
int smw_config_check_sign(const char *subsystem,
			  struct smw_signature_info *info);

/**
 * smw_config_check_verify() - Check if signature verification operation is
 *                             supported
 * @subsystem: Name of the subsystem (if NULL default subsystem)
 * @info: Signature information
 *
 * @info key type name field is mandatory.
 * @info hash algorithm name and signature type name fields are optional.
 *
 * Function checks if the key type provided in the @info structure is
 * supported on the given @subsystem for a signature verification operation.
 * If set, function checks if the hash algorithm is supported on the given
 * @subsytem for the signature verification operation.
 * If set, function checks if the signature type is supported on the given
 * @subsytem for the signature verification operation.
 *
 * If @subsystem is NULL, default subsystem digest capability is checked.
 *
 * Return:
 * SMW_STATUS_OK			- Parameter(s) is(are) supported
 * SMW_STATUS_OPERATION_NOT_CONFIGURED	- One of the parameters is not supported
 * error code otherwise
 */
int smw_config_check_verify(const char *subsystem,
			    struct smw_signature_info *info);

/**
 * struct smw_cipher_info - Cipher operation information
 * @multipart: True if it's a cipher multi-part operation
 * @key_type_name: Key type name
 * @mode: Operation mode name
 * @op_type: Operation type name
 */
struct smw_cipher_info {
	bool multipart;
	const char *key_type_name;
	const char *mode;
	const char *op_type;
};

/**
 * smw_config_check_cipher() - Check if cipher operation is supported
 * @subsystem: Name of the subsystem (if NULL default subsystem)
 * @info: Cipher information
 *
 * Function checks if all the fields provided in the @info structure are
 * supported on the given @subsystem for a cipher one-shot or multi-part
 * operation.
 *
 * If @subsystem is NULL, default subsystem cipher capability is checked.
 *
 * Return:
 * SMW_STATUS_OK			- Parameters are supported
 * SMW_STATUS_OPERATION_NOT_CONFIGURED	- One of the parameters is not supported
 * error code otherwise
 */
int smw_config_check_cipher(const char *subsystem,
			    struct smw_cipher_info *info);

#endif /* __SMW_CONFIG_H__ */
