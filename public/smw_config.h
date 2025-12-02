/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2026 NXP
 */

#ifndef __SMW_CONFIG_H__
#define __SMW_CONFIG_H__

#include <stdbool.h>

#include "smw_status.h"
#include "smw/names.h"

/**
 * smw_config_subsystem_present() - Check if the subsystem is present or not.
 * @subsystem: [in] Name of the subsystem.
 *
 * This function checks if a subsystem is present in the configuration.
 *
 * Return:
 *  - SMW_STATUS_OK:
 *      @subsystem is present.
 *  - SMW_STATUS_INVALID_PARAM:
 *      @subsystem is SMW_SUBSYSTEM_NAME_NONE.
 *  - SMW_STATUS_UNKNOWN_SUBSYSTEM_NAME:
 *      @subsystem is not valid.
 *  - Other error code from &enum smw_status_code
 */
enum smw_status_code smw_config_subsystem_present(smw_subsystem_t subsystem);

/**
 * smw_config_subsystem_loaded() - Return if the subsystem is loaded or not.
 * @subsystem: [in] Name of the subsystem.
 *
 * This functions returns if a subsystem is loaded and operational.
 *
 * Return:
 *  - SMW_STATUS_SUBSYSTEM_LOADED:
 *      @subsystem is loaded.
 *  - SMW_STATUS_SUBSYSTEM_NOT_LOADED:
 *      @subsystem is not loaded.
 *  - SMW_STATUS_INVALID_PARAM:
 *      @subsystem is SMW_SUBSYSTEM_NAME_NONE.
 *  - SMW_STATUS_UNKNOWN_SUBSYSTEM_NAME:
 *      @subsystem is not valid.
 *  - SMW_STATUS_INVALID_LIBRARY_CONTEXT:
 *      Library context is not valid.
 *  - Other error code from &enum smw_status_code
 */
enum smw_status_code smw_config_subsystem_loaded(smw_subsystem_t subsystem);

/**
 * smw_config_check_digest() - Check digest support.
 * @subsystem: [in] Name of the subsystem.
 * @algo: [in] Digest algorithm name.
 *
 * Function checks if the digest @algo is supported on the given subsystem or
 * default subsystem if @subsystem is not specified
 * (:ref:`SMW_SUBSYSTEM_NAME_NONE <smw_subsystem_t>`).
 *
 * Return:
 *  - SMW_STATUS_OK:
 *      @algo is supported.
 *  - SMW_STATUS_INVALID_PARAM:
 *      @algo is not specified.
 *  - SMW_STATUS_UNKNOWN_ALGO_NAME:
 *      @algo is not valid.
 *  - SMW_STATUS_OPERATION_NOT_CONFIGURED:
 *      @algo is not supported.
 *  - SMW_STATUS_UNKNOWN_SUBSYSTEM_NAME:
 *      @subsystem is not valid.
 *  - Other error code from &enum smw_status_code
 */
enum smw_status_code smw_config_check_digest(smw_subsystem_t subsystem,
					     smw_hash_algo_t algo);

/**
 * struct smw_key_info - Key information
 * @key_type_name: [in] Key type name. See &smw_key_type_t.
 * @security_size: [in] Key security size in bits.
 * @security_size_min: [out] Key security size minimum in bits.
 * @security_size_max: [out] Key security size maximum in bits.
 */
struct smw_key_info {
	smw_key_type_t key_type_name;
	unsigned int security_size;
	unsigned int security_size_min;
	unsigned int security_size_max;
};

/**
 * smw_config_check_generate_key() - Check key type generation support.
 * @subsystem: [in] Name of the subsystem.
 * @info: [in/out] Key information.
 *
 * Function checks if the key type provided in the @info structure can be
 * generated on the given subsystem or default subsystem if @subsystem is not
 * specified (:ref:`SMW_SUBSYSTEM_NAME_NONE <smw_subsystem_t>`).
 *
 * If @info's security size field is equal 0, returns the security key
 * range size in bits supported by the subsystem for the key type. Else
 * checks if the security size is supported.
 *
 * Return:
 *  - SMW_STATUS_OK:
 *      Key type is supported.
 *  - SMW_STATUS_INVALID_PARAM:
 *      - @info is NULL.
 *      - @info->key_type_name is SMW_KEY_TYPE_NAME_NONE.
 *  - SMW_STATUS_UNKNOWN_KEY_TYPE_NAME:
 *      @info->key_type_name is not valid.
 *  - SMW_STATUS_OPERATION_NOT_CONFIGURED:
 *      Key type is not supported.
 *  - SMW_STATUS_UNKNOWN_SUBSYSTEM_NAME:
 *      @subsystem is not valid.
 *  - Other error code from &enum smw_status_code
 */
enum smw_status_code smw_config_check_generate_key(smw_subsystem_t subsystem,
						   struct smw_key_info *info);

/**
 * smw_config_check_derive_key() - Check key derivation support.
 * @subsystem: [in] Name of the subsystem.
 * @kdf: [in] Key derivation name.
 *
 * Function checks if the @kdf is supported on the given subsystem or default
 * subsystem if @subsystem is not specified
 * (:ref:`SMW_SUBSYSTEM_NAME_NONE <smw_subsystem_t>`).
 *
 * Return:
 *  - SMW_STATUS_OK:
 *      Key derivation is supported.
 *  - SMW_STATUS_INVALID_PARAM:
 *      @kdf is SMW_KDF_NAME_NONE.
 *  - SMW_STATUS_UNKNOWN_KDF_NAME:
 *      @kdf is not valid key derivation name.
 *  - SMW_STATUS_OPERATION_NOT_CONFIGURED:
 *      @kdf is not supported.
 *  - SMW_STATUS_UNKNOWN_SUBSYSTEM_NAME:
 *      @subsystem is not valid.
 *  - Other error code from &enum smw_status_code
 */
enum smw_status_code smw_config_check_derive_key(smw_subsystem_t subsystem,
						 smw_kdf_t kdf);

/**
 * struct smw_signature_info - Signature operation information
 * @algo_name: [in] Signature algo name. See &typedef smw_signature_algo_t.
 * @type_name: [in] (**optional**) Signature type name.
 *             See &typedef smw_signature_type_t.
 * @hash_algo_name: [in] (**optional**) Hash algorithm name.
 *             See &typedef smw_hash_algo_t.
 */
struct smw_signature_info {
	smw_signature_algo_t algo_name;
	smw_signature_type_t type_name;
	smw_hash_algo_t hash_algo_name;
};

/**
 * smw_config_check_sign() - Check signature generation support.
 * @subsystem: [in] Name of the subsystem.
 * @info: [in] Signature information.
 *
 * Function checks if the signature generation supports the signature
 * information @info on the given subsystem or default subsystem if
 * @subsystem is not specified
 * (:ref:`SMW_SUBSYSTEM_NAME_NONE <smw_subsystem_t>`).
 *
 * The hash algorithm name field @info->hash_algo_name is optional. If set, the
 * function checks if given subsystem or default subsystem supports the
 * hash algorithm for the signature generation.
 *
 * The signature type name field @info->type_name is optional. If set, the
 * function checks if given subsystem or default subsystem supports the
 * signature type for the signature generation.
 *
 * Return:
 *  - SMW_STATUS_OK:
 *      Signature operation is supported.
 *  - SMW_STATUS_INVALID_PARAM:
 *      - @info is NULL.
 *      - @info->algo_name is SMW_SIGNATURE_ALGO_NAME_NONE.
 *  - SMW_STATUS_OPERATION_NOT_CONFIGURED:
 *      Signature operation is not supported.
 *  - SMW_STATUS_UNKNOWN_SUBSYSTEM_NAME:
 *      @subsystem is not valid.
 *  - Other error code from &enum smw_status_code
 */
enum smw_status_code smw_config_check_sign(smw_subsystem_t subsystem,
					   struct smw_signature_info *info);

/**
 * smw_config_check_verify() - Check signature verification support.
 * @subsystem: [in] Name of the subsystem.
 * @info: [in] Signature information.
 *
 * Function checks if the signature verification supports the signature
 * information @info on the given subsystem or default subsystem if
 * @subsystem is not specified
 * (:ref:`SMW_SUBSYSTEM_NAME_NONE <smw_subsystem_t>`).
 *
 * The hash algorithm name field @info->hash_algo_name is optional. If set, the
 * function checks if given subsystem or default subsystem supports the
 * hash algorithm for the signature verification.
 *
 * The signature type name field @info->type_name is optional. If set, the
 * function checks if given subsystem or default subsystem supports the
 * signature type for the signature verification.
 *
 * Return:
 *  - SMW_STATUS_OK:
 *      Verify operation is supported.
 *  - SMW_STATUS_INVALID_PARAM:
 *      - @info is NULL.
 *      - @info->algo_name is SMW_SIGNATURE_ALGO_NAME_NONE.
 *  - SMW_STATUS_OPERATION_NOT_CONFIGURED:
 *      Verify operation is not supported.
 *  - Other error code from &enum smw_status_code
 */
enum smw_status_code smw_config_check_verify(smw_subsystem_t subsystem,
					     struct smw_signature_info *info);

/**
 * struct smw_cipher_info - Cipher operation information
 * @multipart: [in] True if it's a cipher multi-part operation
 * @key_type_name: [in] Key type name. See &typedef smw_key_type_t
 * @mode_name: [in] Operation mode name. See &typedef smw_cipher_mode_t
 * @op_type_name: [in] Operation type name. See &typedef smw_cipher_op_type_t
 */
struct smw_cipher_info {
	bool multipart;
	smw_key_type_t key_type_name;
	smw_cipher_mode_t mode_name;
	smw_cipher_op_type_t op_type_name;
};

/**
 * smw_config_check_cipher() - Check cipher support.
 * @subsystem: [in] Name of the subsystem.
 * @info: [in] Cipher information.
 *
 * Function checks if the cipher information @info is supported on the given
 * subsystem or default subsystem if @subsystem is not specified
 * (:ref:`SMW_SUBSYSTEM_NAME_NONE <smw_subsystem_t>`).
 *
 * Return:
 *  - SMW_STATUS_OK:
 *      Cipher operation is supported.
 *  - SMW_STATUS_INVALID_PARAM:
 *      - @info is NULL.
 *      - @info->key_type_name is SMW_KEY_TYPE_NAME_NONE.
 *      - @info->mode_name is SMW_CIPHER_MODE_NAME_NONE.
 *      - @info->op_type_name is SMW_CIPHER_OP_TYPE_NAME_NONE.
 *  - SMW_STATUS_UNKNOWN_KEY_TYPE_NAME:
 *      @info->key_type_name is not valid.
 *  - SMW_STATUS_UNKNOWN_MODE_NAME:
 *      @info->mode_name is not valid.
 *  - SMW_STATUS_UNKNOWN_OP_TYPE_NAME:
 *      @info->op_type_name is not valid.
 *  - SMW_STATUS_OPERATION_NOT_CONFIGURED:
 *      Cipher operation is not supported.
 *  - SMW_STATUS_UNKNOWN_SUBSYSTEM_NAME:
 *      @subsystem is not valid.
 *  - Other error code from &enum smw_status_code
 */
enum smw_status_code smw_config_check_cipher(smw_subsystem_t subsystem,
					     struct smw_cipher_info *info);

/**
 * struct smw_aead_info - Authentication encryption operation information
 * @multipart: [in] True if it's a AEAD multi-part operation
 * @key_type_name: [in] Key type name. See &typedef smw_key_type_t
 * @mode_name: [in] Operation mode name. See &typedef smw_aead_mode_t
 * @op_type_name: [in] Operation type name. See &typedef smw_aead_op_type_t
 */
struct smw_aead_info {
	bool multipart;
	smw_key_type_t key_type_name;
	smw_aead_mode_t mode_name;
	smw_aead_op_type_t op_type_name;
};

/**
 * smw_config_check_aead() - Check authentication encryption support.
 * @subsystem: [in] Name of the subsystem.
 * @info: [in] AEAD information.
 *
 * Function checks if the authentication encryption information @info
 * is supported on the given subsystem or default subsystem if @subsystem
 * is not specified (:ref:`SMW_SUBSYSTEM_NAME_NONE <smw_subsystem_t>`).
 *
 * Return:
 *  - SMW_STATUS_OK:
 *      AEAD operation is supported.
 *  - SMW_STATUS_INVALID_PARAM:
 *      - @info is NULL.
 *      - @info->key_type_name is SMW_KEY_TYPE_NAME_NONE.
 *      - @info->mode_name is SMW_AEAD_MODE_NAME_NONE.
 *      - @info->op_type_name is SMW_AEAD_OP_TYPE_NAME_NONE.
 *  - SMW_STATUS_UNKNOWN_KEY_TYPE_NAME:
 *      @info->key_type_name is not valid.
 *  - SMW_STATUS_UNKNOWN_MODE_NAME:
 *      @info->mode_name is not valid.
 *  - SMW_STATUS_UNKNOWN_OP_TYPE_NAME:
 *      @info->op_type_name is not valid.
 *  - SMW_STATUS_OPERATION_NOT_CONFIGURED:
 *      AEAD operation is not supported.
 *  - SMW_STATUS_UNKNOWN_SUBSYSTEM_NAME:
 *      @subsystem is not valid.
 *  - Other error code from &enum smw_status_code
 */
enum smw_status_code smw_config_check_aead(smw_subsystem_t subsystem,
					   struct smw_aead_info *info);

/**
 * struct smw_mac_info - MAC operation information
 * @key_type_name: [in] Key type name. See &typedef smw_key_type_t
 * @mac_algo_name: [in] (**optional**) MAC algorithm name.
 *                 See &typedef smw_mac_algo_t
 * @hash_algo_name: [in] (**optional**) Hash algorithm name.
 *                  See &typedef smw_hash_algo_t
 */
struct smw_mac_info {
	smw_key_type_t key_type_name;
	smw_mac_algo_t mac_algo_name;
	smw_hash_algo_t hash_algo_name;
};

/**
 * smw_config_check_mac() - Check MAC support.
 * @subsystem: [in] Name of the subsystem.
 * @info: [in] MAC information.
 *
 * Function checks if the MAC information @info is supported on the given
 * subsystem or default subsystem if @subsystem is not specified
 * (:ref:`SMW_SUBSYSTEM_NAME_NONE <smw_subsystem_t>`).
 *
 * The hash algorithm name field @info->hash_algo_name is optional. If set, the
 * function checks if given subsystem or default subsystem supports the
 * hash algorithm for the MAC operation.
 *
 * The MAC algorithm name field @info->mac_algo_name is optional. If set, the
 * function checks if given subsystem or default subsystem supports the
 * MAC algorithm for the MAC operation.
 *
 * Return:
 *  - SMW_STATUS_OK:
 *      MAC operation is supported.
 *  - SMW_STATUS_INVALID_PARAM:
 *      - @info is NULL.
 *      - @info->key_type_name is SMW_KEY_TYPE_NAME_NONE.
 *  - SMW_STATUS_UNKNOWN_KEY_TYPE_NAME:
 *      @info->key_type_name is not valid.
 *  - SMW_STATUS_UNKNOWN_ALGO_NAME:
 *      @info->mac_algo_name or @info->hash_algo_name is not valid.
 *  - SMW_STATUS_OPERATION_NOT_CONFIGURED:
 *      MAC operation is not supported.
 *  - SMW_STATUS_UNKNOWN_SUBSYSTEM_NAME:
 *      @subsystem is not valid.
 *  - Other error code from &enum smw_status_code
 */
enum smw_status_code smw_config_check_mac(smw_subsystem_t subsystem,
					  struct smw_mac_info *info);

/**
 * smw_config_load() - Load a configuration.
 * @buffer: [in] pointer to the plaintext configuration.
 * @size: [in] size in bytes of the plaintext configuration.
 * @offset: [out] offset in plaintext configuration where parsing failed.
 *
 * This function loads a configuration.
 *
 * The plaintext configuration is parsed and the content is stored in the
 * library configuration database.
 *
 * If the parsing of plaintext configuration fails, @offset points to
 * the number of characters that have been correctly parsed.
 * The beginning of the remaining plaintext which cannot be parsed is printed
 * out.
 *
 * Return:
 *  - SMW_STATUS_OK:
 *      Configuration load is successful.
 *  - SMW_STATUS_INVALID_LIBRARY_CONTEXT:
 *      Library context is not valid.
 *  - SMW_STATUS_INVALID_BUFFER:
 *      - @buffer is NULL.
 *      - @size is 0.
 *  - SMW_STATUS_CONFIG_ALREADY_LOADED:
 *      A configuration is already loaded.
 *  - Other error code from &enum smw_status_code
 */
enum smw_status_code smw_config_load(char *buffer, unsigned int size,
				     unsigned int *offset);

/**
 * smw_config_unload() - Unload the current configuration.
 *
 * This function unloads the current configuration.
 *
 * It frees all memory dynamically allocated by SMW.
 *
 * Return:
 *  - SMW_STATUS_OK:
 *      Configuration unload is successful.
 *  - SMW_STATUS_INVALID_LIBRARY_CONTEXT
 *      Library context is not valid.
 *  - SMW_STATUS_NO_CONFIG_LOADED
 *      No configuration is loaded.
 *  - Other error code from &enum smw_status_code
 */
enum smw_status_code smw_config_unload(void);

/**
 * struct smw_asymmetric_encrypt_info - Asymmetric encryption/decryption
 *                                      operation information
 * @algo_name: [in] Encryption algorithm name.
 *             See &typedef smw_asymmetric_encryption_algo_t
 * @mode_name: [in] (**optional**) Encryption mode (padding scheme) name.
 *             See &typedef smw_asymmetric_encryption_mode_t
 * @hash_algo_name: [in] (**optional**) Hash algorithm name.
 *             See &typedef smw_hash_algo_t
 */
struct smw_asymmetric_encrypt_info {
	smw_asymmetric_encryption_algo_t algo_name;
	smw_asymmetric_encryption_mode_t mode_name;
	smw_hash_algo_t hash_algo_name;
};

/**
 * smw_config_check_asymmetric_encrypt() - Check asymmetric encryption support.
 * @subsystem: [in] Name of the subsystem.
 * @info: [in] Asymmetric encryption operation information.
 *
 * Function checks if the asymmetric encryption information @info is
 * supported on the given subsystem or default subsystem if @subsystem is not
 * specified (:ref:`SMW_SUBSYSTEM_NAME_NONE <smw_subsystem_t>`).
 *
 * The hash algorithm name field @info->hash_algo_name is optional. If set, the
 * function checks if given subsystem or default subsystem supports the
 * hash algorithm for the asymmetric encryption operation.
 *
 * The encryption mode name field @info->mode_name is optional. If set, the
 * function checks if given subsystem or default subsystem supports
 * the encryption mode for the asymmetric encryption operation.
 *
 * Return:
 *  - SMW_STATUS_OK:
 *      Encryption operation is supported.
 *  - SMW_STATUS_INVALID_PARAM:
 *      - @info is NULL.
 *      - @info->algo_name is SMW_ASYMMETRIC_ENCRYPTION_ALGO_NAME_NONE.
 *  - SMW_STATUS_OPERATION_NOT_CONFIGURED:
 *      Encryption operation is not supported.
 *  - SMW_STATUS_UNKNOWN_SUBSYSTEM_NAME:
 *      @subsystem is not valid.
 *  - Other error code from &enum smw_status_code
 */
enum smw_status_code
smw_config_check_asymmetric_encrypt(smw_subsystem_t subsystem,
				    struct smw_asymmetric_encrypt_info *info);

/**
 * smw_config_check_asymmetric_decrypt() - Check asymmetric decryption support.
 * @subsystem: [in] Name of the subsystem.
 * @info: [in] Asymmetric encryption operation information.
 *
 * Function checks if the asymmetric encryption information @info is
 * supported on the given @subsystem or default subsystem if @subsystem is not
 * specified (:ref:`SMW_SUBSYSTEM_NAME_NONE <smw_subsystem_t>`).
 *
 * The hash algorithm name field @info->hash_algo_name is optional. If set, the
 * function checks if given subsystem or default subsystem supports the
 * hash algorithm for the asymmetric decryption operation.
 *
 * The encryption mode name field @info->mode_name is optional. If set, the
 * function checks if given subsystem or default subsystem supports
 * the encryption mode for the asymmetric decryption operation.
 *
 * Return:
 *  - SMW_STATUS_OK:
 *      Decryption operation is supported.
 *  - SMW_STATUS_INVALID_PARAM:
 *      - @info is NULL.
 *      - @info->algo_name is SMW_ASYMMETRIC_ENCRYPTION_ALGO_NAME_NONE.
 *  - SMW_STATUS_OPERATION_NOT_CONFIGURED:
 *      Decryption operation is not supported.
 *  - SMW_STATUS_UNKNOWN_SUBSYSTEM_NAME:
 *      @subsystem is not valid.
 *  - Other error code from &enum smw_status_code
 */
enum smw_status_code
smw_config_check_asymmetric_decrypt(smw_subsystem_t subsystem,
				    struct smw_asymmetric_encrypt_info *info);

#endif /* __SMW_CONFIG_H__ */
