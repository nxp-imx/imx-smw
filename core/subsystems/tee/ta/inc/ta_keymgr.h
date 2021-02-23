/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2021 NXP
 */

#ifndef TA_KEYMGR_H
#define TA_KEYMGR_H

#ifndef BITS_TO_BYTES_SIZE
#define BITS_TO_BYTES_SIZE(security_size) (((security_size) + 7) / 8)
#endif

/**
 * generate_key() - Generate a key.
 * @param_types: Parameters types.
 * @params: Shared parameters between Secure and Normal world.
 *
 * Key ID is not updated if function returned an error.
 *
 * Return:
 * TEE_SUCCESS			- Success.
 * TEE_ERROR_BAD_PARAMETERS	- One of the parameters is invalid.
 * TEE_ERROR_OUT_OF_MEMORY	- Memory allocation failed.
 * Error code from internal functions.
 */
TEE_Result generate_key(uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS]);

/**
 * delete_key() - Delete a key.
 * @param_types: Parameters types.
 * @params: Shared parameters between Secure and Normal world.
 *
 * Key is deleted from linked list and object (transient or persistent) is
 * freed.
 *
 * Return:
 * TEE_SUCCESS			- Success.
 * TEE_ERROR_BAD_PARAMETERS	- One of the parameters is invalid.
 * Error code from internal functions.
 */
TEE_Result delete_key(uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS]);

/**
 * ta_import_key() - Import a TEE transient key.
 * @key_handle: Key handle.
 * @key_type: Key type.
 * @security_size: Key security size.
 * @priv_key: Pointer to private key buffer.
 * @priv_key_len: @priv_key length in bytes.
 * @pub_key: Pointer to public key buffer.
 * @pub_key_len: @pub_key length in bytes.
 *
 * If the operation is successful @key_handle is allocated by the function
 * and must be freed by the caller.
 *
 * Return:
 * TEE_SUCCESS			- Success.
 * TEE_ERROR_BAD_PARAMETERS	- One of the parameters is invalid.
 * Error code from internal functions.
 */
TEE_Result ta_import_key(TEE_ObjectHandle *key_handle,
			 enum tee_key_type key_type, unsigned int security_size,
			 unsigned char *priv_key, unsigned int priv_key_len,
			 unsigned char *pub_key, unsigned int pub_key_len);

/**
 * import_key() - Import a key or keypair.
 * @param_types: Parameters types.
 * @params: Shared parameters between Secure and Normal world.
 *
 * A symmetric key, an asymmetric public key or an asymmetric keypair
 * can be imported.
 * Keys can be BASE64 format. In this case they are decoded into HEX format
 * before import.
 * Subsystem ID is not updated if function returned an error.
 *
 * Return:
 * TEE_SUCCESS			- Success.
 * TEE_ERROR_BAD_PARAMETERS	- One of the parameters is invalid.
 * TEE_ERROR_OUT_OF_MEMORY	- Memory allocation failed.
 * Error code from internal functions.
 */
TEE_Result import_key(uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS]);

/**
 * ta_get_key_handle() - Get the TEE key object handle of a given key ID.
 * @key_handle: Key handle.
 * @key_id: Key ID.
 * @persistent: Set to true if key object is persistent.
 *
 * Return:
 * TEE_SUCCESS			- Success.
 * Error code from internal functions.
 */
TEE_Result ta_get_key_handle(TEE_ObjectHandle *key_handle, uint32_t key_id,
			     bool *persistent);

/**
 * export_key() - Export a key.
 * @param_types: Parameters types.
 * @params: Shared parameters between Secure and Normal world.
 *
 * This function only supports the export of a ECDSA NIST public key.
 *
 * Return:
 * TEE_SUCCESS			- Success.
 * TEE_ERROR_BAD_PARAMETERS	- One of the parameters is invalid.
 * Error code from internal functions.
 */
TEE_Result export_key(uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS]);

/**
 * clear_key_linked_list() - Clear key linked list.
 *
 * This function is called when the TA session is closed. Its goal is to
 * free all key transient objects and free key linked list resources.
 *
 * Return:
 * TEE_SUCCESS	- Success.
 * Error code from key_del_list() function.
 */
TEE_Result clear_key_linked_list(void);

#endif /* TA_KEYMGR_H */
