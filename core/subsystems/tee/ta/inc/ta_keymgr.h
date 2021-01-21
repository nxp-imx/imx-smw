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
