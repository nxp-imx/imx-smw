/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2023-2026 NXP
 */

#ifndef __SMW_STORAGE_H__
#define __SMW_STORAGE_H__

#include "smw_status.h"
#include "smw/attr.h"
#include "smw/names.h"

/**
 * struct smw_data_attributes - Data attributes
 * @storage_id: [in/out] Storage identifier. See &typedef smw_attr_storage_id_t.
 * @attributes: [in/out] Attributes. See &typedef smw_attr_attributes_t.
 */
struct smw_data_attributes {
	smw_attr_storage_id_t storage_id;
	smw_attr_attributes_t attributes;
};

/**
 * struct smw_data_descriptor - Data descriptor
 * @identifier: [in] Data identifier.
 * @data: [in/out] Pointer to the data buffer.
 * @length: [in/out] Length in bytes of data buffer.
 * @attributes: Data attributes. See &typedef smw_data_attributes.
 */
struct smw_data_descriptor {
	unsigned int identifier;
	unsigned char *data;
	unsigned int length;
	struct smw_data_attributes attributes;
};

/**
 * struct smw_encryption_args - Encryption arguments
 * @keys_desc: [in] Pointer to an array of pointers to key descriptors used to
 *             encrypt the data. See &struct smw_key_descriptor.
 * @nb_keys: [in] Number of entries of key descriptors array.
 * @mode_name: [in] Cipher mode name. See &typedef smw_cipher_mode_t.
 * @iv: [in] Pointer to initialization vector. Not used in ECB mode.
 * @iv_length: [in] Length in bytes of the initialization vector. Not used in
 *             ECB mode.
 *
 * The number of keys @nb_keys is usually 1 key, but for the XTS mode, 2 keys
 * are required. In the case of multi-key cipher operation, the keys must be
 * owned by the same Secure Subsystem and must be the same key type.
 */
struct smw_encryption_args {
	struct smw_key_descriptor **keys_desc;
	unsigned int nb_keys;
	smw_cipher_mode_t mode_name;
	unsigned char *iv;
	unsigned int iv_length;
};

/**
 * struct smw_sign_args - Sign arguments
 * @key_descriptor: [in] Pointer to key descriptor used for signing.
 *		    See &struct smw_key_descriptor
 * @algo_name: [in] MAC algorithm name. See &typedef smw_mac_algo_t.
 * @hash_name: [in] Hash algorithm name. See &typedef smw_hash_algo_t.
 */
struct smw_sign_args {
	struct smw_key_descriptor *key_descriptor;
	smw_mac_algo_t algo_name;
	smw_hash_algo_t hash_name;
};

/**
 * struct smw_store_data_args - Store data arguments
 * @version: [in] Version of this structure.
 * @subsystem_name: [in] Secure Subsystem name. See &typedef smw_subsystem_t.
 * @data_descriptor: [in] Data descriptor. See &struct smw_data_descriptor.
 * @encryption_args: [in] (**optional**) Encryption arguments.
 *                   See &struct smw_encryption_args.
 * @sign_args: [in] (**optional**) Sign arguments. See &struct smw_sign_args.
 *
 * The @subsystem_name designates the Secure Subsystem to be used.
 * If this field is :ref:`SMW_SUBSYSTEM_NAME_NONE <smw_subsystem_t>`,
 * the default configured Secure Subsystem is used.
 * In case, user requests to encrypt and/or sign the data, the subsystem is
 * the Secure Subsystem handling the key(s).
 *
 * The @encryption_args and @sign_args arguments are optional. If defined
 * the operation consists respectively in encrypting and/or signing the data.
 * The capability to encrypt and/or sign data is function of the subsystem.
 * More details are available in the :ref:`subsystems-capabilities`.
 *
 * .. note::
 *   If the data is encrypted and/or signed:\
 *
 *     - Key must be present in the same ecure Subsystem. Only opaque key(s) is
 *       supported for encryption/signature operations.
 *     - The key must be capabled to do the cryptographic operation (i.e usage
 *       and permitted algorithm correctly defined when supported).
 */
struct smw_store_data_args {
	unsigned char version;
	smw_subsystem_t subsystem_name;
	struct smw_data_descriptor *data_descriptor;
	struct smw_encryption_args *encryption_args;
	struct smw_sign_args *sign_args;
};

/**
 * struct smw_retrieve_data_args - Retrieve data arguments
 * @version: [in] Version of this structure.
 * @subsystem_name: [in] Secure Subsystem name. See &typedef smw_subsystem_t.
 * @data_descriptor: [in/out] Data descriptor. See &struct smw_data_descriptor.
 *
 * The @subsystem_name designates the Secure Subsystem to be used.
 * If this field is :ref:`SMW_SUBSYSTEM_NAME_NONE <smw_subsystem_t>`,
 * the Secure Subsystem is the one handling the data identifier.
 */
struct smw_retrieve_data_args {
	unsigned char version;
	smw_subsystem_t subsystem_name;
	struct smw_data_descriptor *data_descriptor;
};

/**
 * struct smw_delete_data_args - Delete data arguments
 * @version: [in] Version of this structure.
 * @subsystem_name: [in] Secure Subsystem name. See &typedef smw_subsystem_t.
 * @data_descriptor: [in] Data descriptor. See &struct smw_data_descriptor.
 *
 * The @subsystem_name designates the Secure Subsystem to be used.
 * If this field is :ref:`SMW_SUBSYSTEM_NAME_NONE <smw_subsystem_t>`,
 * the Secure Subsystem is the one handling the data identifier.
 */
struct smw_delete_data_args {
	unsigned char version;
	smw_subsystem_t subsystem_name;
	struct smw_data_descriptor *data_descriptor;
};

/**
 * struct smw_data_info_args - Data information arguments
 * @version: [in] Version of this structure.
 * @subsystem_name: [in/out] Secure Subsystem name. See &typedef smw_subsystem_t.
 * @data_descriptor: [in/out] Data descriptor. See &struct smw_data_descriptor.
 *
 * This function gets the data attributes retrieved for the subsystem owning
 * the given data identifier.
 *
 * The @subsystem_name (input) designates the Secure Subsystem to be used.
 * If this field is :ref:`SMW_SUBSYSTEM_NAME_NONE <smw_subsystem_t>`,
 * the Secure Subsystem is the one handling the data identifier.
 *
 * The @subsystem_name (output) when input value is set to
 * :ref:`SMW_SUBSYSTEM_NAME_NONE <smw_subsystem_t>` is updated with the
 * Secure Subsystem name handling the data identifier.
 *
 * If some data attributes are not supported, the output values are empty.
 */
struct smw_data_info_args {
	unsigned char version;
	smw_subsystem_t subsystem_name;
	struct smw_data_descriptor *data_descriptor;
};

/**
 * smw_store_data() - Store data.
 * @args: Pointer to the structure that contains the store data arguments.
 *
 * Stores the data in the Secure Subsystem. The data can be optionally
 * encrypted and/or signed by the Secure Subsystem before storage. In case of
 * encryption and/or signature, the data retrieved is in blob i.e. encrypted
 * and/or signed.
 *
 * Return:
 *  - SMW_STATUS_OK:
 *      Operation succeeded.
 *  - SMW_STATUS_INVALID_PARAM:
 *      - @args is NULL.
 *      - @args->data_descriptor is NULL.
 *      - @args->data_descriptor->data is NULL.
 *      - @args->data_descriptor->length is 0.
 *      - if @args->encryption_args is defined:\
 *         - @args->encryption_args->nb_keys is 0.
 *         - @args->encryption_args->keys_desc is NULL.
 *         - @args->encryption_args->mode_name is SMW_CIPHER_MODE_NAME_NONE.
 *      - if @args->sign_args is defined:\
 *         - @args->sign_args->key_descriptor is NULL.
 *         - @args->sign_args->algo_name is SMW_SIGN_MODE_NAME_NONE.
 *      - Additional invalid parameters returned by the subsystem.
 *  - Other error code from &enum smw_status_code
 */
enum smw_status_code smw_store_data(struct smw_store_data_args *args);

/**
 * smw_retrieve_data() - Retrieve data.
 * @args: Pointer to the structure that contains the retrieve data arguments.
 *
 * Retrieves the data in the format that was stored. If the data was encrypted
 * and/or signed, the data is returned in blob format (encrypted and/or signed),
 * as detailed in the :ref:`subsystems-capabilities`.
 * If the data was not encrypted and/or signed, the data is returned in plain
 * format.
 *
 * To query the required data buffer length for data retrieval, set
 * @args->data_descriptor->data to NULL. The function will then set the required
 * data buffer length in @args->data_descriptor->length and return
 * SMW_STATUS_OK.
 *
 * On operation completion, the @args->data_descriptor->length is updated to
 * the correct value when
 *
 *  - Data buffer length is bigger than expected. In this case, operation
 *    succeeds.
 *  - Data buffer length is shorter than expected. In this case, operation fails
 *    and returns SMW_STATUS_OUTPUT_TOO_SHORT.
 *
 * Return:
 *  - SMW_STATUS_OK:
 *      Operation succeeded.
 *  - SMW_STATUS_INVALID_PARAM:
 *      - @args is NULL.
 *      - @args->data_descriptor is NULL.
 *      - @args->data_descriptor->data is NULL.
 *      - @args->data_descriptor->identifier is 0.
 *      - @args->subsystem_name is specified (other than SMW_SUBSYSTEM_NAME_NONE)\
 *        and does not match the subsystem handling the data identifier.
 *      - Additional invalid parameters returned by the subsystem.
 *  - Other error code from &enum smw_status_code
 */
enum smw_status_code smw_retrieve_data(struct smw_retrieve_data_args *args);

/**
 * smw_delete_data() - Delete data.
 * @args: Pointer to the structure that contains the store data arguments.
 *
 * Deletes the data.
 *
 * Return:
 *  - SMW_STATUS_OK:
 *      Operation succeeded.
 *  - SMW_STATUS_INVALID_PARAM:
 *      - @args is NULL.
 *      - @args->data_descriptor is NULL.
 *      - @args->data_descriptor->data is NULL.
 *      - @args->data_descriptor->identifier is 0.
 *      - @args->subsystem_name is specified (other than SMW_SUBSYSTEM_NAME_NONE)\
 *        and does not match the subsystem handling the data identifier.
 *      - Additional invalid parameters returned by the subsystem.
 *  - Other error code from &enum smw_status_code
 */
enum smw_status_code smw_delete_data(struct smw_delete_data_args *args);

/**
 * smw_get_data_info() - Get data information.
 * @args: Pointer to the data information arguments.
 *
 * Returns the data information extracts from the subsystem where data is
 * stored combined with the internal database if data identifier is present.
 *
 * The @args.subsystem_name field returned is the subsystem name that owns
 * the data.
 *
 * Return:
 *  - SMW_STATUS_OK:
 *      Operation succeeded.
 *  - SMW_STATUS_INVALID_PARAM:
 *      - @args is NULL.
 *      - @args->data_descriptor is NULL.
 *      - @args->data_descriptor->data is NULL.
 *      - @args->data_descriptor->identifier is 0.
 *      - @args->subsystem_name is specified (other than SMW_SUBSYSTEM_NAME_NONE)\
 *        and does not match the subsystem handling the data identifier.
 *      - Additional invalid parameters returned by the subsystem.
 *  - Other error code from &enum smw_status_code
 */
enum smw_status_code smw_get_data_info(struct smw_data_info_args *args);

#endif /* __SMW_STORAGE_H__ */
