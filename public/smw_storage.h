/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2023 NXP
 */

#ifndef __SMW_STORAGE_H__
#define __SMW_STORAGE_H__

#include "smw_status.h"
#include "smw_strings.h"

/**
 * DOC:
 * The storage APIs allow user of the library to:
 *  - Store data.
 *  - Retrieve data.
 *  - Delete data.
 *
 * The data storing operation allows user to request the subsystem to either:
 *  - store data as given by the user, reading back the data will in the same
 *    format as given by user.
 *  - encrypt data then store, reading back the data will be a blob of
 *    encrypted data.
 *  - encrypt and sign data then store, reading back the data will be a signed
 *    blob of encrypted data.
 *  - sign data then store, reading back the data will be a signed blob of
 *    data. Knowing that data format is identical as the given by user.
 *
 * Refer to the subsystem capabilities for more details of the supported
 * features and blob format.
 *
 * Signature is limited to MAC signature.
 */

/**
 * struct smw_data_descriptor - Data descriptor
 * @identifier: Data identifier
 * @data: Pointer to the data buffer
 * @length: Length of buffer @data
 * @attributes_list: Data attributes list. See &typedef smw_attr_data_type_t
 * @attributes_list_length: Length of buffer @attributes_list
 */
struct smw_data_descriptor {
	unsigned int identifier;
	unsigned char *data;
	unsigned int length;
	unsigned char *attributes_list;
	unsigned int attributes_list_length;
};

/**
 * struct smw_encryption_args - Encryption arguments
 * @keys_desc: Pointer to an array of pointers to key descriptors.
 *	       See &struct smw_key_descriptor
 * @nb_keys: Number of entries of @keys_desc
 * @mode_name: Cipher mode name. See &typedef smw_cipher_mode_t
 * @iv: Pointer to initialization vector
 * @iv_length: @iv length in bytes
 *
 * Depending on @mode_name, the @iv is optional and represents:
 *	- Initialization Vector (CBC, CTS)
 *	- Initial Counter Value (CTR)
 *	- Tweak Value (XTS)
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
 * @key_descriptor: Pointer to a signing Key descriptor object.
 *		    See &struct smw_key_descriptor
 * @algo_name: MAC algorithm name. See &typedef smw_mac_algo_t
 * @hash_name: Hash algorithm name. See &typedef smw_hash_algo_t
 */
struct smw_sign_args {
	struct smw_key_descriptor *key_descriptor;
	smw_mac_algo_t algo_name;
	smw_hash_algo_t hash_name;
};

/**
 * struct smw_store_data_args - Store data arguments
 * @version: Version of this structure
 * @subsystem_name: Secure Subsystem name. See &typedef smw_subsystem_t
 * @data_descriptor: Data descriptor. See &struct smw_data_descriptor
 * @encryption_args: Encryption arguments. See &struct smw_encryption_args
 * @sign_args: Sign arguments. See &struct smw_sign_args
 *
 * @subsystem_name designates the Secure Subsystem to be used.
 * If this field is NULL, the default configured Secure Subsystem is used.
 *
 * The @encryption_args and @smw_sign_args arguments are optional. If defined
 * the operation consists respectively in encrypting and/or signing the data.
 * The capability to encrypt and/or sign data is function of the subsystem.
 * Refer to the :doc:`/capabilities`.
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
 * @version: Version of this structure
 * @subsystem_name: Secure Subsystem name. See &typedef smw_subsystem_t
 * @data_descriptor: Data descriptor. See &struct smw_data_descriptor
 *
 * @subsystem_name designates the Secure Subsystem to be used.
 * If this field is NULL, the default configured Secure Subsystem is used.
 */
struct smw_retrieve_data_args {
	unsigned char version;
	smw_subsystem_t subsystem_name;
	struct smw_data_descriptor *data_descriptor;
};

/**
 * struct smw_delete_data_args - Delete data arguments
 * @version: Version of this structure
 * @subsystem_name: Secure Subsystem name. See &typedef smw_subsystem_t
 * @data_descriptor: Data descriptor. See &struct smw_data_descriptor
 *
 * @subsystem_name designates the Secure Subsystem to be used.
 * If this field is NULL, the default configured Secure Subsystem is used.
 */
struct smw_delete_data_args {
	unsigned char version;
	smw_subsystem_t subsystem_name;
	struct smw_data_descriptor *data_descriptor;
};

/**
 * smw_store_data() - Store data.
 * @args: Pointer to the structure that contains the store data arguments.
 *
 * Stores the data.
 *
 * Return:
 * See &enum smw_status_code
 *	- Common return codes
 */
enum smw_status_code smw_store_data(struct smw_store_data_args *args);

/**
 * smw_retrieve_data() - Retrieve data.
 * @args: Pointer to the structure that contains the retrieve data arguments.
 *
 * Retrieves the data.
 *
 * Return:
 * See &enum smw_status_code
 *	- Common return codes
 *      - SMW_STATUS_DATA_ALREADY_RETRIEVED
 */
enum smw_status_code smw_retrieve_data(struct smw_retrieve_data_args *args);

/**
 * smw_delete_data() - Delete data.
 * @args: Pointer to the structure that contains the store data arguments.
 *
 * Deletes the data.
 *
 * Return:
 * See &enum smw_status_code
 *	- Common return codes
 */
enum smw_status_code smw_delete_data(struct smw_delete_data_args *args);

#endif /* __SMW_STORAGE_H__ */
