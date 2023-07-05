/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2023 NXP
 */

#ifndef __STORAGE_H__
#define __STORAGE_H__

#include "config.h"
#include "keymgr.h"

/**
 * struct smw_storage_data_attributes - Storage attributes.
 * @rw_flags: Data access flags.
 * @lifecycle_flags: Device lifecycles where data is accessible.
 */
struct smw_storage_data_attributes {
	unsigned long rw_flags;
	unsigned long lifecycle_flags;
};

/**
 * struct smw_storage_enc_args - Encryption arguments.
 * @keys_desc: Pointer to an array of internal key descriptor structure pointer.
 * @nb_keys: Number of entries of the array key descriptor pointer.
 * @mode_id: Cipher mode ID
 * @pub: Encryption arguments from the public API.
 */
struct smw_storage_enc_args {
	struct smw_keymgr_descriptor **keys_desc;
	unsigned int nb_keys;
	enum smw_config_cipher_mode_id mode_id;
	struct smw_encryption_args *pub;
};

/**
 * struct smw_storage_data_descriptor - Data descriptor
 * @attributes: Data attributes.
 * @pub: Data descriptor from the public API.
 */
struct smw_storage_data_descriptor {
	struct smw_storage_data_attributes attributes;
	struct smw_data_descriptor *pub;
};

/**
 * struct smw_storage_sign_args - Sign arguments.
 * @key_descriptor: Pointer to a Key descriptor object.
 *		    See &struct smw_key_descriptor
 * @algo_id: MAC algorithm ID
 * @hash_id: Hash algorithm ID
 */
struct smw_storage_sign_args {
	struct smw_keymgr_descriptor key_descriptor;
	enum smw_config_mac_algo_id algo_id;
	enum smw_config_hash_algo_id hash_id;
};

/**
 * struct smw_storage_store_data_args - Internal store data arguments structure
 * @data_descriptor: Data descriptor.
 * @enc_args: Encryption arguments.
 * @sign_args: Sign arguments.
 */
struct smw_storage_store_data_args {
	struct smw_storage_data_descriptor data_descriptor;
	struct smw_storage_enc_args enc_args;
	struct smw_storage_sign_args sign_args;
};

/**
 * struct smw_storage_retrieve_data_args - Internal retrieve data arguments structure
 * @data_descriptor: Data descriptor.
 */
struct smw_storage_retrieve_data_args {
	struct smw_storage_data_descriptor data_descriptor;
};

/**
 * struct smw_storage_delete_data_args - Internal delete data arguments structure
 * @data_descriptor: Data descriptor.
 */
struct smw_storage_delete_data_args {
	struct smw_storage_data_descriptor data_descriptor;
};

/**
 * smw_storage_get_data_identifier() - Return the data identifier.
 * @descriptor: Pointer to the internal data descriptor structure.
 *
 * This function returns the data identifier.
 * If the @descriptor field @pub is NULL the function returns 0.
 *
 * Return:
 * 0
 * data identifier.
 */
unsigned int
smw_storage_get_data_identifier(struct smw_storage_data_descriptor *descriptor);

/**
 * smw_storage_get_data() - Return the pointer to the data.
 * @descriptor: Pointer to the internal data descriptor structure.
 *
 * This function returns the pointer to the data.
 * If the @descriptor field @pub is NULL the function returns NULL.
 *
 * Return:
 * NULL
 * pointer to the data.
 */
unsigned char *
smw_storage_get_data(struct smw_storage_data_descriptor *descriptor);

/**
 * smw_storage_get_data_length() - Return the length of the data.
 * @descriptor: Pointer to the internal data descriptor structure.
 *
 * This function returns the length of the data.
 * If the @descriptor field @pub is NULL the function returns 0.
 *
 * Return:
 * 0
 * length of the data.
 */
unsigned int
smw_storage_get_data_length(struct smw_storage_data_descriptor *descriptor);

/**
 * smw_storage_set_data_length() - Set the length of the data.
 * @descriptor: Pointer to the internal data descriptor structure.
 * @length: Length of the data
 *
 * This function sets the length of the data.
 * If the @descriptor field @pub is NULL, the function returns with no action.
 *
 * Return:
 * none.
 */
void smw_storage_set_data_length(struct smw_storage_data_descriptor *descriptor,
				 unsigned int length);

/**
 * smw_storage_get_iv() - Return the pointer to the iv.
 * @enc_args: Pointer to the internal encryption arguments structure.
 *
 * This function returns the pointer to the iv.
 * If the @enc_args field @pub is NULL the function returns NULL.
 *
 * Return:
 * NULL
 * pointer to the iv.
 */
unsigned char *smw_storage_get_iv(struct smw_storage_enc_args *enc_args);

/**
 * smw_storage_get_iv_length() - Return the length of the iv.
 * @enc_args: Pointer to the internal encryption arguments structure.
 *
 * This function returns the length of the iv.
 * If the @enc_args field @pub is NULL the function returns 0.
 *
 * Return:
 * 0
 * length of the iv.
 */
unsigned int smw_storage_get_iv_length(struct smw_storage_enc_args *enc_args);

#endif /* __STORAGE_H__ */
