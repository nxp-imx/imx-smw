/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2021 NXP
 */

#ifndef __SMW_KEYMGR_H__
#define __SMW_KEYMGR_H__

#include "smw_strings.h"
#include <stdbool.h>

/**
 * struct smw_keypair_gen - Generic Keypair object
 * @public_data: Pointer to the public key
 * @public_length: Length of @public_data in bytes
 * @private_data: Pointer to the private key
 * @private_length: Length of @private_data in bytes
 */
struct smw_keypair_gen {
	unsigned char *public_data;
	unsigned int public_length;
	unsigned char *private_data;
	unsigned int private_length;
};

/**
 * struct smw_keypair_rsa - RSA Keypair object
 * @modulus: Pointer to the RSA modulus
 * @modulus_length: Length of @modulus in bytes
 * @public_data: Pointer to the RSA public exponent
 * @public_length: Length of @public_data in bytes
 * @private_data: Pointer to the RSA private exponent
 * @private_length: Length of @private_data in bytes
 */
struct smw_keypair_rsa {
	unsigned char *modulus;
	unsigned int modulus_length;
	unsigned char *public_data;
	unsigned int public_length;
	unsigned char *private_data;
	unsigned int private_length;
};

/**
 * struct smw_keypair_buffer - Keypair buffer
 * @format_name: Defines the encoding format of all buffers.
 *		 See &typedef smw_key_format_t
 * @gen: Generic keypair object definition. See &struct smw_keypair_gen
 * @rsa: RSA keypair object definition. See &struct smw_keypair_rsa
 *
 * By default if format name is not specified,
 * there will be no encoding (equivalent to "HEX")
 */
struct smw_keypair_buffer {
	smw_key_format_t format_name;
	union {
		struct smw_keypair_gen gen;
		struct smw_keypair_rsa rsa;
	};
};

/**
 * struct smw_key_descriptor - Key descriptor
 * @type_name: Key type name. See &typedef smw_key_type_t
 * @security_size: Security size in bits
 * @id: Key identifier
 * @buffer: Key pair buffer. See &struct smw_keypair_buffer
 */
struct smw_key_descriptor {
	smw_key_type_t type_name;
	unsigned int security_size;
	unsigned long long id;
	struct smw_keypair_buffer *buffer;
};

/**
 * struct smw_generate_key_args - Key generation arguments
 * @version: Version of this structure
 * @subsystem_name: Secure Subsystem name. See &typedef smw_subsystem_t
 * @key_attributes_list: Key attributes list.
 *			 See &typedef smw_attribute_type_t
 * @key_attributes_list_length: Length of the Key attributes list
 * @key_descriptor: Pointer to a Key descriptor object.
 *		    See &struct smw_key_descriptor
 *
 * @subsystem_name designates the Secure Subsystem to be used.
 * If this field is NULL, the default Secure Subsystem configured for
 * this Security Operation is used.
 * The @key_descriptor fields @type_name and @security_size must be given
 * as input to know the type of key to generate.
 * The @key_descriptor field @buffer is optional. Only the public key will be
 * returned if the corresponding pointer and size are set.
 * The @key_descriptor field @id is filled by the API
 * if the operation is successful.
 */
struct smw_generate_key_args {
	unsigned char version;
	smw_subsystem_t subsystem_name;
	const unsigned char *key_attributes_list;
	unsigned int key_attributes_list_length;
	struct smw_key_descriptor *key_descriptor;
};

/**
 * struct smw_derive_key_args - Key derivation arguments
 * @version: Version of this structure
 * @subsystem_name: Secure Subsystem name. See &typedef smw_subsystem_t
 * @kdf_name: Key derivation function name. See &typedef smw_kdf_t
 * @kdf_arguments: Key derivation function arguments
 * @key_descriptor_base: Pointer to a Key base descriptor.
 *			 See &struct smw_key_descriptor
 * @key_attributes_list: Key attributes list
 * @key_attributes_list_length: Length of the Key attributes list
 * @key_descriptor_derived: Pointer to the Key derived descriptor.
 *			    See &struct smw_key_descriptor
 *
 * @subsystem_name designates the Secure Subsystem to be used.
 * If this field is NULL, the default Secure Subsystem configured for
 * this Security Operation is used.
 *
 * A new key is derived from a given key base (@key_descriptor_base) using
 * the key derivation function @kdf_name.
 * If the key derivation function requires more arguments,
 * the @kdf_arguments refers to the associated key derivation function
 * arguments, else this pointer is not used and can be NULL.
 *
 * The result of the key derivation is set in the @key_descriptor_derived
 * structure and consist in a new key id and the public data is exported
 * if the public data and size are set in the @buffer field.
 */
struct smw_derive_key_args {
	unsigned char version;
	smw_subsystem_t subsystem_name;
	smw_kdf_t kdf_name;
	void *kdf_arguments;
	struct smw_key_descriptor *key_descriptor_base;
	const unsigned char *key_attributes_list;
	unsigned int key_attributes_list_length;
	struct smw_key_descriptor *key_descriptor_derived;
};

/**
 * struct smw_kdf_tls12_args - Key derivation function TLS 1.2 arguments
 * @key_exchange_name: Name of the key exchange algorithm.
 *                     See &typedef smw_tls12_kea_t
 * @encryption_name: Name of the encryption algorithm.
 *                   See &typedef smw_tls12_enc_t
 * @prf_name: Name of the Pseudo-Random Function (PRF).
 *            See &typedef smw_hash_algo_t
 * @ext_master_key: If true, generates an extended master secret key
 * @kdf_input: Key derivation input data used to generate the master secret key
 * @kdf_input_length: Length in bytes of the @kdf_input buffer
 * @master_sec_key_id: Generated master key identifier
 * @client_w_enc_key_id: Generated client write encryption key identifier
 * @server_w_enc_key_id: Generated server write encryption key identifier
 * @client_w_mac_key_id: Generated client write MAC key identifier (see note 1)
 * @server_w_mac_key_id: Generated server write MAC key identifier (see note 1)
 * @client_w_iv: Pointer to the Client IV buffer (see note 2)
 * @client_w_iv_length: Length of @client_w_iv in bytes (see note 2)
 * @server_w_iv: Pointer to the Server IV buffer (see note 2)
 * @server_w_iv_length: Length of @server_w_iv in bytes (see note 2)
 *
 * This structure defines the additional arguments needed for the TLS 1.2
 * Key derivation (&smw_derive_key_args->kdf_name = `TLS12_KEY_EXCHANGE`).
 *
 * Note 1: Client/Server write MAC key are not generated with AES GCM cipher
 *         encryption.
 * Note 2: Client/Server write IVs are generated only in case of Authentication
 *         Encryption with Additional Data Cipher mode (like AES CCM or GCM).
 *
 * The key derivation &smw_derive_key_args->key_descriptor_derived is filled
 * only if the @key_exchange_name request for an ephemeral public key.
 * Following &smw_derive_key_args->key_descriptor_derived fields are filled:
 *  - @id: set to 0
 *  - @type_name: Set the key type name
 *  - @security_size: Size in bits of the derived key
 *  - @buffer: Public key data buffer only
 */
struct smw_kdf_tls12_args {
	// Input parameters
	smw_tls12_kea_t key_exchange_name;
	smw_tls12_enc_t encryption_name;
	smw_hash_algo_t prf_name;
	bool ext_master_key;
	unsigned char *kdf_input;
	unsigned int kdf_input_length;
	// Output parameters
	unsigned long long master_sec_key_id;
	unsigned long long client_w_enc_key_id;
	unsigned long long server_w_enc_key_id;
	unsigned long long client_w_mac_key_id;
	unsigned long long server_w_mac_key_id;
	unsigned char *client_w_iv;
	unsigned int client_w_iv_length;
	unsigned char *server_w_iv;
	unsigned int server_w_iv_length;
};

/**
 * struct smw_update_key_args - Key update arguments
 * @version: Version of this structure
 * @subsystem_name: Secure Subsystem name. See &typedef smw_subsystem_t
 */
struct smw_update_key_args {
	unsigned char version;
	smw_subsystem_t subsystem_name;
	//TODO: define smw_update_key_args
};

/**
 * struct smw_import_key_args - Key import arguments
 * @version: Version of this structure
 * @subsystem_name: Secure Subsystem name. See &typedef smw_subsystem_t
 * @key_attributes_list: Key attributes list.
 *			 See &typedef smw_attribute_type_t
 * @key_attributes_list_length: Length of a Key attributes list
 * @key_descriptor: Pointer to a Key descriptor object.
 *		    See &struct smw_key_descriptor
 *
 * @subsystem_name designates the Secure Subsystem to be used.
 * If this field is NULL, the default Secure Subsystem configured for
 * this Security Operation is used.
 * The @key_descriptor fields @type_name and @security_size must be given
 * as input to define the type of key to import.
 * The @key_descriptor field @buffer is mandatory. A public key, a private key
 * or a key pair is imported if the corresponding pointer and size is set.
 * The @key_descriptor field @id is filled by the API
 * if the operation is successful.
 * The @buffer field @format_name is optional. The default value is "HEX".
 */
struct smw_import_key_args {
	unsigned char version;
	smw_subsystem_t subsystem_name;
	const unsigned char *key_attributes_list;
	unsigned int key_attributes_list_length;
	struct smw_key_descriptor *key_descriptor;
};

/**
 * struct smw_export_key_args - Key export arguments
 * @version: Version of this structure
 * @key_attributes_list: Key attributes list.
 *			 See &typedef smw_attribute_type_t
 * @key_attributes_list_length: Length of the Key attributes list
 * @key_descriptor: Pointer to a Key descriptor object.
 *		    See &struct smw_key_descriptor
 *
 * The @key_descriptor fields @id must be given as input.
 * The @key_descriptor field @buffer is mandatory.
 * The public key buffer must be set in order to export the public Key,
 * in case of asymmetric Keys.
 * The private key buffer must be set in order to export the private Key,
 * only if the Secure Subsystem supports it. In that case, the private Key
 * may be encrypted, not plaintext.
 * The user can use smw_get_key_buffers_lengths() to set correct lengths
 * for the public/private key buffer(s).
 */
struct smw_export_key_args {
	unsigned char version;
	const unsigned char *key_attributes_list;
	unsigned int key_attributes_list_length;
	struct smw_key_descriptor *key_descriptor;
};

/**
 * struct smw_delete_key_args - Key deletion arguments
 * @version: Version of this structure
 * @key_descriptor: Pointer to a Key descriptor object.
 *		    See &struct smw_key_descriptor
 *
 * The @key_descriptor fields @id must be given as input.
 * The @key_descriptor fields @buffer is ignored.
 */
struct smw_delete_key_args {
	unsigned char version;
	struct smw_key_descriptor *key_descriptor;
};

/**
 * smw_generate_key() - Generate a Key.
 * @args: Pointer to the structure that contains the Key generation arguments.
 *
 * This function generates a Key.
 *
 * Return:
 * See &enum smw_status_code
 *	- Common return codes
 */
enum smw_status_code smw_generate_key(struct smw_generate_key_args *args);

/**
 * smw_derive_key() - Derive a Key.
 * @args: Pointer to the structure that contains the Key derivation arguments.
 *
 * This function derives a Key.
 *
 * Return:
 * See &enum smw_status_code
 *	- Common return codes
 */
enum smw_status_code smw_derive_key(struct smw_derive_key_args *args);

/**
 * smw_update_key() - Update a Key.
 * @args: Pointer to the structure that contains the Key update arguments.
 *
 * This function updates the Key attribute list.
 *
 * Return:
 * See &enum smw_status_code
 *	- Common return codes
 */
enum smw_status_code smw_update_key(struct smw_update_key_args *args);

/**
 * smw_import_key() - Import a Key.
 * @args: Pointer to the structure that contains the Key import arguments.
 *
 * This function imports a Key into the storage managed by the Secure Subsystem.
 * The key must be plain text.
 *
 * Return:
 * See &enum smw_status_code
 *	- Common return codes
 */
enum smw_status_code smw_import_key(struct smw_import_key_args *args);

/**
 * smw_export_key() - Export a Key.
 * @args: Pointer to the structure that contains the Key export arguments.
 *
 * This function exports a Key.
 *
 * Return:
 * See &enum smw_status_code
 *	- Common return codes
 */
enum smw_status_code smw_export_key(struct smw_export_key_args *args);

/**
 * smw_delete_key() - Delete a Key.
 * @args: Pointer to the structure that contains the Key deletion arguments.
 *
 * This function deletes a Key.
 *
 * Return:
 * See &enum smw_status_code
 *	- Common return codes
 */
enum smw_status_code smw_delete_key(struct smw_delete_key_args *args);

/**
 * smw_get_key_buffers_lengths() - Gets Key buffers lengths.
 * @descriptor: Pointer to the Key descriptor.
 *
 * This function gets the Key buffers lengths given the Key type name
 * and the security size.
 * The @descriptor fields @type_name and @security_size must be given as input.
 * The @descriptor field @buffer is mandatory.
 * The @buffer field @format_name is optional.
 * The @buffer fields @public_length and @private_length are updated.
 *
 * Return:
 * See &enum smw_status_code
 *	- Common return codes
 */
enum smw_status_code
smw_get_key_buffers_lengths(struct smw_key_descriptor *descriptor);

/**
 * smw_get_key_type_name() - Gets the Key type name.
 * @descriptor: Pointer to the Key descriptor.
 *
 * This function gets the Key type name given the Key ID.
 * The @descriptor field @id must be given as input.
 * The @descriptor fields @type_name is updated.
 *
 * Return:
 * See &enum smw_status_code
 *	- Common return codes
 */
enum smw_status_code
smw_get_key_type_name(struct smw_key_descriptor *descriptor);

/**
 * smw_get_security_size() - Gets the Security size.
 * @descriptor: Pointer to the Key descriptor.
 *
 * This function gets the Security size given the Key ID.
 * The @descriptor field @id must be given as input.
 * The @descriptor fields @security_size is updated.
 *
 * Return:
 * See &enum smw_status_code
 *	- Common return codes
 */
enum smw_status_code
smw_get_security_size(struct smw_key_descriptor *descriptor);

#endif /* __SMW_KEYMGR_H__ */
