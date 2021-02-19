/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2021 NXP
 */

#ifndef __SMW_KEYMGR_H__
#define __SMW_KEYMGR_H__

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
 * @format_name: Defines the encoding format of all buffers
 * @gen: Generic keypair object definition
 * @rsa: RSA keypair object definition
 *
 * @format_name is a string value among:
 * - "HEX": hexadecimal value (no encoding)
 * - "BASE64": base 64 encodng value
 * By default if format name is not specified,
 * there will be no encoding (equivalent to "HEX")
 */
struct smw_keypair_buffer {
	const char *format_name;
	union {
		struct smw_keypair_gen gen;
		struct smw_keypair_rsa rsa;
	};
};

/**
 * struct smw_key_descriptor - Key descriptor
 * @type_name: Key type name
 * @security_size: Security size in bits
 * @id: Key identifier
 * @buffer: Key pair buffer
 */
struct smw_key_descriptor {
	const char *type_name;
	unsigned int security_size;
	unsigned long long id;
	struct smw_keypair_buffer *buffer;
};

/**
 * struct smw_generate_key_args - Key generation arguments
 * @version: Version of this structure
 * @subsystem_name: Secure Subsystem name
 * @key_attributes_list: Key attributes list
 * @key_attributes_list_length: Length of the Key attributes list
 * @key_descriptor: Pointer to a Key descriptor object
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
	const char *subsystem_name;
	const unsigned char *key_attributes_list;
	unsigned int key_attributes_list_length;
	struct smw_key_descriptor *key_descriptor;
};

/**
 * struct smw_derive_key_args - Key derivation arguments
 * @version: Version of this structure
 * @subsystem_name: Secure Subsystem name
 * @key_descriptor_in: Pointer to a Key descriptor
 * @key_attributes_list: Key attributes list
 * @key_attributes_list_length: Length of the Key attributes list
 * @key_descriptor_out: Pointer to the new Key decriptor
 *
 * @subsystem_name designates the Secure Subsystem to be used.
 * If this field is NULL, the default Secure Subsystem configured for
 * this Security Operation is used.
 * The new Key is derived from the key described by @key_descriptor_in.
 * The @key_descriptor_out field @buffer is optional. Only the public key
 * will be returned if the corresponding pointer and size are set.
 * The @key_descriptor_out field @id is filled by the API
 * if the operation is successful.
 */
struct smw_derive_key_args {
	unsigned char version;
	const char *subsystem_name;
	struct smw_key_descriptor *key_descriptor_in;
	const unsigned char *key_attributes_list;
	unsigned int key_attributes_list_length;
	struct smw_key_descriptor *key_descriptor_out;
};

/**
 * struct smw_update_key_args - Key update arguments
 * @version: Version of this structure
 * @subsystem_name: Secure Subsystem name
 */
struct smw_update_key_args {
	unsigned char version;
	const char *subsystem_name;
	//TODO: define smw_update_key_args
};

/**
 * struct smw_import_key_args - Key import arguments
 * @version: Version of this structure
 * @subsystem_name: Secure Subsystem name
 * @key_attributes_list: Key attributes list
 * @key_attributes_list_length: Length of a Key attributes list
 * @key_descriptor: Pointer to a Key descriptor object
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
	const char *subsystem_name;
	const unsigned char *key_attributes_list;
	unsigned int key_attributes_list_length;
	struct smw_key_descriptor *key_descriptor;
};

/**
 * struct smw_export_key_args - Key export arguments
 * @version: Version of this structure
 * @key_attributes_list: Key attributes list
 * @key_attributes_list_length: Length of the Key attributes list
 * @key_descriptor: Pointer to a Key descriptor object
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
 * @key_descriptor: Pointer to a Key descriptor object
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
 * error code.
 */
int smw_generate_key(struct smw_generate_key_args *args);

/**
 * smw_derive_key() - Derive a Key.
 * @args: Pointer to the structure that contains the Key derivation arguments.
 *
 * This function derives a Key.
 *
 * Return:
 * error code.
 */
int smw_derive_key(struct smw_derive_key_args *args);

/**
 * smw_update_key() - Update a Key.
 * @args: Pointer to the structure that contains the Key update arguments.
 *
 * This function updates the Key attribute list.
 *
 * Return:
 * error code.
 */
int smw_update_key(struct smw_update_key_args *args);

/**
 * smw_import_key() - Import a Key.
 * @args: Pointer to the structure that contains the Key import arguments.
 *
 * This function imports a Key into the storage managed by the Secure Subsystem.
 * The key must be plain text.
 *
 * Return:
 * error code.
 */
int smw_import_key(struct smw_import_key_args *args);

/**
 * smw_export_key() - Export a Key.
 * @args: Pointer to the structure that contains the Key export arguments.
 *
 * This function exports a Key.
 *
 * Return:
 * error code.
 */
int smw_export_key(struct smw_export_key_args *args);

/**
 * smw_delete_key() - Delete a Key.
 * @args: Pointer to the structure that contains the Key deletion arguments.
 *
 * This function deletes a Key.
 *
 * Return:
 * error code.
 */
int smw_delete_key(struct smw_delete_key_args *args);

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
 * error code.
 */
int smw_get_key_buffers_lengths(struct smw_key_descriptor *descriptor);

/**
 * smw_get_key_type_name() - Gets the Key type name.
 * @descriptor: Pointer to the Key descriptor.
 *
 * This function gets the Key type name given the Key ID.
 * The @descriptor field @id must be given as input.
 * The @descriptor fields @type_name is updated.
 *
 * Return:
 * error code.
 */
int smw_get_key_type_name(struct smw_key_descriptor *descriptor);

/**
 * smw_get_security_size() - Gets the Security size.
 * @descriptor: Pointer to the Key descriptor.
 *
 * This function gets the Security size given the Key ID.
 * The @descriptor field @id must be given as input.
 * The @descriptor fields @security_size is updated.
 *
 * Return:
 * error code.
 */
int smw_get_security_size(struct smw_key_descriptor *descriptor);

#endif /* __SMW_KEYMGR_H__ */
