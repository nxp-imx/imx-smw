/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020 NXP
 */

#include <stdint.h>

enum smw_keymgr_privacy_id {
	/* Key privacy */
	SMW_KEYMGR_PRIVACY_ID_PUBLIC,
	SMW_KEYMGR_PRIVACY_ID_PRIVATE,
	SMW_KEYMGR_PRIVACY_ID_PAIR,
	SMW_KEYMGR_PRIVACY_ID_NB,
	SMW_KEYMGR_PRIVACY_ID_INVALID
};

enum smw_keymgr_format_id {
	/* Key format */
	SMW_KEYMGR_FORMAT_ID_HEX,
	SMW_KEYMGR_FORMAT_ID_BASE64,
	SMW_KEYMGR_FORMAT_ID_NB,
	SMW_KEYMGR_FORMAT_ID_INVALID
};

/**
 * struct smw_keymgr_identifier - Key identifier
 * @subsystem_id: Secure Subsystem ID
 * @type_id: Key type ID
 * @privacy_id: Key privacy ID
 * @security_size: Security size in bits
 * @id: Key ID set by the subsystem
 *
 */
struct smw_keymgr_identifier {
	enum subsystem_id subsystem_id;
	enum smw_config_key_type_id type_id;
	enum smw_keymgr_privacy_id privacy_id;
	unsigned int security_size;
	uint32_t id;
};

/**
 * struct smw_keymgr_descriptor - Key descriptor
 * @identifier: Key identifier
 * @format_id: Format ID of the Key buffers
 * @pub: Key descriptor from the public API
 */
struct smw_keymgr_descriptor {
	struct smw_keymgr_identifier identifier;
	enum smw_keymgr_format_id format_id;
	struct smw_key_descriptor *pub;
};

/**
 * struct smw_keymgr_attributes - Key attributes list.
 * @persistent_storage: Use persistent subsystem storage or not.
 *
 */
struct smw_keymgr_attributes {
	bool persistent_storage;
};

/**
 * struct smw_keymgr_generate_key_args - Key generation arguments
 * @key_attributes: Key attributes
 * @key_descriptor: Descriptor of the generated Key
 *
 */
struct smw_keymgr_generate_key_args {
	struct smw_keymgr_attributes key_attributes;
	struct smw_keymgr_descriptor key_descriptor;
};

/**
 * struct smw_keymgr_derive_key_args - Key derivation arguments
 * @key_descriptor_in: Descriptor of the input Key
 * @key_attributes: Key attributes
 * @key_descriptor_out: Descriptor of the derived Key
 *
 */
struct smw_keymgr_derive_key_args {
	struct smw_keymgr_descriptor key_descriptor_in;
	struct smw_keymgr_attributes key_attributes;
	struct smw_keymgr_descriptor key_descriptor_out;
};

/**
 * struct smw_keymgr_update_key_args - Key update arguments
 *
 */
struct smw_keymgr_update_key_args {
	//TODO: define smw_keymgr_update_key_args
	int dummy;
};

/**
 * struct smw_keymgr_import_key_args - Key import arguments
 * @key_attributes: Key attributes
 * @key_descriptor: Descriptor of the imported Key
 *
 */
struct smw_keymgr_import_key_args {
	struct smw_keymgr_attributes key_attributes;
	struct smw_keymgr_descriptor key_descriptor;
};

/**
 * struct smw_keymgr_export_key_args - Key export arguments
 * @key_attributes: Key attributes
 * @key_descriptor: Descriptor of the exported Key
 *
 */
struct smw_keymgr_export_key_args {
	struct smw_keymgr_attributes key_attributes;
	struct smw_keymgr_descriptor key_descriptor;
};

/**
 * struct smw_keymgr_delete_key_args - Key deletion arguments
 * @key_descriptor: Descriptor of the Key to delete
 *
 */
struct smw_keymgr_delete_key_args {
	struct smw_keymgr_descriptor key_descriptor;
};

/**
 * smw_keymgr_alloc_keypair_buffer() - Allocate a keypair object.
 * @descriptor: Pointer to the internal Key descriptor structure.
 * @public_length: Length of the public Key buffer
 * @private_length: Length of the private Key buffer
 *
 * This function allocates a keypair buffer object and
 * the keys buffers (public/private) if corresponding lengths are set.
 *
 * Return:
 * error code.
 */
int smw_keymgr_alloc_keypair_buffer(struct smw_keymgr_descriptor *descriptor,
				    unsigned int public_length,
				    unsigned int private_length);

/**
 * smw_keymgr_free_keypair_buffer() - Free a keypair object.
 * @descriptor: Pointer to the internal Key descriptor structure.
 *
 * This function frees the memory allocated by
 * smw_keymgr_alloc_keypair_buffer().
 *
 * Return:
 * error code.
 */
int smw_keymgr_free_keypair_buffer(struct smw_keymgr_descriptor *descriptor);

/**
 * smw_keymgr_get_public_data() - Return the address of the public Key buffer.
 * @descriptor: Pointer to the internal Key descriptor structure.
 *
 * This function returns the address of the public Key buffer.
 * If the @buffer field @pub is NULL, the function returns NULL.
 *
 * Return:
 * NULL
 * address of the public Key buffer
 */
unsigned char *
smw_keymgr_get_public_data(struct smw_keymgr_descriptor *descriptor);

/**
 * smw_keymgr_get_public_length() - Return the length of the public Key buffer.
 * @descriptor: Pointer to the internal Key descriptor structure.
 *
 * This function returns the length of the public Key buffer.
 * If the @buffer field @pub is NULL, the function returns 0.
 *
 * Return:
 * 0
 * length of the public Key buffer.
 */
unsigned int
smw_keymgr_get_public_length(struct smw_keymgr_descriptor *descriptor);

/**
 * smw_keymgr_set_public_data() - Set the address of the public Key buffer.
 * @descriptor: Pointer to the internal Key descriptor structure.
 * @public_data: Address of the public Key buffer.
 *
 * This function sets the address of the public Key buffer.
 * If the @buffer field @pub is NULL, the function returns with no action.
 *
 * Return:
 * none.
 */
void smw_keymgr_set_public_data(struct smw_keymgr_descriptor *descriptor,
				unsigned char *public_data);

/**
 * smw_keymgr_set_public_length() - Set the length of the public Key buffer.
 * @descriptor: Pointer to the internal Key descriptor structure.
 * @public_length: Length of the public Key buffer.
 *
 * This function sets the length of the public Key buffer.
 * If the @buffer field @pub is NULL, the function returns with no action.
 *
 * Return:
 * none.
 */
void smw_keymgr_set_public_length(struct smw_keymgr_descriptor *descriptor,
				  unsigned int public_length);

/**
 * smw_keymgr_set_private_length() - Set the length of the private Key buffer.
 * @descriptor: Pointer to the internal Key descriptor structure.
 * @private_length: Length of the private Key buffer.
 *
 * This function sets the length of the private Key buffer.
 * If the @buffer field @pub is NULL, the function returns with no action.
 *
 * Return:
 * none.
 */
void smw_keymgr_set_private_length(struct smw_keymgr_descriptor *descriptor,
				   unsigned int private_length);

/**
 * smw_keymgr_get_buffers_lengths() - Get the lengths of the Key buffers.
 * @type_id: Key type ID.
 * @security_size: Security size in bits.
 * @format_id: Format ID.
 * @public_buffer_length: Pointer to the public buffer length.
 * @private_buffer_length: Pointer to the private buffer length.
 *
 * This function computes the lengths of the Key buffers.
 *
 * Return:
 * error code.
 */
int smw_keymgr_get_buffers_lengths(enum smw_config_key_type_id type_id,
				   unsigned int security_size,
				   enum smw_keymgr_format_id format_id,
				   unsigned int *public_buffer_length,
				   unsigned int *private_buffer_length);

/**
 * smw_keymgr_convert_descriptor() - Key descriptor conversion.
 * @in: Pointer to a public Key descriptor.
 * @out: Pointer to an internal Key descriptor.
 *
 * This function converts a public Key descriptor
 * into an internal Key descriptor.
 *
 * Return:
 * error code.
 */
int smw_keymgr_convert_descriptor(struct smw_key_descriptor *in,
				  struct smw_keymgr_descriptor *out);

/**
 * smw_keymgr_set_default_attributes() - Set default Key attributes.
 * @attr: Pointer to the Key attributes structure.
 *
 * This function sets the default values of the Key attributes.
 *
 * Return:
 * None.
 */
void smw_keymgr_set_default_attributes(struct smw_keymgr_attributes *attr);

/**
 * smw_keymgr_get_privacy_id() - Get the Key privacy ID.
 * @type_id: Key type ID.
 * @privacy_id: Key privacy ID.
 *
 * This function gets the Key privacy ID given the Key type ID.
 *
 * Return:
 * error code.
 */
int smw_keymgr_get_privacy_id(enum smw_config_key_type_id type_id,
			      enum smw_keymgr_privacy_id *privacy_id);
