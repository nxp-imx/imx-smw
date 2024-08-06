/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2024 NXP
 */

#ifndef __KEYMGR_H__
#define __KEYMGR_H__

#include <stdint.h>
#include <stdbool.h>

#include "smw/names.h"

#include "constants.h"
#include "config.h"
#include "key.h"

/* Define invalid key identifier */
#define INVALID_KEY_ID INVALID_OBJ_ID

/* Default RSA public exponent is 65537, which has a length of 3 bytes */
#define DEFAULT_RSA_PUB_EXP	65537
#define DEFAULT_RSA_PUB_EXP_LEN 3

/*
 * Ordering must be the same for internal values and public values.
 * This way the offset between the internal values and the public values
 * can be used for conversion, and no conversion table is required.
 *
 * The offset between the internal values and the public values is
 * given by the first public value.
 */

#define SMW_KEYMGR_PRIVACY_ID_OFFSET                                           \
	(SMW_KEY_PRIVACY_NAME_PUBLIC - SMW_KEYMGR_PRIVACY_ID_PUBLIC)

enum smw_keymgr_privacy_id {
	SMW_KEYMGR_PRIVACY_ID_PUBLIC,
	SMW_KEYMGR_PRIVACY_ID_PRIVATE,
	SMW_KEYMGR_PRIVACY_ID_PAIR,
	/* This type is intended for secret data that has been derived using a
	 * key derivation function.
	 */
	SMW_KEYMGR_PRIVACY_ID_SHARED_SECRET,
	SMW_KEYMGR_PRIVACY_ID_NB,
	SMW_KEYMGR_PRIVACY_ID_INVALID
};

/**
 * struct smw_keymgr_identifier - Key identifier
 * @subsystem_id: Secure Subsystem ID
 * @type_id: Key type ID
 * @privacy_id: Key privacy ID
 * @security_size: Security size in bits
 * @id: Key ID set by the subsystem
 * @attributes: Key attributes
 * @storage_id: Key storage identifier
 * @group: Key group (may not be used by all subsystems)
 */
struct smw_keymgr_identifier {
	enum subsystem_id subsystem_id;
	enum smw_config_key_type_id type_id;
	enum smw_keymgr_privacy_id privacy_id;
	unsigned int security_size;
	uint32_t id;
	smw_attr_attributes_t attributes;
	uint32_t storage_id;
	uint16_t group;
};

/**
 * struct smw_keymgr_key_ops - keypair with operations
 * @keys: Public API Keypair
 * @public_data: Get the @pub's public data reference
 * @public_length: Get the @pub's public length reference
 * @private_data: Get the @pub's private data reference
 * @private_length: Get the @pub's private length reference
 * @modulus: Get the @pub's modulus reference
 * @modulus_length: Get the @pub's modulus length reference
 * @exponent: Get the @pub's exponent reference
 * @exponent_length: Get the @pub's exponent length reference
 *
 * This structure is initialized by the function
 * smw_keymgr_convert_descriptor().
 * The operations are function of the keypair object defined by the
 * key type.
 */
struct smw_keymgr_key_ops {
	struct smw_keypair_buffer *keys;

	unsigned char **(*public_data)(struct smw_keymgr_key_ops *this);
	unsigned int *(*public_length)(struct smw_keymgr_key_ops *this);
	unsigned char **(*private_data)(struct smw_keymgr_key_ops *this);
	unsigned int *(*private_length)(struct smw_keymgr_key_ops *this);
	unsigned char **(*modulus)(struct smw_keymgr_key_ops *this);
	unsigned int *(*modulus_length)(struct smw_keymgr_key_ops *this);
	unsigned char **(*exponent)(struct smw_keymgr_key_ops *this);
	unsigned int *(*exponent_length)(struct smw_keymgr_key_ops *this);
};

/**
 * struct smw_keymgr_descriptor - Key descriptor
 * @identifier: Key identifier
 * @format_id: Format ID of the Key buffers
 * @pub: Key descriptor from the public API
 * @ops: Keypair operations
 */
struct smw_keymgr_descriptor {
	struct smw_keymgr_identifier identifier;
	enum smw_keymgr_format_id format_id;
	struct smw_key_descriptor *pub;
	struct smw_keymgr_key_ops ops;
};

/**
 * struct smw_keymgr_generate_key_args - Key generation arguments
 * @key_descriptor: Descriptor of the generated Key
 * @key_attributes: Pointer to the public Key attributes structure
 *
 */
struct smw_keymgr_generate_key_args {
	struct smw_keymgr_descriptor key_descriptor;
	struct smw_key_attributes *key_attributes;
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
 * @key_descriptor: Descriptor of the imported Key
 * @key_attributes: Pointer to the public Key attributes structure
 *
 */
struct smw_keymgr_import_key_args {
	struct smw_keymgr_descriptor key_descriptor;
	struct smw_key_attributes *key_attributes;
};

/**
 * struct smw_keymgr_export_key_args - Key export arguments
 * @key_descriptor: Descriptor of the exported Key
 *
 */
struct smw_keymgr_export_key_args {
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
 * struct smw_keymgr_get_key_attributes_args - Get Key attributes arguments
 * @identifier: Key identifier
 * @key_attributes: Pointer to the public Key attributes structure
 *
 */
struct smw_keymgr_get_key_attributes_args {
	struct smw_keymgr_identifier identifier;
	struct smw_key_attributes *key_attributes;
};

/**
 * struct smw_keymgr_commit_key_storage_args - Commit Key storage arguments
 * @pub: Pointer to the public commit key storage arguments structure
 *
 */
struct smw_keymgr_commit_key_storage_args {
	struct smw_commit_key_storage_args *pub;
};

/**
 * smw_keymgr_alloc_keypair_buffer() - Allocate a keypair object.
 * @descriptor: Pointer to the internal Key descriptor structure.
 * @public_length: Length of the public Key buffer.
 * @private_length: Length of the private Key buffer.
 * @modulus_length: Length of the modulus Key buffer (RSA key).
 *
 * This function allocates a keypair buffer object and
 * the keys buffers (public/private/modulus) if corresponding lengths are set.
 *
 * Return:
 * error code.
 */
int smw_keymgr_alloc_keypair_buffer(struct smw_keymgr_descriptor *descriptor,
				    unsigned int public_length,
				    unsigned int private_length,
				    unsigned int modulus_length);

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
 * smw_keymgr_free_keys_ptr_array() - Free the array of keymgr descriptors
 *                                    pointer
 * @keys_desc: Pointer to the array to free.
 * @nb_keys: Number of entries of @keys_desc.
 *
 * Return:
 * none
 */
void smw_keymgr_free_keys_ptr_array(struct smw_keymgr_descriptor **keys_desc,
				    unsigned int nb_keys);

/**
 * smw_keymgr_get_api_key_id() - Return the API key descriptor id value.
 * @descriptor: Pointer to the internal Key descriptor structure.
 *
 * This function returns the value of the API key descriptor id value.
 *
 * Return:
 * key descriptor id
 */
unsigned int
smw_keymgr_get_api_key_id(struct smw_keymgr_descriptor *descriptor);

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
 * smw_keymgr_get_private_data() - Return the address of the private Key buffer.
 * @descriptor: Pointer to the internal Key descriptor structure.
 *
 * This function returns the address of the private Key buffer.
 * If the @descriptor field @pub is NULL or if the @pub field @buffer is NULL,
 * the function returns NULL.
 *
 * Return:
 * NULL
 * address of the private Key buffer
 */
unsigned char *
smw_keymgr_get_private_data(struct smw_keymgr_descriptor *descriptor);

/**
 * smw_keymgr_get_private_length() - Return the length of the private Key
 *                                   buffer.
 * @descriptor: Pointer to the internal Key descriptor structure.
 *
 * This function returns the length of the private Key buffer.
 * If the @descriptor field @pub is NULL or if the @pub field @buffer is NULL,
 * the function returns 0.
 *
 * Return:
 * 0
 * length of the private Key buffer.
 */
unsigned int
smw_keymgr_get_private_length(struct smw_keymgr_descriptor *descriptor);

/**
 * smw_keymgr_get_modulus() - Return the address of the modulus buffer.
 * @descriptor: Pointer to the internal Key descriptor structure.
 *
 * This function returns the address of the modulus buffer.
 * If the @descriptor field @pub is NULL or if the @pub field @buffer is NULL,
 * the function returns NULL.
 *
 * Return:
 * NULL
 * address of the modulus buffer.
 */
unsigned char *smw_keymgr_get_modulus(struct smw_keymgr_descriptor *descriptor);

/**
 * smw_keymgr_get_modulus_length() - Return the length of the modulus buffer.
 * @descriptor: Pointer to the internal Key descriptor structure.
 *
 * This function returns the length of the modulus buffer.
 * If the @descriptor field @pub is NULL or if the @pub field @buffer is NULL,
 * the function returns 0.
 *
 * Return:
 * 0
 * length of the modulus Key buffer.
 */
unsigned int
smw_keymgr_get_modulus_length(struct smw_keymgr_descriptor *descriptor);

/**
 * smw_keymgr_get_exponent() - Return the address of the exponent buffer.
 * @descriptor: Pointer to the internal Key descriptor structure.
 *
 * This function returns the address of the exponent buffer.
 * If the @descriptor field @pub is NULL or if the @pub field @buffer is NULL,
 * the function returns NULL.
 *
 * Return:
 * NULL
 * address of the exponent buffer.
 */
unsigned char *
smw_keymgr_get_exponent(struct smw_keymgr_descriptor *descriptor);

/**
 * smw_keymgr_get_exponent_length() - Return the length of the exponent buffer.
 * @descriptor: Pointer to the internal Key descriptor structure.
 *
 * This function returns the length of the exponent buffer.
 * If the @descriptor field @pub is NULL or if the @pub field @buffer is NULL,
 * the function returns 0.
 *
 * Return:
 * 0
 * length of the exponent Key buffer.
 */
unsigned int
smw_keymgr_get_exponent_length(struct smw_keymgr_descriptor *descriptor);

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
 * smw_keymgr_set_private_data() - Set the address of the private Key buffer.
 * @descriptor: Pointer to the internal Key descriptor structure.
 * @private_data: Address of the private Key buffer.
 *
 * This function sets the address of the private Key buffer.
 * If the @buffer field @pub is NULL, the function returns with no action.
 *
 * Return:
 * none.
 */
void smw_keymgr_set_private_data(struct smw_keymgr_descriptor *descriptor,
				 unsigned char *private_data);

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
 * smw_keymgr_set_modulus_length() - Set the length of the modulus buffer.
 * @descriptor: Pointer to the internal Key descriptor structure.
 * @modulus_length: Length of the modulus buffer.
 *
 * This function sets the length of the modulus buffer.
 * If the @buffer field @pub is NULL, the function returns with no action.
 *
 * Return:
 * none.
 */
void smw_keymgr_set_modulus_length(struct smw_keymgr_descriptor *descriptor,
				   unsigned int modulus_length);

/**
 * smw_keymgr_set_exponent_length() - Set the length of the exponent buffer.
 * @descriptor: Pointer to the internal Key descriptor structure.
 * @modulus_length: Length of the exponent buffer.
 *
 * This function sets the length of the exponent buffer.
 * If the @buffer field @pub is NULL, the function returns with no action.
 *
 * Return:
 * none.
 */
void smw_keymgr_set_exponent_length(struct smw_keymgr_descriptor *descriptor,
				    unsigned int exponent_length);

/**
 * smw_keymgr_update_public_buffer() - Update the public buffer fields
 * @descriptor: Key descriptor.
 * @data: Data to be converted in base64 if key buffer's format is base64.
 * @length: Length of the @data.
 *
 * If the key buffer format is base64, the function converts the @data to
 * base64 and update the key buffer's data field. Otherwise, the key buffer's
 * data is assumed to be the same as the @data.
 *
 * Key buffer's length is updated if function success of return
 * SMW_STATUS_OUTPUT_TOO_SHORT.
 *
 * If @data = NULL, only the key buffer's length is updated.
 *
 * Return:
 * SMW_STATUS_OK                 - Success
 * SMW_STATUS_OPERATION_FAILURE  - Operation failed
 * SMW_STATUS_OUTPUT_TOO_SHORT   - Output buffer is too short
 * SMW_STATUS_INVALID_PARAM      - One of the parameter is invalid.
 */
int smw_keymgr_update_public_buffer(struct smw_keymgr_descriptor *descriptor,
				    unsigned char *data, unsigned int length);

/**
 * smw_keymgr_update_private_buffer() - Update the private buffer fields
 * @descriptor: key descriptor.
 * @data: Data to be converted in base64 if key buffer's format is base64.
 * @length: Length of the @data.
 *
 * If the key buffer format is base64, the function converts the @data to
 * base64 and update the key buffer's data field. Otherwise, the key buffer's
 * data is assumed to be the same as the @data.
 *
 * Key buffer's length is updated if function success of return
 * SMW_STATUS_OUTPUT_TOO_SHORT.
 *
 * If @data = NULL, only the key buffer's length is updated.
 *
 * Return:
 * SMW_STATUS_OK                 - Success
 * SMW_STATUS_OPERATION_FAILURE  - Operation failed
 * SMW_STATUS_OUTPUT_TOO_SHORT   - Output buffer is too short
 * SMW_STATUS_INVALID_PARAM      - One of the parameter is invalid.
 */
int smw_keymgr_update_private_buffer(struct smw_keymgr_descriptor *descriptor,
				     unsigned char *data, unsigned int length);

/**
 * smw_keymgr_update_modulus_buffer() - Update the modulus buffer fields
 * @descriptor: key descriptor.
 * @data: Data to be converted in base64 if key buffer's format is base64.
 * @length: Length of the @data.
 *
 * If the key buffer format is base64, the function converts the @data to
 * base64 and update the key buffer's data field. Otherwise, the key buffer's
 * data is assumed to be the same as the @data.
 *
 * Key buffer's length is updated if function success of return
 * SMW_STATUS_OUTPUT_TOO_SHORT.
 *
 * If @data = NULL, only the key buffer's length is updated.
 *
 * Return:
 * SMW_STATUS_OK                 - Success
 * SMW_STATUS_OPERATION_FAILURE  - Operation failed
 * SMW_STATUS_OUTPUT_TOO_SHORT   - Output buffer is too short
 * SMW_STATUS_INVALID_PARAM      - One of the parameter is invalid.
 */
int smw_keymgr_update_modulus_buffer(struct smw_keymgr_descriptor *descriptor,
				     unsigned char *data, unsigned int length);

/**
 * smw_keymgr_convert_descriptor() - Key descriptor conversion.
 * @in: Pointer to a public Key descriptor.
 * @out: Pointer to an internal Key descriptor.
 * @new_key: True if it's a new key or false.
 * @subsystem_id: Pointer to Secure Subsystem ID.
 *
 * This function converts a public Key descriptor
 * into an internal Key descriptor.
 *
 * Return:
 * error code.
 */
int smw_keymgr_convert_descriptor(struct smw_key_descriptor *in,
				  struct smw_keymgr_descriptor *out,
				  bool new_key,
				  enum subsystem_id *subsystem_id);

/**
 * smw_keymgr_convert_descriptors() - Convert public key descriptors pointer array
 *                                    in internal key descriptors pointer array
 * @in: Address of the pointer to the array of public key descriptors
 *             pointer to convert.
 * @out: Pointer to an internal Key descriptors array.
 * @nb_keys: Number of keys.
 * @subsystem_id: Pointer to Secure Subsystem ID.
 *
 * Return:
 * SMW_STATUS_OK		- Success
 * SMW_STATUS_ALLOC_FAILURE	- Memory allocation failure
 * Error code from smw_keymgr_convert_descriptor()
 */
int smw_keymgr_convert_descriptors(struct smw_key_descriptor **in,
				   struct smw_keymgr_descriptor ***out,
				   unsigned int nb_keys,
				   enum subsystem_id *subsystem_id);

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

#endif /* __KEYMGR_H__ */
