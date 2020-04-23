/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020 NXP
 */

/**
 * struct smw_key_identifier - SMW Key identifier
 *
 * This structure is an opaque structure that describes a Key identifier.
 */
struct smw_key_identifier;

/**
 * struct smw_generate_key_args - Key generation arguments
 * @version: Version of this structure
 * @subsystem_name: Secure Subsystem name
 * @key_type_name: Key type name
 * @security_size: Security size in bits
 * @key_attributes_list: Key attributes list
 * @key_attributes_list_length: Length of the Key attributes list
 * @key_identifier: Pointer to the new Key identifier
 *
 * @subsystem_name designates the Secure Subsystem to be used.
 * If this field is NULL, the default Secure Subsystem configured for
 * this Security Operation is used.
 * @key_identifier must be allocated with smw_alloc_key_identifier().
 */
struct smw_generate_key_args {
	/* Inputs */
	unsigned char version;
	const char *subsystem_name;
	const char *key_type_name;
	unsigned int security_size;
	const unsigned char *key_attributes_list;
	unsigned int key_attributes_list_length;
	/* Outputs */
	struct smw_key_identifier *key_identifier;
};

/**
 * struct smw_derive_key_args - Key derivation arguments
 * @version: Version of this structure
 * @subsystem_name: Secure Subsystem name
 * @original_key_identifier: Pointer to a Key identifier
 * @key_type_name: Key type name
 * @security_size: Security size in bits
 * @key_attributes_list: Key attributes list
 * @key_attributes_list_length: Length of the Key attributes list
 * @key_identifier: Pointer to the new Key identifier
 *
 * @subsystem_name designates the Secure Subsystem to be used.
 * If this field is NULL, the default Secure Subsystem configured for
 * this Security Operation is used.
 * @key_identifier must be allocated with smw_alloc_key_identifier().
 * @original_key_identifier is the Key identifier the new Key is derived from.
 */
struct smw_derive_key_args {
	/* Inputs */
	unsigned char version;
	const char *subsystem_name;
	struct smw_key_identifier *original_key_identifier;
	const char *key_type_name;
	unsigned int security_size;
	const unsigned char *key_attributes_list;
	unsigned int key_attributes_list_length;
	/* Outputs */
	struct smw_key_identifier *key_identifier;
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
 * @key_type_name: Key type name
 * @input_buffer: Location of the Key to be imported
 * @input_buffer_length: Length of the Key to be imported
 * @key_attributes_list: Key attributes list
 * @key_attributes_list_length: Length of the Key attributes list
 * @key_identifier: Pointer to the new Key identifier
 *
 * @subsystem_name designates the Secure Subsystem to be used.
 * If this field is NULL, the default Secure Subsystem configured for
 * this Security Operation is used.
 * @key_identifier must be allocated with smw_alloc_key_identifier().
 */
struct smw_import_key_args {
	/* Inputs */
	unsigned char version;
	const char *subsystem_name;
	const char *key_type_name;
	unsigned char *input_buffer;
	unsigned int input_buffer_length;
	const unsigned char *key_attributes_list;
	unsigned int key_attributes_list_length;
	/* Outputs */
	struct smw_key_identifier *key_identifier;
};

/**
 * struct smw_export_key_args - Key export arguments
 * @version: Version of this structure
 * @subsystem_name: Secure Subsystem name
 * @key_identifier: Pointer to the Key identifier
 * @output_buffer: Location where the Key has to be exported
 * @output_buffer_length: Maximum length of the Key to be exported
 * @key_attributes_list: Key attributes list
 * @key_attributes_list_length: Length of the Key attributes list
 *
 * @subsystem_name designates the Secure Subsystem to be used.
 * If this field is NULL, the default Secure Subsystem configured for
 * this Security Operation is used.
 */
struct smw_export_key_args {
	/* Inputs */
	unsigned char version;
	const char *subsystem_name;
	struct smw_key_identifier *key_identifier;
	/* Outputs */
	unsigned char *output_buffer;
	unsigned int output_buffer_length;
	const unsigned char *key_attributes_list;
	unsigned int key_attributes_list_length;
};

/**
 * struct smw_delete_key_args - Key deletion arguments
 * @version: Version of this structure
 * @key_identifier: Pointer to the Key identifier
 *
 */
struct smw_delete_key_args {
	/* Inputs */
	unsigned char version;
	struct smw_key_identifier *key_identifier;
};

/**
 * smw_alloc_key_identifier() - Allocate a Key identifier structure.
 * @key_identifier: address of the pointer to the Key identifier.
 *
 * This function allocates a Key identifier structure.
 *
 * Return:
 * error code.
 */
int smw_alloc_key_identifier(struct smw_key_identifier **key_identifier);

/**
 * smw_free_key_identifier() - Free a Key identifier structure.
 * @key_identifier: the pointer to the Key identifier.
 *
 * This function frees a Key identifier structure
 * allocated with smw_alloc_key_identifier().
 *
 * Return:
 * error code.
 */
int smw_free_key_identifier(struct smw_key_identifier *key_identifier);

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
