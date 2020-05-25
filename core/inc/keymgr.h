/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020 NXP
 */

/**
 * struct smw_key_identifier - Key identifier
 * @subsystem_id: Secure Subsystem ID
 * @key_type_id: Key type ID
 * @security_size: Key length
 * @is_private: true - private Key / false - public Key
 * @id: Key ID set by the subsystem
 *
 */
struct smw_key_identifier {
	enum subsystem_id subsystem_id;
	enum smw_config_key_type_id key_type_id;
	unsigned int security_size;
	bool is_private;
	unsigned long id;
};

/**
 * struct smw_keymgr_generate_key_args - Key generation arguments
 * @key_type_id: Key type ID
 * @security_size: Security size
 * @key_attributes_list: Key attributes list
 * @key_attributes_list_length: Length of the Key attributes list
 * @key_identifier: Pointer to the new Key identifier
 *
 */
struct smw_keymgr_generate_key_args {
	/* Inputs */
	enum smw_config_key_type_id key_type_id;
	unsigned int security_size;
	const unsigned char *key_attributes_list;
	unsigned int key_attributes_list_length;
	/* Outputs */
	struct smw_key_identifier *key_identifier;
};

/**
 * struct smw_keymgr_derive_key_args - Key derivation arguments
 * @original_key_identifier: Pointer to a Key identifier
 * @key_type_id: Key type ID
 * @security_size: Security size
 * @key_attributes_list: Key attributes list
 * @key_attributes_list_length: Length of the Key attributes list
 * @key_identifier: Pointer to the new Key identifier
 *
 */
struct smw_keymgr_derive_key_args {
	/* Inputs */
	struct smw_key_identifier *original_key_identifier;
	enum smw_config_key_type_id key_type_id;
	unsigned int security_size;
	const unsigned char *key_attributes_list;
	unsigned int key_attributes_list_length;
	/* Outputs */
	struct smw_key_identifier *key_identifier;
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
 * @key_type_id: Key type ID
 * @input_buffer: Location of the Key to be imported
 * @input_buffer_length: Length of the Key to be imported
 * @key_attributes_list: Key attributes list
 * @key_attributes_list_length: Length of the Key attributes list
 * @key_identifier: Pointer to the new Key identifier
 *
 */
struct smw_keymgr_import_key_args {
	/* Inputs */
	enum smw_config_key_type_id key_type_id;
	unsigned char *input_buffer;
	unsigned int input_buffer_length;
	const unsigned char *key_attributes_list;
	unsigned int key_attributes_list_length;
	/* Outputs */
	struct smw_key_identifier *key_identifier;
};

/**
 * struct smw_keymgr_export_key_args - Key export arguments
 * @key_identifier: Pointer to the Key identifier
 * @output_buffer: Location where the Key has to be exported
 * @output_buffer_length: Maximum length of the Key to be exported
 * @key_attributes_list: Key attributes list
 * @key_attributes_list_length: Length of the Key attributes list
 *
 */
struct smw_keymgr_export_key_args {
	/* Inputs */
	struct smw_key_identifier *key_identifier;
	/* Outputs */
	unsigned char *output_buffer;
	unsigned int output_buffer_length;
	const unsigned char *key_attributes_list;
	unsigned int key_attributes_list_length;
};

/**
 * struct smw_keymgr_delete_key_args - Key deletion arguments
 * @key_identifier: Pointer to the Key identifier
 *
 */
struct smw_keymgr_delete_key_args {
	/* Inputs */
	struct smw_key_identifier *key_identifier;
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
 * smw_keymgr_read_attributes() - Read key_attributes_list buffer.
 * @attributes_list: List of attributes buffer to read.
 * @attributes_length: Buffer size (bytes).
 * @key_attributes: Pointer to smw_keymgr_attributes structure to fill.
 *
 * This function reads a list of attributes parsed by smw_tlv_read_element()
 * function and fill smw_keymgr_attributes structure using fill_key_attributes()
 * function.
 * @attributes_list is encoded with TLV encoding scheme:
 * The ‘Type’ field is encoded as an ASCII string terminated with the null
 * character.
 * The ‘Length’ field is encoded with two bytes.
 * The ‘Value’ field is a byte stream that contains the data.
 *
 * Return:
 * SMW_STATUS_OK		- Success.
 * SMW_STATUS_INVALID_PARAM	- One of the parameter is invalid.
 * SMW_STATUS_ALLOC_FAILURE	- Memory allocation failed.
 */
int smw_keymgr_read_attributes(const unsigned char *attributes_list,
			       unsigned int attributes_length,
			       struct smw_keymgr_attributes *key_attributes);
