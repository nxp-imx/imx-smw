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
