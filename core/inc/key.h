/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2024-2025 NXP
 */

#ifndef __KEY_H__
#define __KEY_H__

#include "smw/names.h"
#include "base64.h"

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
 * @s_id: Key ID set by the subsystem
 * @key_attributes: Key attributes
 * @group: Key group (may not be used by all subsystems)
 */
struct smw_keymgr_identifier {
	enum subsystem_id subsystem_id;
	enum smw_config_key_type_id type_id;
	enum smw_keymgr_privacy_id privacy_id;
	unsigned int security_size;
	uint32_t s_id;
	struct smw_key_attributes key_attributes;
	uint16_t group;
};

#define INIT_SMW_KEYMGR_IDENTIFIER                                             \
	((struct smw_keymgr_identifier){                                       \
		.subsystem_id = SUBSYSTEM_ID_INVALID,                          \
		.type_id = SMW_CONFIG_KEY_TYPE_ID_INVALID,                     \
		.privacy_id = SMW_KEYMGR_PRIVACY_ID_INVALID,                   \
		.security_size = 0,                                            \
		.s_id = INVALID_KEY_ID,                                        \
		.key_attributes = { 0 },                                       \
		.group = 0 })

/**
 * struct smw_keymgr_key_ops - keypair with operations
 * @keys: Public API Keypair
 * @public_data: Get the @pub's public data reference
 * @public_length: Get the @pub's public length reference
 * @private_data: Get the @pub's private data reference
 * @private_length: Get the @pub's private length reference
 * @modulus: Get the @pub's modulus reference
 * @modulus_length: Get the @pub's modulus length reference
 * @public_exponent: Get the @pub's public exponent reference
 * @public_exponent_length: Get the @pub's public exponent length reference
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
	unsigned char **(*public_exponent)(struct smw_keymgr_key_ops *this);
	unsigned int *(*public_exponent_length)(struct smw_keymgr_key_ops *this);
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
 * smw_utils_key_get_privacy_name() - Get the name associated to a Key privacy ID.
 * @id: Key privacy ID.
 *
 * This function gets the name associated to a Key privacy ID.
 *
 * Return:
 * Key privacy name.
 */
smw_key_privacy_t smw_utils_key_get_privacy_name(enum smw_keymgr_privacy_id id);

/**
 * smw_utils_key_get_format_id() - Get the ID associated to a key format name.
 * @name: Name as a string.
 * @id: Pointer where the ID is written.
 *
 * This function gets the ID associated to a key format name.
 *
 * Return:
 * error code.
 */
int smw_utils_key_get_format_id(smw_key_format_t name,
				enum smw_keymgr_format_id *id);

/**
 * smw_utils_key_get_format_name() - Get the key format name.
 * @id: Pointer to key format ID.
 *
 * This function gets the Key format name associated to an ID.
 *
 * Return:
 * Key format name.
 */
smw_key_format_t smw_utils_key_get_format_name(enum smw_keymgr_format_id id);

/**
 * smw_utils_key_set_hex_buffer() - Set HEX buffer.
 * @format_id: Format of the input buffer.
 * @buffer: Pointer to the input buffer.
 * @buffer_len: @buffer length in bytes.
 * @hex_buffer: Pointer to the HEX buffer to update.
 * @hex_buffer_len: @hex_buffer length.
 *
 * If format id is BASE64, the input buffer in converted in HEX format.
 * Memory allocated to @hex_buffer in smw_utils_base64_decode() should
 * be freed at the end of the operation.
 *
 * Return:
 * SMW_STATUS_OK  - Success.
 * Error code from smw_utils_base64_decode().
 */
int smw_utils_key_set_hex_buffer(enum smw_keymgr_format_id format_id,
				 unsigned char *buffer, unsigned int buffer_len,
				 unsigned char **hex_buffer,
				 unsigned int *hex_buffer_len);

/**
 * smw_utils_key_get_hex_buffer_len() - Calculate the hex length of a buffer.
 * @format_id: Format of the input buffer.
 * @buffer: Pointer to the input buffer.
 * @buffer_len: @buffer length in bytes.
 * @hex_buffer_len: Length of @buffer in hex.
 *
 * Return:
 * SMW_STATUS_OK            - Success.
 * SMW_STATUS_INVALID_PARAM - One of the parameter is invalid.
 */
int smw_utils_key_get_hex_buffer_len(enum smw_keymgr_format_id format_id,
				     unsigned char *buffer,
				     unsigned int buffer_len,
				     unsigned int *hex_buffer_len);

/**
 * smw_utils_key_copy() - Copy keymgr descriptor
 * @out: Output keymgr descriptor
 * @in: Input keymgr descriptor
 *
 * The function copies the @in descriptor to the @out descriptor allocating
 * @out->pub public key descriptor and the @put->pub->buffer if input key
 * buffer defined.
 *
 * Return:
 * SMW_STATUS_OK            - Success.
 * SMW_STATUS_INVALID_PARAM - One of the parameter is invalid.
 * SMW_STATUS_ALLOC_FAILURE - Memory allocation error.
 */
int smw_utils_key_copy(struct smw_keymgr_descriptor *out,
		       struct smw_keymgr_descriptor *in);

/**
 * smw_utils_key_free() - Free keymgr descriptor
 * @desc: Keymgr descriptor to free
 *
 * The function frees the @desc->oub->buffer and @desc->pub public key
 * descriptor.
 */
void smw_utils_key_free(struct smw_keymgr_descriptor *desc);

#endif /* __KEY_H__ */
