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
 * smw_keymgr_get_key_privacy_id() - Get the ID associated to a Key privacy name.
 * @name: Name of the Key privacy.
 * @id: Pointer where the ID is written.
 *
 * This function gets the ID associated to a Key privacy name.
 *
 * Return:
 * error code.
 */
int smw_keymgr_get_key_privacy_id(smw_key_privacy_t name,
				  enum smw_keymgr_privacy_id *id);

/**
 * smw_keymgr_get_key_privacy_name() - Get the name associated to a Key privacy ID.
 * @id: Key privacy ID.
 *
 * This function gets the name associated to a Key privacy ID.
 *
 * Return:
 * Key privacy name.
 */
smw_key_privacy_t
smw_keymgr_get_key_privacy_name(enum smw_keymgr_privacy_id id);

/**
 * smw_keymgr_get_key_format_id() - Get the ID associated to a key format name.
 * @name: Name as a string.
 * @id: Pointer where the ID is written.
 *
 * This function gets the ID associated to a key format name.
 *
 * Return:
 * error code.
 */
int smw_keymgr_get_key_format_id(smw_key_format_t name,
				 enum smw_keymgr_format_id *id);

/**
 * smw_keymgr_get_key_format_name() - Get the key format name.
 * @id: Pointer to key format ID.
 *
 * This function gets the Key format name associated to an ID.
 *
 * Return:
 * Key format name.
 */
smw_key_format_t smw_keymgr_get_key_format_name(enum smw_keymgr_format_id id);

/**
 * smw_keymgr_set_hex_key_buffer() - Set HEX buffer.
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
int smw_keymgr_set_hex_key_buffer(enum smw_keymgr_format_id format_id,
				  unsigned char *buffer,
				  unsigned int buffer_len,
				  unsigned char **hex_buffer,
				  unsigned int *hex_buffer_len);

/**
 * smw_keymgr_get_hex_key_buffer_len() - Calculate the hex length of a buffer.
 * @format_id: Format of the input buffer.
 * @buffer: Pointer to the input buffer.
 * @buffer_len: @buffer length in bytes.
 * @hex_buffer_len: Length of @buffer in hex.
 *
 * Return:
 * SMW_STATUS_OK            - Success.
 * SMW_STATUS_INVALID_PARAM - One of the parameter is invalid.
 */
int smw_keymgr_get_hex_key_buffer_len(enum smw_keymgr_format_id format_id,
				      unsigned char *buffer,
				      unsigned int buffer_len,
				      unsigned int *hex_buffer_len);

#endif /* __KEY_H__ */
