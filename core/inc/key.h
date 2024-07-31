/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2024 NXP
 */

#ifndef __KEY_H__
#define __KEY_H__

#include "smw/names.h"

enum smw_keymgr_format_id {
	/* Key format */
	SMW_KEYMGR_FORMAT_ID_HEX,
	SMW_KEYMGR_FORMAT_ID_BASE64,
	SMW_KEYMGR_FORMAT_ID_NB,
	SMW_KEYMGR_FORMAT_ID_INVALID
};

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
 * @format_id: Pointer to key format ID.
 *
 * This function gets the Key format name associated to an ID.
 *
 * Return:
 * Key format name.
 */
smw_key_format_t
smw_keymgr_get_key_format_name(enum smw_keymgr_format_id format_id);

#endif /* __KEY_H__ */
