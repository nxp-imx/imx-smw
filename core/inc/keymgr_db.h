/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2022 NXP
 */

#ifndef __KEYMGR_DB_H__
#define __KEYMGR_DB_H__

#include "keymgr.h"

/**
 * smw_keymgr_db_create() - Create a key in the database
 * @id: New key identifier created in the database
 * @identifier: Internal Key identifier object
 *
 * Function creates a new key in the OSAL Key database. The
 * given @identifier is stored in the key entry.
 * Objective of the function is to ensure that key can be
 * created in the database before creating/importing key in
 * the subsytem.
 *
 * Return:
 * SMW_STATUS_OK                - Success
 * SMW_STATUS_OPS_INVALID       - OSAL operation invalid
 * SMW_STATUS_KEY_DB_CREATE     - Key creation error
 */
int smw_keymgr_db_create(unsigned int *id,
			 struct smw_keymgr_identifier *identifier);

/**
 * smw_keymgr_db_update() - Update a key in the database
 * @id: Key identifier to update in the database
 * @identifier: Internal Key identifier object
 *
 * Function updates a key in the database. The given @identifier
 * replaces the key entry's data.
 *
 * Return:
 * SMW_STATUS_OK                - Success
 * SMW_STATUS_OPS_INVALID       - OSAL operation invalid
 * SMW_STATUS_KEY_DB_UPDATE     - Key update error
 */
int smw_keymgr_db_update(unsigned int id,
			 struct smw_keymgr_identifier *identifier);

/**
 * smw_keymgr_db_delete() - Delete a key in the database
 * @id: Key identifier to delete in the database
 * @identifier: Internal Key identifier object
 *
 * Return:
 * SMW_STATUS_OK                - Success
 * SMW_STATUS_OPS_INVALID       - OSAL operation invalid
 * SMW_STATUS_KEY_DB_DELETE     - Key delete error
 */
int smw_keymgr_db_delete(unsigned int id,
			 struct smw_keymgr_identifier *identifier);

/**
 * smw_keymgr_db_get_info() - Retrieve key's data from the database
 * @id: Key identifier in the database
 * @identifier: Internal Key identifier object
 *
 * Return:
 * SMW_STATUS_OK                - Success
 * SMW_STATUS_OPS_INVALID       - OSAL operation invalid
 * SMW_STATUS_KEY_DB_GET_INFO   - Key get information error
 */
int smw_keymgr_db_get_info(unsigned int id,
			   struct smw_keymgr_identifier *identifier);

#endif /* __KEYMGR_DB_H__ */
