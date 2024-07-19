/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2022-2024 NXP
 */

#ifndef __KEYMGR_DB_H__
#define __KEYMGR_DB_H__

#include "keymgr.h"

/**
 * struct smw_keymgr_key_info - Key information stored in object database
 * @subsystem_name: Secure Subsystem name
 * @type_id: Key type ID
 * @privacy_id: Key privacy ID
 * @security_size: Security size in bits
 * @id: Key ID set by the subsystem
 * @attributes: Key attributes
 * @storage_id: Key storage identifier
 * @group: Key group (may not be used by all subsystems)
 */
struct smw_keymgr_key_info {
	smw_subsystem_t subsystem_name;
	enum smw_config_key_type_id type_id;
	enum smw_keymgr_privacy_id privacy_id;
	unsigned int security_size;
	uint32_t id;
	smw_attr_attributes_t attributes;
	uint32_t storage_id;
	uint16_t group;
};

/**
 * smw_keymgr_db_create() - Create a key in the database
 * @id: New key identifier created in the database
 * @identifier: Internal Key identifier object
 *
 * Function creates a new key in the OSAL object database. The
 * given @identifier is stored in the object entry.
 * Objective of the function is to ensure that key can be
 * created in the database before creating/importing key in
 * the subsystem.
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
 * SMW_STATUS_UNKNOWN_ID        - Key ID is unknown
 */
int smw_keymgr_db_get_info(unsigned int id,
			   struct smw_keymgr_identifier *identifier);

#endif /* __KEYMGR_DB_H__ */
