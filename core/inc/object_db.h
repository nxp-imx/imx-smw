/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2023 NXP
 */

#ifndef __OBJECT_DB_H__
#define __OBJECT_DB_H__

#include "object.h"
#include "keymgr.h"
#include "storage.h"

union smw_object_db_info {
	struct smw_keymgr_identifier key_identifier;
	struct smw_storage_data_info data_info;
};

/**
 * smw_object_db_create() - Create an object in the database
 * @id: New object identifier created in the database
 * @persistence_id: Object persistence ID
 * @info: Object information
 *
 * Function creates a new object in the OSAL object database. The
 * given @info is stored in the object entry.
 * Objective of the function is to ensure that the object can be
 * created in the database before storing the obecjt in the
 * subsystem.
 *
 * Return:
 * SMW_STATUS_OK                - Success
 * SMW_STATUS_OPS_INVALID       - OSAL operation invalid
 * SMW_STATUS_OBJ_DB_CREATE     - Object creation error
 */
int smw_object_db_create(unsigned int *id,
			 enum smw_object_persistence_id persistence_id,
			 union smw_object_db_info *info);

/**
 * smw_object_db_update() - Update an object in the database
 * @id: Object identifier to update in the database
 * @persistence_id: Object persistence ID
 * @info: Object information
 *
 * Function updates an object in the database. The given @identifier
 * replaces the key entry's data.
 *
 * Return:
 * SMW_STATUS_OK                - Success
 * SMW_STATUS_OPS_INVALID       - OSAL operation invalid
 * SMW_STATUS_OBJ_DB_UPDATE     - Object update error
 */
int smw_object_db_update(unsigned int id,
			 enum smw_object_persistence_id persistence_id,
			 union smw_object_db_info *info);

/**
 * smw_object_db_delete() - Delete an object in the database
 * @id: Object identifier to delete in the database
 * @persistence_id: Object persistence ID
 *
 * Return:
 * SMW_STATUS_OK                - Success
 * SMW_STATUS_OPS_INVALID       - OSAL operation invalid
 * SMW_STATUS_OBJ_DB_DELETE     - Object delete error
 */
int smw_object_db_delete(unsigned int id,
			 enum smw_object_persistence_id persistence_id);

/**
 * smw_object_db_get_info() - Retrieve the object information from the database
 * @id: Object identifier in the database
 * @persistence_id: Object persistence ID
 * @info: Object information
 *
 * Return:
 * SMW_STATUS_OK                - Success
 * SMW_STATUS_OPS_INVALID       - OSAL operation invalid
 * SMW_STATUS_OBJ_DB_GET_INFO   - Object get information error
 * SMW_STATUS_UNKNOWN_ID        - Object ID is unknown
 */
int smw_object_db_get_info(unsigned int id,
			   enum smw_object_persistence_id persistence_id,
			   union smw_object_db_info *info);

#endif /* __OBJECT_DB_H__ */
