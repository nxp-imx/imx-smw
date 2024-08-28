/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2023-2024 NXP
 */

#ifndef __OBJECT_DB_H__
#define __OBJECT_DB_H__

#include "keymgr_db.h"
#include "storage.h"

#define KEY_DEFAULT_LABEL  "Key"
#define DATA_DEFAULT_LABEL "Data"

/**
 * smw_object_db_create() - Create an object in the database
 * @id: New object identifier created in the database
 * @attributes: Object attributes
 * @obj: Object descriptor
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
int smw_object_db_create(unsigned int *id, smw_attr_attributes_t attributes,
			 struct smw_object_descriptor *obj);

/**
 * smw_object_db_update() - Update an object in the database
 * @id: Object identifier to update in the database
 * @attributes: Object attributes
 * @obj: Object descriptor
 *
 * Function updates an object in the database. The given @identifier
 * replaces the key entry's data.
 *
 * Return:
 * SMW_STATUS_OK                - Success
 * SMW_STATUS_OPS_INVALID       - OSAL operation invalid
 * SMW_STATUS_OBJ_DB_UPDATE     - Object update error
 * SMW_STATUS_UNKNOWN_ID        - Object ID is unknown
 */
int smw_object_db_update(unsigned int id, smw_attr_attributes_t attributes,
			 struct smw_object_descriptor *obj);

/**
 * smw_object_db_delete() - Delete an object in the database
 * @id: Object identifier to delete in the database
 * @attributes: Object attributes
 *
 * Return:
 * SMW_STATUS_OK                - Success
 * SMW_STATUS_OPS_INVALID       - OSAL operation invalid
 * SMW_STATUS_OBJ_DB_DELETE     - Object delete error
 * SMW_STATUS_UNKNOWN_ID        - Object ID is unknown
 */
int smw_object_db_delete(unsigned int id, smw_attr_attributes_t attributes);

/**
 * smw_object_db_get_info() - Retrieve the object information from the database
 * @id: Object identifier in the database
 * @attributes: Object attributes
 * @obj: Object descriptor
 *
 * Return:
 * SMW_STATUS_OK                - Success
 * SMW_STATUS_OPS_INVALID       - OSAL operation invalid
 * SMW_STATUS_OBJ_DB_GET_INFO   - Object get information error
 * SMW_STATUS_UNKNOWN_ID        - Object ID is unknown
 */
int smw_object_db_get_info(unsigned int id, smw_attr_attributes_t attributes,
			   struct smw_object_descriptor *obj);

#endif /* __OBJECT_DB_H__ */
