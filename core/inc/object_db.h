/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2023-2025 NXP
 */

#ifndef __OBJECT_DB_H__
#define __OBJECT_DB_H__

#include "keymgr_db.h"
#include "storage.h"

#define KEY_DEFAULT_LABEL	 "Key"
#define KEY_DEFAULT_EL2GO_LABEL	 "Key-EdgeLock2GO"
#define DATA_DEFAULT_LABEL	 "Data"
#define DATA_DEFAULT_EL2GO_LABEL "Data-EdgeLock2GO"

/**
 * smw_object_db_prep_desc() - Prepare/complete the object descriptor
 * @id: Object identifier
 * @obj: Object descriptor
 */
void smw_object_db_prep_desc(unsigned int id,
			     struct smw_object_descriptor *obj);

/**
 * smw_object_db_create() - Create an object in the database
 * @id: New object identifier created in the database
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
int smw_object_db_create(unsigned int *id, struct smw_object_descriptor *obj);

/**
 * smw_object_db_update() - Update an object in the database
 * @id: Object identifier to update in the database
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
int smw_object_db_update(unsigned int id, struct smw_object_descriptor *obj);

/**
 * smw_object_db_delete() - Delete an object in the database
 * @id: Object identifier to delete in the database
 * @obj: Object descriptor
 *
 * Return:
 * SMW_STATUS_OK                - Success
 * SMW_STATUS_OPS_INVALID       - OSAL operation invalid
 * SMW_STATUS_OBJ_DB_DELETE     - Object delete error
 * SMW_STATUS_UNKNOWN_ID        - Object ID is unknown
 */
int smw_object_db_delete(unsigned int id, struct smw_object_descriptor *obj);

/**
 * smw_object_db_get_info() - Retrieve the object information from the database
 * @id: Object identifier in the database
 * @obj: Object descriptor
 *
 * Return:
 * SMW_STATUS_OK                - Success
 * SMW_STATUS_OPS_INVALID       - OSAL operation invalid
 * SMW_STATUS_OBJ_DB_GET_INFO   - Object get information error
 * SMW_STATUS_UNKNOWN_ID        - Object ID is unknown
 */
int smw_object_db_get_info(unsigned int id, struct smw_object_descriptor *obj);

/**
 * smw_object_db_clean_descriptor() - Clean the object descriptor
 * @obj: Object descriptor
 *
 * Return:
 * None.
 */
void smw_object_db_clean_descriptor(struct smw_object_descriptor *obj);

#endif /* __OBJECT_DB_H__ */
