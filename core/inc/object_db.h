/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2023-2025 NXP
 */

#ifndef __OBJECT_DB_H__
#define __OBJECT_DB_H__

#include "osal.h"
#include "keymgr_db.h"
#include "storage.h"

#define KEY_DEFAULT_LABEL	 "Key"
#define KEY_DEFAULT_EL2GO_LABEL	 "Key-EdgeLock2GO"
#define DATA_DEFAULT_LABEL	 "Data"
#define DATA_DEFAULT_EL2GO_LABEL "Data-EdgeLock2GO"

/**
 * smw_object_db_prepare() - Prepare the osal object
 * @s_id: Objcet identifier in subsystem
 * @obj_desc: Object descriptor
 * @obj: OSAL object
 */
void smw_object_db_prepare(unsigned int s_id,
			   struct smw_object_descriptor *obj_desc,
			   struct smw_osal_object *obj);

/**
 * smw_object_db_create() - Create an object in the database
 * @s_id: Object identifier in the subsystem
 * @obj: Object descriptor
 *
 * Function creates a new object in the OSAL object database.
 * The @obj descriptor contains all information of the object to create
 * and the @s_id to object id in the subsystem.
 *
 * Objective of the function is to ensure that the object can be
 * created in the database before storing the object in the
 * subsystem.
 *
 * On success, the @obj->id contains the database id that user will get in
 * return of the object creation.
 * Could be identical to the @s_id if set by user.
 *
 * Return:
 * SMW_STATUS_OK                - Success
 * SMW_STATUS_OPS_INVALID       - OSAL operation invalid
 * SMW_STATUS_OBJ_DB_CREATE     - Object creation error
 */
int smw_object_db_create(unsigned int s_id, struct smw_object_descriptor *obj);

/**
 * smw_object_db_update() - Update an object in the database
 * @s_id: Object identifier in the subsystem
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
int smw_object_db_update(unsigned int s_id, struct smw_object_descriptor *obj);

/**
 * smw_object_db_delete() - Delete an object in the database
 * @obj: Object descriptor
 *
 * Return:
 * SMW_STATUS_OK                - Success
 * SMW_STATUS_OPS_INVALID       - OSAL operation invalid
 * SMW_STATUS_OBJ_DB_DELETE     - Object delete error
 * SMW_STATUS_UNKNOWN_ID        - Object ID is unknown
 */
int smw_object_db_delete(struct smw_object_descriptor *obj);

/**
 * smw_object_db_get_info() - Retrieve the object information from the database
 * @s_id: Object identifier in the subsystem
 * @obj: Object descriptor
 *
 * Return:
 * SMW_STATUS_OK                - Success
 * SMW_STATUS_OPS_INVALID       - OSAL operation invalid
 * SMW_STATUS_OBJ_DB_GET_INFO   - Object get information error
 * SMW_STATUS_UNKNOWN_ID        - Object ID is unknown
 */
int smw_object_db_get_info(unsigned int *s_id,
			   struct smw_object_descriptor *obj);

/**
 * smw_object_db_clean_descriptor() - Clean the object descriptor
 * @obj: Object descriptor
 *
 * Return:
 * None.
 */
void smw_object_db_clean_descriptor(struct smw_object_descriptor *obj);

#endif /* __OBJECT_DB_H__ */
