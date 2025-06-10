/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2024-2025 NXP
 */

#ifndef __OBJECT_DESC_H__
#define __OBJECT_DESC_H__

#include "smw/object.h"
#include "pkcs11smw.h"

/**
 * obj_db_retrieve() - Retrieve objects from database
 * @hsession: Session handle
 * @attrs: List of object attributes
 * @nb_attrs: Number of attributes
 * @pnb_imported: Number of imported objects
 *
 * return:
 * CKR_OK                       - Success
 * CKR_GENERAL_ERROR            - Handle invalid
 * CKR_ARGUMENTS_BAD            - Wrong argument
 * CKR_SESSION_HANDLE_INVALID   - Session Handle invalid
 * CKR_HOST_MEMORY              - Allocation error
 * CKR_OK                       - Objects imported
 */
CK_RV obj_db_retrieve(CK_SESSION_HANDLE hsession, CK_ATTRIBUTE_PTR attrs,
		      CK_ULONG nb_attrs, CK_ULONG *pnb_imported);

/**
 * obj_db_update() - Update object in database
 * @obj: Object
 *
 * return:
 * CKR_OK             - Success
 * CKR_GENERAL_ERROR  - Bad type of object
 */
CK_RV obj_db_update(struct libobj_obj *obj);

/**
 * obj_db_get() - Get object in database
 * @obj: Object
 * @descriptor: SMW Object descriptor
 *
 * return:
 * CKR_OK             - Success
 * CKR_GENERAL_ERROR  - Bad type of object
 */
CK_RV obj_db_get(struct libobj_obj *obj,
		 struct smw_object_descriptor *descriptor);

/**
 * obj_db_get_size() - Get the object size
 * @obj: Object
 * @pulSize: Object's size
 *
 * return:
 * CKR_OK             - Success
 * CKR_GENERAL_ERROR  - Bad type of object
 */
CK_RV obj_db_get_size(struct libobj_obj *obj, CK_ULONG_PTR pulSize);

#endif /* __OBJECT_DESC_H__ */
