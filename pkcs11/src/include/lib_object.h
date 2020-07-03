/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020 NXP
 */

#ifndef __LIB_OBJECT_H__
#define __LIB_OBJECT_H__

#include "types.h"

/**
 * libobj_create() - Create an object
 * @hsession: Session handle
 * @attrs: List of the object attributes
 * @nb_attrs: Number of attributes
 * @hobj: Object handle
 *
 * After verifing the validity of the @hsession, the function
 * checks the attributes list @attrs function of the Object Class
 * attributes.
 * Finally, adds the object in the session's object list if all attributes
 * are correct.
 *
 * return:
 * CKR_CURVE_NOT_SUPPORTED       - Curve is not supported
 * CKR_ATTRIBUTE_READ_ONLY       - One attribute is read only
 * CKR_TEMPLATE_INCOMPLETE       - Attribute type not found
 * CKR_TEMPLATE_INCONSISTENT     - Attribute type must not be defined
 * CKR_ATTIBUTE_VALUE_INVALID    - Attribute value is not valid
 * CKR_USER_NOT_LOGGED_IN        - User must log to create object
 * CKR_HOST_MEMORY               - Allocation error
 * CKR_CRYPTOKI_NOT_INITIALIZED  - Context not initialized
 * CKR_GENERAL_ERROR             - No slot defined
 * CKR_SESSION_HANDLE_INVALID    - Session Handle invalid
 * CKR_SESSION_CLOSED            - Session closed
 * CKR_FUNCTION_FAILED           - Function failure
 * CKR_OK                        - Success
 */
CK_RV libobj_create(CK_SESSION_HANDLE hsession, CK_ATTRIBUTE_PTR attrs,
		    CK_ULONG nb_attrs, CK_OBJECT_HANDLE_PTR hobj);

/**
 * libobj_delete() - Delete an object
 * @object: Object to delete
 */
void libobj_delete(struct libobj *object);

/**
 * libobj_destroy() - Destroy an object
 * @hsession: Session handle
 * @hobject: Object handle
 *
 * return:
 * CKR_FUNCTION_FAILED           - Object not supported
 * CKR_ACTION_PROHIBITED         - Object is not destroyable
 * CKR_OBJECT_HANDLE_INVALID     - Object not found
 * CKR_CRYPTOKI_NOT_INITIALIZED  - Context not initialized
 * CKR_GENERAL_ERROR             - No slot defined
 * CKR_SESSION_HANDLE_INVALID    - Session Handle invalid
 * CKR_SESSION_CLOSED            - Session closed
 * CKR_OK                        - Success
 */
CK_RV libobj_destroy(CK_SESSION_HANDLE hsession, CK_OBJECT_HANDLE hobject);

#endif /* __LIB_OBJECT_H__ */
