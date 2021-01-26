/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2021 NXP
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
 * CKR_SLOT_ID_INVALID           - Slot ID is not valid
 * CKR_CURVE_NOT_SUPPORTED       - Curve is not supported
 * CKR_ATTRIBUTE_READ_ONLY       - One attribute is read only
 * CKR_TEMPLATE_INCOMPLETE       - Attribute type not found
 * CKR_TEMPLATE_INCONSISTENT     - Attribute type must not be defined
 * CKR_ATTRIBUTE_VALUE_INVALID   - Attribute value is not valid
 * CKR_USER_NOT_LOGGED_IN        - User must log to create object
 * CKR_HOST_MEMORY               - Allocation error
 * CKR_CRYPTOKI_NOT_INITIALIZED  - Context not initialized
 * CKR_GENERAL_ERROR             - No slot defined
 * CKR_SESSION_HANDLE_INVALID    - Session Handle invalid
 * CKR_SESSION_CLOSED            - Session closed
 * CKR_FUNCTION_FAILED           - Function failure
 * CKR_DEVICE_MEMORY             - Device memory error
 * CKR_DEVICE_ERROR              - Device failure
 * CKR_OK                        - Success
 */
CK_RV libobj_create(CK_SESSION_HANDLE hsession, CK_ATTRIBUTE_PTR attrs,
		    CK_ULONG nb_attrs, CK_OBJECT_HANDLE_PTR hobj);

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

/**
 * libobj_get_attribute() - Return object's attributes
 * @hsession: Session handle
 * @hobject: Object handle
 * @attrs: List of the object attributes to return
 * @nb_attrs: Number of attributes
 *
 * After verifing the validity of the @hsession and the @hobj,
 * the function returns the value of the given attributes list @attrs.
 *
 * return:
 * CKR_OBJECT_HANDLE_INVALID     - Object not found
 * CKR_CRYPTOKI_NOT_INITIALIZED  - Context not initialized
 * CKR_GENERAL_ERROR             - No slot defined
 * CKR_SESSION_HANDLE_INVALID    - Session Handle invalid
 * CKR_FUNCTION_FAILED           - Function failure
 * CKR_ATTRIBUTE_SENSITIVE       - Attribute is sensitive
 * CKR_BUFFER_TOO_SMALL          - One of the attributes length is too small
 * CKR_ATTRIBUTE_TYPE_INVALID    - One of the attributes is not present
 * CKR_OK                        - Success
 */
CK_RV libobj_get_attribute(CK_SESSION_HANDLE hsession, CK_OBJECT_HANDLE hobject,
			   CK_ATTRIBUTE_PTR attrs, CK_ULONG nb_attrs);

/**
 * libobj_modify_attribute() - Modify object's attributes
 * @hsession: Session handle
 * @hobject: Object handle
 * @attrs: List of the object attributes to modify
 * @nb_attrs: Number of attributes
 *
 * After verifing the validity of the @hsession and the @hobj,
 * the function modifies the value of the given attributes list @attrs.
 * If an attribute is not modifiable, the attribute is not changed and
 * CKR_ACTION_PROHIBITED error is returned.
 *
 * return:
 * CKR_OBJECT_HANDLE_INVALID     - Object not found
 * CKR_CRYPTOKI_NOT_INITIALIZED  - Context not initialized
 * CKR_GENERAL_ERROR             - No slot defined
 * CKR_SESSION_HANDLE_INVALID    - Session Handle invalid
 * CKR_ATTRIBUTE_READ_ONLY       - Attribute is read only
 * CKR_ATTRIBUTE_TYPE_INVALID    - Attribute not found
 * CKR_ATTRIBUTE_VALUE_INVALID   - Attribute value or length not valid
 * CKR_HOST_MEMORY               - Out of memory
 * CKR_FUNCTION_FAILED           - Object not supported
 * CKR_OK                        - Success
 */
CK_RV libobj_modify_attribute(CK_SESSION_HANDLE hsession,
			      CK_OBJECT_HANDLE hobject, CK_ATTRIBUTE_PTR attrs,
			      CK_ULONG nb_attrs);

/**
 * libobj_generate_key() - Generate a secret key object
 * @hsession: Session handle
 * @mech: Key generation mechanism
 * @attrs: List of the key attributes
 * @nb_attrs: Number of key attributes
 * @hkey: Key object handle
 *
 * After verifying the validity of the @hsession and the support of the
 * generate key mechanism, the function creates a secret key
 * object function of the related attributes.
 * To finish, the SlotID Generate Key operation is executed before
 * adding the objects in the session's object list if everything success.
 *
 * return:
 * CKR_MECHANISM_INVALID         - Mechanism not supported
 * CKR_SLOT_ID_INVALID           - Slot ID is not valid
 * CKR_ATTRIBUTE_READ_ONLY       - One attribute is read only
 * CKR_TEMPLATE_INCOMPLETE       - Attribute type not found
 * CKR_TEMPLATE_INCONSISTENT     - Attribute type must not be defined
 * CKR_ATTRIBUTE_VALUE_INVALID   - Attribute value is not valid
 * CKR_USER_NOT_LOGGED_IN        - User must log to create object
 * CKR_HOST_MEMORY               - Allocation error
 * CKR_CRYPTOKI_NOT_INITIALIZED  - Context not initialized
 * CKR_GENERAL_ERROR             - No slot defined
 * CKR_SESSION_HANDLE_INVALID    - Session Handle invalid
 * CKR_SESSION_CLOSED            - Session closed
 * CKR_FUNCTION_FAILED           - Function failure
 * CKR_OK                        - Success
 */
CK_RV libobj_generate_key(CK_SESSION_HANDLE hsession, CK_MECHANISM_PTR mech,
			  CK_ATTRIBUTE_PTR attrs, CK_ULONG nb_attrs,
			  CK_OBJECT_HANDLE_PTR hkey);

/**
 * libobj_generate_keypair() - Generate a keypair object
 * @hsession: Session handle
 * @mech: Keypair generation mechanism
 * @pub_attrs: List of the public key attributes
 * @nb_pub_attrs: Number of public key attributes
 * @priv_attrs: List of the private key attributes
 * @nb_priv_attrs: Number of private key attributes
 * @hpub: Public key object handle
 * @hpriv: Private key object handle
 *
 * After verifying the validity of the @hsession and the support of the
 * generate key mechanism, the function creates a public and private key
 * object function of the related attributes.
 * To finish, the SlotID Generate Key Pair operation is executed before
 * adding the objects in the session's object list if everything success.
 *
 * return:
 * CKR_MECHANISM_INVALID         - Mechanism not supported
 * CKR_SLOT_ID_INVALID           - Slot ID is not valid
 * CKR_CURVE_NOT_SUPPORTED       - Curve is not supported
 * CKR_ATTRIBUTE_READ_ONLY       - One attribute is read only
 * CKR_TEMPLATE_INCOMPLETE       - Attribute type not found
 * CKR_TEMPLATE_INCONSISTENT     - Attribute type must not be defined
 * CKR_ATTRIBUTE_VALUE_INVALID   - Attribute value is not valid
 * CKR_USER_NOT_LOGGED_IN        - User must log to create object
 * CKR_HOST_MEMORY               - Allocation error
 * CKR_CRYPTOKI_NOT_INITIALIZED  - Context not initialized
 * CKR_GENERAL_ERROR             - No slot defined
 * CKR_SESSION_HANDLE_INVALID    - Session Handle invalid
 * CKR_SESSION_CLOSED            - Session closed
 * CKR_FUNCTION_FAILED           - Function failure
 * CKR_DEVICE_MEMORY             - Device memory error
 * CKR_DEVICE_ERROR              - Device failure
 * CKR_OK                        - Success
 */
CK_RV libobj_generate_keypair(CK_SESSION_HANDLE hsession, CK_MECHANISM_PTR mech,
			      CK_ATTRIBUTE_PTR pub_attrs, CK_ULONG nb_pub_attrs,
			      CK_ATTRIBUTE_PTR priv_attrs,
			      CK_ULONG nb_priv_attrs, CK_OBJECT_HANDLE_PTR hpub,
			      CK_OBJECT_HANDLE_PTR hpriv);

/**
 * libobj_find_init() - Initialize the find object query
 * @hsession: Session handle
 * @attrs: List of the object attributes to find
 * @nb_attrs: Number of attributes
 *
 * Initializes a session find object query.
 * Objects must match defined @attrs, if @nb_attrs is 0, find all objects
 *
 * return:
 * CKR_CRYPTOKI_NOT_INITIALIZED  - Context not initialized
 * CKR_GENERAL_ERROR             - No slot defined
 * CKR_SESSION_HANDLE_INVALID    - Session Handle invalid
 * CKR_SESSION_CLOSED            - Session closed
 * CKR_ATTRIBUTE_VALUE_INVALID   - Attribute value is not valid
 * CKR_OPERATION_ACTIVE          - A query is already active
 * CKR_HOST_MEMORY               - Allocation error
 * CKR_OK                        - Success
 */
CK_RV libobj_find_init(CK_SESSION_HANDLE hsession, CK_ATTRIBUTE_PTR attrs,
		       CK_ULONG nb_attrs);

/**
 * libobj_find() - Continues search of objects matching started query
 * @hsession: Session handle
 * @pobjs: List of the object handles found
 * @nb_obj_max: Maximum number of object handles to be returned
 * @pnb_objs_found: Number of object handles found
 *
 * Continues a maximum of @nb_obj_max matching the started query operation
 * with libobj_find_init function.
 * If no more objects found, set @pnb_objs_found to 0, else @pnb_objs_found
 * is set with the number of object handles returned.
 *
 * return:
 * CKR_CRYPTOKI_NOT_INITIALIZED  - Context not initialized
 * CKR_GENERAL_ERROR             - No slot defined
 * CKR_SESSION_HANDLE_INVALID    - Session Handle invalid
 * CKR_OK                        - Success
 */
CK_RV libobj_find(CK_SESSION_HANDLE hsession, CK_OBJECT_HANDLE_PTR pobjs,
		  CK_ULONG nb_objs_max, CK_ULONG_PTR pnb_objs_found);

/**
 * libobj_find_final() - Finalize the find object query
 * @hsession: Session handle
 *
 * Finalizes a session find object query initiated with libobj_find_init
 * function.
 *
 * return:
 * CKR_CRYPTOKI_NOT_INITIALIZED  - Context not initialized
 * CKR_GENERAL_ERROR             - No slot defined
 * CKR_SESSION_HANDLE_INVALID    - Session Handle invalid
 * CKR_OK                        - Success
 */
CK_RV libobj_find_final(CK_SESSION_HANDLE hsession);

/**
 * libobj_list_destroy() - Destroy all objects of the @list
 * @list: List of objects
 *
 * Destroy all objects of the @list and the destroy the @list's mutex
 * protection.
 *
 * return:
 * CKR_MUTEX_BAD                 - Mutex not correct
 * CKR_HOST_MEMORY               - Memory error
 * CKR_GENERAL_ERROR             - No context available
 * CKR_OK                        - Success
 */
CK_RV libobj_list_destroy(struct libobj_list *list);

#endif /* __LIB_OBJECT_H__ */
