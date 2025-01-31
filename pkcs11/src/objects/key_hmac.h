/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2024-2025 NXP
 */

#ifndef __KEY_HMAC_H__
#define __KEY_HMAC_H__

#include "types.h"
#include "libobj_types.h"

/**
 * key_hmac_free() - Free a HMAC key
 * @obj: HMAC Key object
 */
void key_hmac_free(struct libobj_obj *obj);

/*
 * key_hmac_create() - Creates a HMAC key object
 * @hsession: Session handle
 * @obj: HMAC Key object
 * @attrs: List of object attributes
 *
 * If key attributes are correct, create a new HMAC key object.
 *
 * return:
 * CKR_CRYPTOKI_NOT_INITIALIZED  - Context not initialized
 * CKR_SESSION_HANDLE_INVALID    - Session Handle invalid
 * CKR_SLOT_ID_INVALID           - Slot ID is not valid
 * CKR_ATTRIBUTE_VALUE_INVALID   - Attribute value is not valid
 * CKR_FUNCTION_FAILED           - Function failure
 * CKR_TEMPLATE_INCOMPLETE       - Attribute template incomplete
 * CKR_TEMPLATE_INCONSISTENT     - One of the attribute is not valid
 * CKR_HOST_MEMORY               - Allocation error
 * CKR_GENERAL_ERROR             - General error defined
 * CKR_DEVICE_MEMORY             - Device memory error
 * CKR_DEVICE_ERROR              - Device failure
 * CKR_OK                        - Success
 */
CK_RV key_hmac_create(CK_SESSION_HANDLE hsession, struct libobj_obj *obj,
		      struct libattr_list *attrs);

/*
 * key_hmac_retrieve() - Retrieve a HMAC key object
 * @hsession: Session handle
 * @obj: HMAC Key object
 * @attrs: List of object attributes
 *
 * If key attributes are corrects, retrieve a HMAC key object.
 *
 * return:
 * CKR_CRYPTOKI_NOT_INITIALIZED  - Context not initialized
 * CKR_SESSION_HANDLE_INVALID    - Session Handle invalid
 * CKR_SLOT_ID_INVALID           - Slot ID is not valid
 * CKR_ATTRIBUTE_VALUE_INVALID   - Attribute value is not valid
 * CKR_FUNCTION_FAILED           - Function failure
 * CKR_TEMPLATE_INCOMPLETE       - Attribute template incomplete
 * CKR_TEMPLATE_INCONSISTENT     - One of the attribute is not valid
 * CKR_HOST_MEMORY               - Allocation error
 * CKR_GENERAL_ERROR             - General error defined
 * CKR_DEVICE_MEMORY             - Device memory error
 * CKR_DEVICE_ERROR              - Device failure
 * CKR_OK                        - Success
 */
CK_RV key_hmac_retrieve(CK_SESSION_HANDLE hsession, struct libobj_obj *obj,
			struct libattr_list *attrs);

/**
 * key_hmac_get_attribute() - Get an attribute from the HMAC key
 * @attr: Attribute to get
 * @obj: HMAC key object
 * @protect: True if object is sensitive or unextractable
 *
 * Get the given attribute @attr from the HMAC key object,
 * if not present, as this is the last function called to get the attribute
 * set the attribute's ulValueLen to CK_UNAVAILABLE_INFORMATION
 *
 * return:
 * CKR_ATTRIBUTE_SENSITIVE       - Attribute is sensitive
 * CKR_BUFFER_TOO_SMALL          - Attribute length is too small
 * CKR_ATTRIBUTE_TYPE_INVALID    - Attribute not found
 * CKR_OK                        - Success
 */
CK_RV key_hmac_get_attribute(CK_ATTRIBUTE_PTR attr,
			     const struct libobj_obj *obj, bool protect);

/**
 * key_hmac_modify_attribute() - Modify an attribute of the HMAC key
 * @attr: Attribute to modify
 * @obj: HMAC key object
 *
 * Modify the given attribute @attr of the HMAC key object,
 * if not present, as this is the last function called returns the
 * CKR_ATTRIBUTE_TYPE_INVALID error.
 *
 * return:
 * CKR_ATTRIBUTE_READ_ONLY       - Attribute is read only
 * CKR_ATTRIBUTE_TYPE_INVALID    - Attribute not found
 * CKR_ATTRIBUTE_VALUE_INVALID   - Attribute value or length not valid
 * CKR_HOST_MEMORY               - Out of memory
 * CKR_OK                        - Success
 */
CK_RV key_hmac_modify_attribute(CK_ATTRIBUTE_PTR attr, struct libobj_obj *obj);

/*
 * key_hmac_generate() - Generates a HMAC object
 * @hsession: Session handle
 * @mech: Key generation mechanism
 * @obj: HMAC Key object
 * @attrs: List of key attributes
 *
 * If key attributes are correct, create and generate a HMAC key object.
 *
 * return:
 * CKR_CRYPTOKI_NOT_INITIALIZED  - Context not initialized
 * CKR_SESSION_HANDLE_INVALID    - Session Handle invalid
 * CKR_MECHANISM_INVALID         - Mechanism not supported
 * CKR_SLOT_ID_INVALID           - Slot ID is not valid
 * CKR_ATTRIBUTE_VALUE_INVALID   - Attribute value is not valid
 * CKR_FUNCTION_FAILED           - Function failure
 * CKR_TEMPLATE_INCOMPLETE       - Attribute template incomplete
 * CKR_TEMPLATE_INCONSISTENT     - One of the attribute is not valid
 * CKR_HOST_MEMORY               - Allocation error
 * CKR_GENERAL_ERROR             - General error defined
 * CKR_DEVICE_MEMORY             - Device memory error
 * CKR_DEVICE_ERROR              - Device failure
 * CKR_FUNCTION_CANCELED         - Application callback canceled function
 * CKR_OK                        - Success
 */
CK_RV key_hmac_generate(CK_SESSION_HANDLE hsession, CK_MECHANISM_PTR mech,
			struct libobj_obj *obj, struct libattr_list *attrs);

/*
 * key_hmac_derive() - Derive a HMAC object
 * @hsession: Session handle
 * @mech: Key derivation mechanism
 * @derive_params: Pointer to key derivation parameters structure
 * @attrs: List of key attributes
 *
 * If key attributes are correct, create and derive a HMAC key object.
 *
 * return:
 * CKR_CRYPTOKI_NOT_INITIALIZED  - Context not initialized
 * CKR_SESSION_HANDLE_INVALID    - Session Handle invalid
 * CKR_MECHANISM_INVALID         - Mechanism not supported
 * CKR_SLOT_ID_INVALID           - Slot ID is not valid
 * CKR_ATTRIBUTE_VALUE_INVALID   - Attribute value is not valid
 * CKR_FUNCTION_FAILED           - Function failure
 * CKR_TEMPLATE_INCOMPLETE       - Attribute template incomplete
 * CKR_TEMPLATE_INCONSISTENT     - One of the attribute is not valid
 * CKR_HOST_MEMORY               - Allocation error
 * CKR_GENERAL_ERROR             - General error defined
 * CKR_DEVICE_MEMORY             - Device memory error
 * CKR_DEVICE_ERROR              - Device failure
 * CKR_FUNCTION_CANCELED         - Application callback canceled function
 * CKR_OK                        - Success
 */
CK_RV key_hmac_derive(CK_SESSION_HANDLE hsession, CK_MECHANISM_PTR mech,
		      struct libobj_key_derive_params *derive_params,
		      struct libattr_list *attrs);

#endif /* __KEY_HMAC_H__ */
