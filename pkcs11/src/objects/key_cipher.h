/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2021, 2023 NXP
 */

#ifndef __KEY_CIPHER_H__
#define __KEY_CIPHER_H__

#include "types.h"

/**
 * key_cipher_free() - Free a Cipher key
 * @obj: Cipher Key object
 */
void key_cipher_free(struct libobj_obj *obj);

/*
 * key_cipher_create() - Creates a Cipher key object
 * @hsession: Session handle
 * @obj: Cipher Key object
 * @attrs: List of object attributes
 *
 * If key attributes are corrects, create a new Cipher key object.
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
CK_RV key_cipher_create(CK_SESSION_HANDLE hsession, struct libobj_obj *obj,
			struct libattr_list *attrs);

/**
 * key_cipher_get_attribute() - Get an attribute from the Cipher key
 * @attr: Attribute to get
 * @obj: Cipher key object
 * @protect: True if object is sensitive or unextractable
 *
 * Get the given attribute @attr from the Cipher key object,
 * if not present, as this is the last function called to get the attribute
 * set the attribute's ulValueLen to CK_UNAVAILABLE_INFORMATION
 *
 * return:
 * CKR_ATTRIBUTE_SENSITIVE       - Attribute is sensitive
 * CKR_BUFFER_TOO_SMALL          - Attribute length is too small
 * CKR_ATTRIBUTE_TYPE_INVALID    - Attribute not found
 * CKR_OK                        - Success
 */
CK_RV key_cipher_get_attribute(CK_ATTRIBUTE_PTR attr,
			       const struct libobj_obj *obj, bool protect);

/**
 * key_cipher_modify_attribute() - Modify an attribute of the Cipher key
 * @attr: Attribute to modify
 * @obj: Cipher key object
 *
 * Modify the given attribute @attr of the Cipher key object,
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
CK_RV key_cipher_modify_attribute(CK_ATTRIBUTE_PTR attr,
				  struct libobj_obj *obj);

/*
 * key_cipher_generate() - Generates a Cipher object
 * @hsession: Session handle
 * @mech: Key generation mechanism
 * @obj: Cipher Key object
 * @attrs: List of key attributes
 *
 * If key attributes are corrects, create and generate a Cipher key object.
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
CK_RV key_cipher_generate(CK_SESSION_HANDLE hsession, CK_MECHANISM_PTR mech,
			  struct libobj_obj *obj, struct libattr_list *attrs);

/*
 * key_cipher_get_id() - Get the cipher key ID returned by SMW
 * @id: Byte buffer of the key ID
 * @obj: Cipher Key object
 * @prefix_len: Byte length of id prefix
 *
 * Allocates the @id buffer with a length of SMW Key ID added to the
 * given @prefix_len bytes.
 * Then copies in the @id buffer indexed of the @prefix_len the
 * SMW's id.
 *
 * return:
 * CKR_HOST_MEMORY               - Allocation error
 * CKR_GENERAL_ERROR             - General error defined
 * CKR_OK                        - Success
 */
CK_RV key_cipher_get_id(struct libbytes *id, struct libobj_obj *obj,
			size_t prefix_len);

#endif /* __KEY_CIPHER_H__ */
