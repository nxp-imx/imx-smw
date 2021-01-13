/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2021 NXP
 */

#ifndef __KEY_EC_H__
#define __KEY_EC_H__

#include "types.h"

/**
 * key_ec_public_free() - Free an EC public key
 * @obj: EC public Key object
 */
void key_ec_public_free(struct libobj_obj *obj);

/**
 * key_ec_private_free() - Free an EC private key
 * @obj: EC private Key object
 */
void key_ec_private_free(struct libobj_obj *obj);

/*
 * key_ec_public_create() - Creates an EC public key object
 * @hsession: Session handle
 * @obj: EC Public Key object
 * @attrs: List of object attributes
 *
 * If key attributes are corrects, create a new EC Public key object.
 *
 * return:
 * CKR_CRYPTOKI_NOT_INITIALIZED  - Context not initialized
 * CKR_GENERAL_ERROR             - No slot defined
 * CKR_SESSION_HANDLE_INVALID    - Session Handle invalid
 * CKR_SLOT_ID_INVALID           - Slot ID is not valid
 * CKR_CURVE_NOT_SUPPORTED       - Curve is not supported
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
CK_RV key_ec_public_create(CK_SESSION_HANDLE hsession, struct libobj_obj *obj,
			   struct libattr_list *attrs);

/**
 * key_ec_public_get_attribute() - Get an attribute from the EC public key
 * @attr: Attribute to get
 * @obj: EC public key object
 *
 * Get the given attribute @attr from the EC public key object,
 * if not present, as this is the last function called to get the attribute
 * set the attribute's ulValueLen to CK_UNAVAILABLE_INFORMATION
 *
 * return:
 * CKR_ATTRIBUTE_SENSITIVE       - Attribute is sensitive
 * CKR_BUFFER_TOO_SMALL          - Attribute length is too small
 * CKR_ATTRIBUTE_TYPE_INVALID    - Attribute not found
 * CKR_OK                        - Success
 */
CK_RV key_ec_public_get_attribute(CK_ATTRIBUTE_PTR attr,
				  const struct libobj_obj *obj);

/**
 * key_ec_public_modify_attribute() - Modify an attribute of the EC public key
 * @attr: Attribute to modify
 * @obj: EC public key object
 *
 * Modify the given attribute @attr of the EC public key object,
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
CK_RV key_ec_public_modify_attribute(CK_ATTRIBUTE_PTR attr,
				     struct libobj_obj *obj);

/*
 * key_ec_private_create() - Creates an EC private key object
 * @hsession: Session handle
 * @obj: EC Private Key object
 * @attrs: List of object attributes
 *
 * If key attributes are corrects, create a new EC Private key object.
 *
 * return:
 * CKR_CRYPTOKI_NOT_INITIALIZED  - Context not initialized
 * CKR_GENERAL_ERROR             - No slot defined
 * CKR_SESSION_HANDLE_INVALID    - Session Handle invalid
 * CKR_SLOT_ID_INVALID           - Slot ID is not valid
 * CKR_CURVE_NOT_SUPPORTED       - Curve is not supported
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
CK_RV key_ec_private_create(CK_SESSION_HANDLE hsession, struct libobj_obj *obj,
			    struct libattr_list *attrs);

/**
 * key_ec_private_get_attribute() - Get an attribute from the EC private key
 * @attr: Attribute to get
 * @obj: EC private key object
 * @protect: True if object is sensitive or unextractable
 *
 * Get the given attribute @attr from the EC private key object,
 * if not present, as this is the last function called to get the attribute
 * set the attribute's ulValueLen to CK_UNAVAILABLE_INFORMATION
 *
 * return:
 * CKR_ATTRIBUTE_SENSITIVE       - Attribute is sensitive
 * CKR_BUFFER_TOO_SMALL          - Attribute length is too small
 * CKR_ATTRIBUTE_TYPE_INVALID    - Attribute not found
 * CKR_OK                        - Success
 */
CK_RV key_ec_private_get_attribute(CK_ATTRIBUTE_PTR attr,
				   const struct libobj_obj *obj, bool protect);

/**
 * key_ec_private_modify_attribute() - Modify an attribute of the EC private key
 * @attr: Attribute to modify
 * @obj: EC private key object
 *
 * Modify the given attribute @attr of the EC private key object,
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
CK_RV key_ec_private_modify_attribute(CK_ATTRIBUTE_PTR attr,
				      struct libobj_obj *obj);

/*
 * key_ec_keypair_generate() - Generates an EC keypair object
 * @hsession: Session handle
 * @mech: Keypair generation mechanism
 * @pub_obj: EC Public Key object
 * @pub_attrs: List of Public key object attributes
 * @priv_obj: EC Private Key object
 * @priv_attrs: List of Private key object attributes
 *
 * If key attributes are corrects, create and generate an EC Keypair object.
 *
 * return:
 * CKR_CRYPTOKI_NOT_INITIALIZED  - Context not initialized
 * CKR_SESSION_HANDLE_INVALID    - Session Handle invalid
 * CKR_MECHANISM_INVALID         - Mechanism not supported
 * CKR_SLOT_ID_INVALID           - Slot ID is not valid
 * CKR_CURVE_NOT_SUPPORTED       - Curve is not supported
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
CK_RV key_ec_keypair_generate(CK_SESSION_HANDLE hsession, CK_MECHANISM_PTR mech,
			      struct libobj_obj *pub_obj,
			      struct libattr_list *pub_attrs,
			      struct libobj_obj *priv_obj,
			      struct libattr_list *priv_attrs);

/*
 * key_cipher_get_id() - Get the cipher key ID returned by SMW
 * @id: Byte buffer of the key ID
 * @obj: EC Key object
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
CK_RV key_ec_get_id(struct libbytes *id, struct libobj_obj *obj,
		    size_t prefix_len);

#endif /* __KEY_EC_H__ */
