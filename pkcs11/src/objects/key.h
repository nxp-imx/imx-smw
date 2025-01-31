/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2021, 2024-2025 NXP
 */

#ifndef __KEY_H__
#define __KEY_H__

#include "types.h"

/**
 * key_free() - Free a key object
 * @obj: Key object
 */
void key_free(struct libobj_obj *obj);

/**
 * key_create() - Create a key object
 * @hsession: Session handle
 * @obj: Key object
 * @attrs: List of object attributes
 *
 * If key attributes are correct, create a new key object.
 *
 * return:
 * CKR_CRYPTOKI_NOT_INITIALIZED  - Context not initialized
 * CKR_SESSION_HANDLE_INVALID    - Session Handle invalid
 * CKR_ATTRIBUTE_READ_ONLY       - One attribute is read only
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
CK_RV key_create(CK_SESSION_HANDLE hsession, struct libobj_obj *obj,
		 struct libattr_list *attrs);

/**
 * key_retrieve() - Retrieve a key object
 * @hsession: Session handle
 * @obj: Key object
 * @attrs: List of object attributes
 * @id: Token key ID
 *
 * If key attributes are corrects, retrieve a key object.
 *
 * return:
 * CKR_CRYPTOKI_NOT_INITIALIZED  - Context not initialized
 * CKR_SESSION_HANDLE_INVALID    - Session Handle invalid
 * CKR_ATTRIBUTE_READ_ONLY       - One attribute is read only
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
CK_RV key_retrieve(CK_SESSION_HANDLE hsession, struct libobj_obj *obj,
		   struct libattr_list *attrs, unsigned int id);

/**
 * key_get_attribute() - Get an attribute from a key object
 * @attr: Attribute to get
 * @obj: Key object
 *
 * Get the given attribute @attr from the key's class of @obj,
 * if not present, call the key's subkey get attribute function.
 *
 * return:
 * CKR_ATTRIBUTE_SENSITIVE       - Attribute is sensitive
 * CKR_BUFFER_TOO_SMALL          - Attribute length is too small
 * CKR_ATTRIBUTE_TYPE_INVALID    - Attribute not found
 * CKR_FUNCTION_FAILED           - Object not supported
 * CKR_OK                        - Success
 */
CK_RV key_get_attribute(CK_ATTRIBUTE_PTR attr, const struct libobj_obj *obj);

/**
 * key_modify_attribute() - Modify an attribute of a key object
 * @attr: Attribute to modify
 * @obj: Key object
 *
 * Modify the given attribute @attr of the key's class of @obj,
 * if not present, call the key's subkey modify attribute function.
 *
 * return:
 * CKR_ATTRIBUTE_READ_ONLY       - Attribute is read only
 * CKR_ATTRIBUTE_TYPE_INVALID    - Attribute not found
 * CKR_ATTRIBUTE_VALUE_INVALID   - Attribute value or length not valid
 * CKR_HOST_MEMORY               - Out of memory
 * CKR_FUNCTION_FAILED           - Object not supported
 * CKR_OK                        - Success
 */
CK_RV key_modify_attribute(CK_ATTRIBUTE_PTR attr, struct libobj_obj *obj);

/**
 * key_keypair_generate() - Generate a keypair object
 * @hsession: Session handle
 * @mech: Keypair generation mechanism
 * @pub_key: Public Key object
 * @pub_attrs: List of the public key attributes
 * @priv_key: Private Key object
 * @priv_attrs: List of the private key attributes
 *
 * If public and private key attributes are corrects, create a keypair object.
 *
 * return:
 * CKR_CRYPTOKI_NOT_INITIALIZED  - Context not initialized
 * CKR_SESSION_HANDLE_INVALID    - Session Handle invalid
 * CKR_ATTRIBUTE_READ_ONLY       - One attribute is read only
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
CK_RV key_keypair_generate(CK_SESSION_HANDLE hsession, CK_MECHANISM_PTR mech,
			   struct libobj_obj *pub_key,
			   struct libattr_list *pub_attrs,
			   struct libobj_obj *priv_key,
			   struct libattr_list *priv_attrs);

/**
 * key_secret_key_generate() - Generate a secret key object
 * @hsession: Session handle
 * @mech: Key generation mechanism
 * @obj: Secret Key object
 * @attrs: List of the key attributes
 *
 * If key attributes are correct, create a secret key object.
 *
 * return:
 * CKR_CRYPTOKI_NOT_INITIALIZED  - Context not initialized
 * CKR_SESSION_HANDLE_INVALID    - Session Handle invalid
 * CKR_ATTRIBUTE_READ_ONLY       - One attribute is read only
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
CK_RV key_secret_key_generate(CK_SESSION_HANDLE hsession, CK_MECHANISM_PTR mech,
			      struct libobj_obj *obj,
			      struct libattr_list *attrs);

/**
 * derive_key() - Derive a secret key object
 * @hsession: Session handle
 * @mech: Key Derivation mechanism
 * @base_key: Base key handle
 * @derived_key: Derived key object
 * @attrs: List of the key attributes
 *
 * If key attributes are correct, allocate memory to a derived key object.
 * Key attributes CKA_SENSITIVE, CKA_ALWAYS_SENSITIVE, CKA_EXTRACTABLE, and
 * CKA_NEVER_EXTRACTABLE attributes for the base key affect the values that
 * these attributes can hold for the derived key.
 * This function also checks if the derive mechanism parameters are valid.
 *
 * return:
 * CKR_ATTRIBUTE_VALUE_INVALID    - Attribute value is not valid
 * CKR_HOST_MEMORY                - Memory allocation error
 * CKR_KEY_FUNCTION_NOT_PERMITTED - Function not permitted with key
 * CKR_FUNCTION_NOT_SUPPORTED     - Operation not supported
 * CKR_MECHANISM_PARAM_INVALID    - Mechanism parameter is invalid
 * CKR_OK                         - Success
 * Return values from attr_get_value().
 * Return values from attr_set_value().
 * Return values from key_secret_new().
 */
CK_RV derive_key(CK_SESSION_HANDLE hsession, CK_MECHANISM_PTR mech,
		 CK_OBJECT_HANDLE base_key, struct libobj_obj *derived_key,
		 struct libattr_list *attrs);

/**
 * is_hkdf_extract_set() - Check if HKDF-Extract key derivation mech is set
 * @mech: Key Derivation mechanism
 *
 * Check if only extract section of the HKDF is set.
 *
 * return:
 * True, if extract section of the HKDF is set.
 * False, otherwise
 */
CK_BBOOL is_hkdf_extract_set(CK_MECHANISM_PTR mech);

#endif /* __KEY_H__ */
