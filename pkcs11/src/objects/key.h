/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2021 NXP
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
 * If key attributes are corrects, create a new key object.
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
 * CKR_OK                        - Success
 */
CK_RV key_create(CK_SESSION_HANDLE hsession, struct libobj_obj *obj,
		 struct libattr_list *attrs);

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
 * If key attributes are corrects, create a secret key object.
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
 * CKR_OK                        - Success
 */
CK_RV key_secret_key_generate(CK_SESSION_HANDLE hsession, CK_MECHANISM_PTR mech,
			      struct libobj_obj *obj,
			      struct libattr_list *attrs);

/*
 * key_get_id() - Get the key ID returned by SMW
 * @id: Byte buffer of the key ID
 * @obj: Key object
 * @prefix_len: Byte length of id prefix
 *
 * Call the specific key get id function that will allocate and return
 * the SMW Key.
 *
 * return:
 * CKR_HOST_MEMORY               - Allocation error
 * CKR_GENERAL_ERROR             - General error defined
 * CKR_FUNCTION_FAILED           - Function failure
 * CKR_OK                        - Success
 */
CK_RV key_get_id(struct libbytes *id, struct libobj_obj *obj,
		 size_t prefix_len);

#endif /* __KEY_H__ */
