/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020 NXP
 */

#ifndef __KEY_EC_H__
#define __KEY_EC_H__

#include "types.h"

/**
 * key_ec_public_free() - Free an EC public key
 * @obj: EC public Key object
 */
void key_ec_public_free(void *obj);

/**
 * key_ec_private_free() - Free an EC private key
 * @obj: EC private Key object
 */
void key_ec_private_free(void *obj);

/*
 * key_ec_public_create() - Creates an EC public key object
 * @obj: EC Public Key
 * @attrs: List of object attributes
 *
 * If key attributes are corrects, create a new EC Public key object.
 *
 * return:
 * CKR_CURVE_NOT_SUPPORTED       - Curve is not supported
 * CKR_ATTRIBUTE_VALUE_INVALID   - Attribute value is not valid
 * CKR_FUNCTION_FAILED           - Function failure
 * CKR_TEMPLATE_INCOMPLETE       - Attribute template incomplete
 * CKR_TEMPLATE_INCONSISTENT     - One of the attribute is not valid
 * CKR_HOST_MEMORY               - Allocation error
 * CKR_GENERAL_ERROR             - General error defined
 * CKR_OK                        - Success
 */
CK_RV key_ec_public_create(void **obj, struct libattr_list *attrs);

/*
 * key_ec_private_create() - Creates an EC private key object
 * @obj: EC Private Key
 * @attrs: List of object attributes
 *
 * If key attributes are corrects, create a new EC Private key object.
 *
 * return:
 * CKR_CURVE_NOT_SUPPORTED       - Curve is not supported
 * CKR_ATTRIBUTE_VALUE_INVALID   - Attribute value is not valid
 * CKR_FUNCTION_FAILED           - Function failure
 * CKR_TEMPLATE_INCOMPLETE       - Attribute template incomplete
 * CKR_TEMPLATE_INCONSISTENT     - One of the attribute is not valid
 * CKR_HOST_MEMORY               - Allocation error
 * CKR_GENERAL_ERROR             - General error defined
 * CKR_OK                        - Success
 */
CK_RV key_ec_private_create(void **obj, struct libattr_list *attrs);

/*
 * key_ec_keypair_generate() - Generates an EC keypair object
 * @hsession: Session handle
 * @mech: Keypair generation mechanism
 * @pub_obj: EC Public Key
 * @pub_attrs: List of Public key object attributes
 * @priv_obj: EC Private Key
 * @priv_attrs: List of Private key object attributes
 *
 * If key attributes are corrects, create and generate an EC Keypair object.
 *
 * return:
 * CKR_CURVE_NOT_SUPPORTED       - Curve is not supported
 * CKR_ATTRIBUTE_VALUE_INVALID   - Attribute value is not valid
 * CKR_FUNCTION_FAILED           - Function failure
 * CKR_TEMPLATE_INCOMPLETE       - Attribute template incomplete
 * CKR_TEMPLATE_INCONSISTENT     - One of the attribute is not valid
 * CKR_HOST_MEMORY               - Allocation error
 * CKR_GENERAL_ERROR             - General error defined
 * CKR_OK                        - Success
 */
CK_RV key_ec_keypair_generate(CK_SESSION_HANDLE hsession, CK_MECHANISM_PTR mech,
			      void **pub_obj, struct libattr_list *pub_attrs,
			      void **priv_obj, struct libattr_list *priv_attrs);

/*
 * key_cipher_get_id() - Get the cipher key ID returned by SMW
 * @id: Byte buffer of the key ID
 * @key: Cipher Key object
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
CK_RV key_ec_get_id(struct libbytes *id, void *key, size_t prefix_len);

#endif /* __KEY_EC_H__ */
