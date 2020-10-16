/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020 NXP
 */

#ifndef __KEY_CIPHER_H__
#define __KEY_CIPHER_H__

#include "types.h"

/**
 * key_cipher_free() - Free a Cipher key
 * @obj: Cipher Key object
 */
void key_cipher_free(void *obj);

/*
 * key_cipher_create() - Creates a Cipher key object
 * @obj: Cipher Key
 * @attrs: List of object attributes
 *
 * If key attributes are corrects, create a new Cipher key object.
 *
 * return:
 * CKR_ATTRIBUTE_VALUE_INVALID   - Attribute value is not valid
 * CKR_FUNCTION_FAILED           - Function failure
 * CKR_TEMPLATE_INCOMPLETE       - Attribute template incomplete
 * CKR_TEMPLATE_INCONSISTENT     - One of the attribute is not valid
 * CKR_HOST_MEMORY               - Allocation error
 * CKR_GENERAL_ERROR             - General error defined
 * CKR_OK                        - Success
 */
CK_RV key_cipher_create(void **obj, struct libattr_list *attrs);

/*
 * key_cipher_generate() - Generates a Cipher object
 * @hsession: Session handle
 * @mech: Key generation mechanism
 * @key_type: Key type
 * @obj: Cipher Key object
 * @attrs: List of key attributes
 *
 * If key attributes are corrects, create and generate a Cipher key object.
 *
 * return:
 * CKR_ATTRIBUTE_VALUE_INVALID   - Attribute value is not valid
 * CKR_FUNCTION_FAILED           - Function failure
 * CKR_TEMPLATE_INCOMPLETE       - Attribute template incomplete
 * CKR_TEMPLATE_INCONSISTENT     - One of the attribute is not valid
 * CKR_HOST_MEMORY               - Allocation error
 * CKR_GENERAL_ERROR             - General error defined
 * CKR_OK                        - Success
 */
CK_RV key_cipher_generate(CK_SESSION_HANDLE hsession, CK_MECHANISM_PTR mech,
			  CK_KEY_TYPE key_type, void **obj,
			  struct libattr_list *attrs);

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
CK_RV key_cipher_get_id(struct libbytes *id, void *key, size_t prefix_len);

#endif /* __KEY_CIPHER_H__ */
