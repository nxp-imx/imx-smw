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
 * key_ec_public_create() - Creates an EC public key
 * @obj: EC Public Key created
 * @attrs: List of object attributes
 *
 * If key attributes are corrects, create a new EC Public key.
 *
 * return:
 * CKR_CURVE_NOT_SUPPORTED       - Curve is not supported
 * CKR_ATTIBUTE_VALUE_INVALID    - Attribute value is not valid
 * CKR_FUNCTION_FAILED           - Function failure
 * CKR_TEMPLATE_INCOMPLETE       - Attribute template incomplete
 * CKR_TEMPLATE_INCONSISTENT     - One of the attribute is not valid
 * CKR_HOST_MEMORY               - Allocation error
 * CKR_GENERAL_ERROR             - General error defined
 * CKR_OK                        - Success
 */
CK_RV key_ec_public_create(void **obj, struct libattr_list *attrs);

/*
 * key_ec_private_create() - Creates an EC private key
 * @obj: EC Private Key created
 * @attrs: List of object attributes
 *
 * If key attributes are corrects, create a new EC Private key.
 *
 * return:
 * CKR_CURVE_NOT_SUPPORTED       - Curve is not supported
 * CKR_ATTIBUTE_VALUE_INVALID    - Attribute value is not valid
 * CKR_FUNCTION_FAILED           - Function failure
 * CKR_TEMPLATE_INCOMPLETE       - Attribute template incomplete
 * CKR_TEMPLATE_INCONSISTENT     - One of the attribute is not valid
 * CKR_HOST_MEMORY               - Allocation error
 * CKR_GENERAL_ERROR             - General error defined
 * CKR_OK                        - Success
 */
CK_RV key_ec_private_create(void **obj, struct libattr_list *attrs);

#endif /* __KEY_EC_H__ */
