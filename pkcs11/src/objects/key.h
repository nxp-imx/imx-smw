/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020 NXP
 */

#ifndef __KEY_H__
#define __KEY_H__

#include "types.h"

/**
 * key_free() - Free a key object
 * @obj: Key object
 * @class: Class of the key object
 */
void key_free(void *obj, CK_OBJECT_CLASS class);

/**
 * key_create() - Create a key object
 * @obj: Key object created
 * @class: Key class object
 * @attrs: List of object attributes
 *
 * If key attributes are corrects, create a new key object.
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
CK_RV key_create(void **obj, CK_OBJECT_CLASS class, struct libattr_list *attrs);

#endif /* __KEY_H__ */
