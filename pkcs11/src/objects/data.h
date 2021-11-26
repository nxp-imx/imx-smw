/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2022 NXP
 */

#ifndef __DATA_H__
#define __DATA_H__

#include "types.h"

/**
 * data_free() - Free a data object
 * @obj: Data object
 */
void data_free(struct libobj_obj *obj);

/**
 * data_create() - Create a data object
 * @hsession: Session handle
 * @obj: Data object
 * @attrs: List of object attributes
 *
 * If data attributes are corrects, create a new data object.
 *
 * return:
 * CKR_ATTRIBUTE_READ_ONLY       - One attribute is read only
 * CKR_ATTRIBUTE_VALUE_INVALID   - Attribute value is not valid
 * CKR_TEMPLATE_INCOMPLETE       - Attribute template incomplete
 * CKR_TEMPLATE_INCONSISTENT     - One of the attribute is not valid
 * CKR_HOST_MEMORY               - Allocation error
 * CKR_GENERAL_ERROR             - General error defined
 * CKR_OK                        - Success
 */
CK_RV data_create(CK_SESSION_HANDLE hsession, struct libobj_obj *obj,
		  struct libattr_list *attrs);

/**
 * data_get_attribute() - Get an attribute from a data object
 * @attr: Attribute to get
 * @obj: Data object
 *
 * Get the given attribute @attr from the data's class of @obj.
 *
 * return:
 * CKR_ATTRIBUTE_SENSITIVE       - Attribute is sensitive
 * CKR_BUFFER_TOO_SMALL          - Attribute length is too small
 * CKR_ATTRIBUTE_TYPE_INVALID    - Attribute not found
 * CKR_OK                        - Success
 */
CK_RV data_get_attribute(CK_ATTRIBUTE_PTR attr, const struct libobj_obj *obj);

/**
 * data_modify_attribute() - Modify an attribute of a data object
 * @attr: Attribute to modify
 * @obj: Data object
 *
 * Modify the given attribute @attr of the data's class of @obj.
 *
 * return:
 * CKR_ATTRIBUTE_READ_ONLY       - Attribute is read only
 * CKR_ATTRIBUTE_TYPE_INVALID    - Attribute not found
 * CKR_ATTRIBUTE_VALUE_INVALID   - Attribute value or length not valid
 * CKR_HOST_MEMORY               - Out of memory
 * CKR_FUNCTION_FAILED           - Object not supported
 * CKR_OK                        - Success
 */
CK_RV data_modify_attribute(CK_ATTRIBUTE_PTR attr, struct libobj_obj *obj);

#endif /* __DATA_H__ */
