/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2025 NXP
 */

#ifndef __CERT_H__
#define __CERT_H__

#include "types.h"

/**
 * cert_free() - Free a certificate object
 * @obj: Certificate object
 */
void cert_free(struct libobj_obj *obj);

/**
 * cert_create() - Create a certificate object
 * @hsession: Session handle
 * @obj: Certificate object
 * @attrs: List of object attributes
 *
 * If certificate attributes are corrects, create a new certificate object.
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
CK_RV cert_create(CK_SESSION_HANDLE hsession, struct libobj_obj *obj,
		  struct libattr_list *attrs);

/**
 * cert_get_attribute() - Get an attribute from a certificate object
 * @attr: Attribute to get
 * @obj: Certificate object
 *
 * Get the given attribute @attr from the certificate's class of @obj.
 *
 * return:
 * CKR_ATTRIBUTE_SENSITIVE       - Attribute is sensitive
 * CKR_BUFFER_TOO_SMALL          - Attribute length is too small
 * CKR_ATTRIBUTE_TYPE_INVALID    - Attribute not found
 * CKR_OK                        - Success
 */
CK_RV cert_get_attribute(CK_ATTRIBUTE_PTR attr, const struct libobj_obj *obj);

/**
 * cert_modify_attribute() - Modify an attribute of a certificate object
 * @attr: Attribute to modify
 * @obj: Certificate object
 *
 * Modify the given attribute @attr of the certificate's class of @obj.
 *
 * return:
 * CKR_ATTRIBUTE_READ_ONLY       - Attribute is read only
 * CKR_ATTRIBUTE_TYPE_INVALID    - Attribute not found
 * CKR_ATTRIBUTE_VALUE_INVALID   - Attribute value or length not valid
 * CKR_HOST_MEMORY               - Out of memory
 * CKR_FUNCTION_FAILED           - Object not supported
 * CKR_OK                        - Success
 */
CK_RV cert_modify_attribute(CK_ATTRIBUTE_PTR attr, struct libobj_obj *obj);

/**
 * cert_get_size() - Return certificate size
 * @obj: Certificate object
 * @obj_size: Size of object
 *
 * Based on the certificate type, fetch the certificate object and
 * return the certificate size.
 *
 * return:
 * CKR_GENERAL_ERROR             - Sub certificate object is NULL
 * CKR_FUNCTION_FAILED           - Certificate type not supported
 * CKR_OK                        - Success
 */
CK_RV cert_get_size(const struct libobj_obj *obj, CK_ULONG_PTR obj_size);

#endif /* __CERT_H__ */
