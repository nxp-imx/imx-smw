/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2021 NXP
 */

#ifndef __ATTRIBUTE_H__
#define __ATTRIBUTE_H__

#include "types.h"

enum attr_req { NO_OVERWRITE = 0, MUST, MUST_NOT, OPTIONAL, READ_ONLY };

#define _TATTR(_struct, _field, _type, _len, _req, _conv)                      \
	{                                                                      \
		.of_field = offsetof(struct libobj_##_struct, _field),         \
		.type = CKA_##_type, .val_len = _len, .req = _req,             \
		.attr_to = attr_to_##_conv,                                    \
	}

#define TATTR(_struct, _field, _type, _len, _req, _conv)                       \
	_TATTR(_struct, _field, _type, _len, _req, _conv)

/**
 * struct template_attr - Definition of an template object attribute
 * @type: Attribute type
 * @val_len: Expected attribute value len (0 if variable)
 * @req: Define if attribute must be define or not
 * @of_field: Field offset in the object's structure
 * @attr_to: Function use to copy attribute into @dest
 */
struct template_attr {
	CK_ATTRIBUTE_TYPE type;
	size_t val_len;
	enum attr_req req;
	size_t of_field;

	CK_DECLARE_FUNCTION_POINTER(CK_RV, attr_to)
	(void *dest, CK_ATTRIBUTE_PTR attr);
};

/**
 * attr_to_class() - Copy attribute to CK_OBJECT_CLASS
 * @dest: Destination value
 * @attr: Attribute to copy into @dest
 *
 * If attribute @value is defined, copies the attribute of
 * type CK_OBJECT_CLASS
 *
 * return:
 * CKR_ATTRIBUTE_VALUE_INVALID - Attribute value not valid
 * CKR_OK                      - Success
 */
CK_RV attr_to_class(void *dest, CK_ATTRIBUTE_PTR attr);

/**
 * attr_to_rfc2279() - Allocate and copy attribute to rfc2279
 * @dest: Destination value
 * @attr: Attribute to copy into @dest
 *
 * If attribute @value is defined, allocates and copies the attribute of
 * type rfc2279 into the @dest.
 *
 * return:
 * CKR_ATTRIBUTE_VALUE_INVALID - Attribute value or length not valid
 * CKR_HOST_MEMORY             - Out of memory
 * CKR_OK                      - Success
 */
CK_RV attr_to_rfc2279(void *dest, CK_ATTRIBUTE_PTR attr);

/**
 * attr_to_boolean() - Copy attribute to boolean
 * @dest: Destination value
 * @attr: Attribute to copy into @dest
 *
 * If attribute @value is defined, copies the attribute of
 * type CK_BBOOL
 *
 * return:
 * CKR_ATTRIBUTE_VALUE_INVALID - Attribute value not valid
 * CKR_OK                      - Success
 */
CK_RV attr_to_boolean(void *dest, CK_ATTRIBUTE_PTR attr);

/**
 * attr_to_key() - Copy attribute to CK_KEY_TYPE
 * @dest: Destination value
 * @attr: Attribute to copy into @dest
 *
 * If attribute @value is defined, copies the attribute of
 * type CK_KEY_TYPE
 *
 * return:
 * CKR_ATTRIBUTE_VALUE_INVALID - Attribute value not valid
 * CKR_OK                      - Success
 */
CK_RV attr_to_key(void *dest, CK_ATTRIBUTE_PTR attr);

/**
 * attr_to_byte_array() - Copy attribute to CK_BYTE array
 * @dest: Destination value
 * @attr: Attribute to copy into @dest
 *
 * If attribute @value is defined, allocates and copies the
 * attribute of type CK_BYTE_PTR
 *
 * return:
 * CKR_ATTRIBUTE_VALUE_INVALID - Attribute value or length not valid
 * CKR_HOST_MEMORY             - Out of memory
 * CKR_OK                      - Success
 */
CK_RV attr_to_byte_array(void *dest, CK_ATTRIBUTE_PTR attr);

/**
 * attr_to_date() - Copy attribute to CK_DATE
 * @dest: Destination value
 * @attr: Attribute to copy into @dest
 *
 * If attribute @value is defined, copies the attribute of
 * type CK_DATE
 *
 * return:
 * CKR_ATTRIBUTE_VALUE_INVALID - Attribute value not valid
 * CKR_OK                      - Success
 */
CK_RV attr_to_date(void *dest, CK_ATTRIBUTE_PTR attr);

/**
 * attr_to_mech() - Copy attribute to CK_MECHANISM_TYPE
 * @dest: Destination value
 * @attr: Attribute to copy into @dest
 *
 * If attribute @value is defined, copies the attribute of
 * type CK_MECHANISM_TYPE
 *
 * return:
 * CKR_ATTRIBUTE_VALUE_INVALID - Attribute value not valid
 * CKR_OK                      - Success
 */
CK_RV attr_to_mech(void *dest, CK_ATTRIBUTE_PTR attr);

/**
 * attr_to_mech_list() - Copy attribute to mechanism list
 * @dest: Destination value
 * @attr: Attribute to copy into @dest
 *
 * If attribute @value is defined, copies the attribute of
 * type CK_MECHANISM_TYPE_PTR
 *
 * return:
 * CKR_ATTRIBUTE_VALUE_INVALID - Attribute value or length not valid
 * CKR_HOST_MEMORY             - Out of memory
 * CKR_OK                      - Success
 */
CK_RV attr_to_mech_list(void *dest, CK_ATTRIBUTE_PTR attr);

/**
 * attr_to_attr_list() - Copy attribute to attribute list
 * @dest: Destination value
 * @attr: Attribute to copy into @dest
 *
 * If attribute @value is defined, copies the attribute of
 * type CK_ATTRIBUTE_PTR
 *
 * return:
 * CKR_ATTRIBUTE_VALUE_INVALID - Attribute value or length not valid
 * CKR_HOST_MEMORY             - Out of memory
 * CKR_OK                      - Success
 */
CK_RV attr_to_attr_list(void *dest, CK_ATTRIBUTE_PTR attr);

/**
 * attr_to_bignumber() - Copy attribute to big number
 * @dest: Destination value
 * @attr: Attribute to copy into @dest
 *
 * If attribute @value is defined, copies the attribute of
 * type CK_BYTE_PTR
 *
 * return:
 * CKR_ATTRIBUTE_VALUE_INVALID - Attribute value or length not valid
 * CKR_HOST_MEMORY             - Out of memory
 * CKR_OK                      - Success
 */
CK_RV attr_to_bignumber(void *dest, CK_ATTRIBUTE_PTR attr);

/**
 * attr_to_ulong() - Copy attribute to unsigned long
 * @dest: Destination value
 * @attr: Attribute to copy into @dest
 *
 * If attribute @value is defined, copies the attribute of
 * type CK_ULONG
 *
 * return:
 * CKR_ATTRIBUTE_VALUE_INVALID - Attribute value not valid
 * CKR_OK                      - Success
 */
CK_RV attr_to_ulong(void *dest, CK_ATTRIBUTE_PTR attr);

/**
 * get_attr_value() - Find an attribute type and get its value
 * @obj: Object containing the field to set
 * @tattr: Object attribute definition
 * @attrs: Attributes list
 * @req_overwrite: Overwrite the attribute requirement (!= NO_OVERWRITE)
 *
 * If the attribute is present once, verify the attribute length and
 * the attribute requirement.
 * Then if attribute is correct, copies its value in the @dest by calling
 * the @copy_to function set in the @tattr definition.
 *
 * return:
 * CKR_ATTRIBUTE_READ_ONLY     - Attribute is read only
 * CKR_TEMPLATE_INCOMPLETE     - Attribute type not found
 * CKR_TEMPLATE_INCONSISTENT   - Attribute type must not be defined
 * CKR_ATTRIBUTE_VALUE_INVALID - Attribute value or length not valid
 * CKR_OK                      - Success
 */
CK_RV
attr_get_value(void *obj, const struct template_attr *tattr,
	       struct libattr_list *attrs, enum attr_req req_overwrite);

#endif /* __ATTRIBUTE_H__ */
