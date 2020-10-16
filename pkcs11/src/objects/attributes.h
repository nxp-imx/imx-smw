/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020 NXP
 */

#ifndef __ATTRIBUTE_H__
#define __ATTRIBUTE_H__

#include "types.h"

enum attr_req { NO_OVERWRITE = 0, MUST, MUST_NOT, OPTIONAL, READ_ONLY };

/**
 * struct template_attr - Definition of an template object attribute
 * @type: Attribute type
 * @val_len: Expected attribute value len (0 if variable)
 * @req: Define if attribute must be define or not
 * @copy_to: Function use to copy attribute into @dest
 */
struct template_attr {
	CK_ATTRIBUTE_TYPE type;
	size_t val_len;
	enum attr_req req;

	CK_DECLARE_FUNCTION_POINTER(CK_RV, copy_to)
	(void *dest, CK_ATTRIBUTE_PTR attr);
};

/**
 * struct rfc2279 - RFC2279 string data type
 * @string: No NULL terminated string of CK_UTF8CHAR
 * @length: Length of string
 */
struct rfc2279 {
	CK_UTF8CHAR_PTR string;
	size_t length;
};

/**
 * struct mech_list - Mechanim type list
 * @mech: Pointer to an array of mechanism
 * @number: Number of mechanism
 */
struct mech_list {
	CK_MECHANISM_TYPE_PTR mech;
	size_t number;
};

/**
 * attr_to_class() - Copy attribute to CK_OBJECT_CLASS
 * @dest: destination value
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
 * @dest: destination value
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
 * attr_to_bool() - Copy attribute to boolean
 * @dest: destination value
 * @attr: Attribute to copy into @dest
 *
 * If attribute @value is defined, copies the attribute of
 * type CK_BBOOL
 *
 * return:
 * CKR_ATTRIBUTE_VALUE_INVALID - Attribute value not valid
 * CKR_OK                      - Success
 */
CK_RV attr_to_bool(void *dest, CK_ATTRIBUTE_PTR attr);

/**
 * attr_to_key() - Copy attribute to CK_KEY_TYPE
 * @dest: destination value
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
 * @dest: destination value
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
 * @dest: destination value
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
 * @dest: destination value
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
 * @dest: destination value
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
 * @dest: destination value
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
 * @dest: destination value
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
 * @dest: destination value
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
 * @dest: Attribute value destination
 * @tattr: Attribute definition
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
attr_get_value(void *dest, const struct template_attr *tattr,
	       struct libattr_list *attrs, enum attr_req req_overwrite);

#endif /* __ATTRIBUTE_H__ */
