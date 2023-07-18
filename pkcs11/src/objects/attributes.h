/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2021, 2023 NXP
 */

#ifndef __ATTRIBUTE_H__
#define __ATTRIBUTE_H__

#include "types.h"

enum attr_req { NO_OVERWRITE = 0, MUST, MUST_NOT, OPTIONAL, READ_ONLY };

#define _TATTR(_struct, _field, _type, _len, _req, _protect, _conv, _modify)   \
	{                                                                      \
		.of_field = offsetof(struct libobj_##_struct, _field),         \
		.type = CKA_##_type, .val_len = _len, .req = _req,             \
		.protect = _protect, .attr_to = attr_to_##_conv,               \
		.to_attr = _conv##_to_attr, .modify = _modify                  \
	}

/*
 * Define an attribute:
 *   - non protected
 *   - non modifiable
 */
#define TATTR(_struct, _field, _type, _len, _req, _conv)                       \
	_TATTR(_struct, _field, _type, _len, _req, false, _conv, NULL)

/*
 * Define an attribute:
 *   - protected
 *   - non modifiable
 */
#define TATTR_P(_struct, _field, _type, _len, _req, _conv)                     \
	_TATTR(_struct, _field, _type, _len, _req, true, _conv, NULL)

/*
 * Define an attribute:
 *   - non protected
 *   - modifiable, using a standard modification operation
 */
#define TATTR_M(_struct, _field, _type, _len, _req, _conv)                     \
	_TATTR(_struct, _field, _type, _len, _req, false, _conv, modify_##_conv)

/*
 * Define an attribute:
 *   - non protected
 *   - modifiable, using a specification modification operation
 */
#define TATTR_MS(_struct, _field, _type, _len, _req, _conv, _cond_modif)       \
	_TATTR(_struct, _field, _type, _len, _req, false, _conv,               \
	       modify_##_cond_modif)

/**
 * struct template_attr - Definition of an template object attribute
 * @type: Attribute type
 * @val_len: Expected attribute value len (0 if variable)
 * @req: Define if attribute must be define or not
 * @of_field: Field offset in the object's structure
 * @protect: Attribute protected by object sensitive or extractable setting
 * @attr_to: Function use to copy attribute into @dest
 * @to_attr: Function use to copy @src to attribute
 * @modify: Function use to modify an attribute of @dest
 */
struct template_attr {
	CK_ATTRIBUTE_TYPE type;
	size_t val_len;
	enum attr_req req;
	size_t of_field;
	bool protect;

	CK_DECLARE_FUNCTION_POINTER(CK_RV, attr_to)
	(void *dest, CK_ATTRIBUTE_PTR attr);
	CK_DECLARE_FUNCTION_POINTER(CK_RV, to_attr)
	(CK_ATTRIBUTE_PTR attr, const void *src);
	CK_DECLARE_FUNCTION_POINTER(CK_RV, modify)
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
 * class_to_attr() - Copy a CK_OBJECT_CLASS to attribute
 * @attr: Attribute destination
 * @src: Source value
 *
 * If attribute @value is defined, copies the @src into
 * attribute of type CK_OBJECT_CLASS
 *
 * return:
 * CKR_BUFFER_TOO_SMALL        - Attribute length too small
 * CKR_OK                      - Success
 */
CK_RV class_to_attr(CK_ATTRIBUTE_PTR attr, const void *src);

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
 * rfc2279_to_attr() - Copy a rfc2279 to attribute
 * @attr: Attribute destination
 * @src: Source value
 *
 * If attribute @value is defined, copies the @src into
 * attribute of type rfc2279
 *
 * return:
 * CKR_BUFFER_TOO_SMALL        - Attribute length too small
 * CKR_OK                      - Success
 */
CK_RV rfc2279_to_attr(CK_ATTRIBUTE_PTR attr, const void *src);

/**
 * modify_rfc2279() - Modify a rfc2279 attribute
 * @dest: Destination value
 * @attr: New attribute
 *
 * If new attribute is correct, replace the @dest attribute value
 * with the new ones.
 *
 * return:
 * CKR_ATTRIBUTE_VALUE_INVALID - Attribute value or length not valid
 * CKR_HOST_MEMORY             - Out of memory
 * CKR_OK                      - Success
 */
CK_RV modify_rfc2279(void *dest, CK_ATTRIBUTE_PTR attr);

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
 * boolean_to_attr() - Copy a boolean to attribute
 * @attr: Attribute destination
 * @src: Source value
 *
 * If attribute @value is defined, copies the @src into
 * attribute of type CK_BBOOL
 *
 * return:
 * CKR_BUFFER_TOO_SMALL        - Attribute length too small
 * CKR_OK                      - Success
 */
CK_RV boolean_to_attr(CK_ATTRIBUTE_PTR attr, const void *src);

/**
 * modify_boolean() - Modify a boolean attribute
 * @dest: Destination value
 * @attr: New attribute
 *
 * If new attribute is correct, replace the @dest attribute value
 * with the new ones.
 *
 * return:
 * CKR_ATTRIBUTE_VALUE_INVALID - Attribute value not valid
 * CKR_OK                      - Success
 */
CK_RV modify_boolean(void *dest, CK_ATTRIBUTE_PTR attr);

/**
 * modify_true_only() - Modify a boolean attribute to true only
 * @dest: Destination value
 * @attr: New attribute
 *
 * If new attribute's value is true, replace the @dest attribute value
 * with the new ones.
 * Else if new attribute's value is false and @dest attribute value is
 * true, @dest is a read only attribute.
 *
 * return:
 * CKR_ATTRIBUTE_READ_ONLY     - Attribute is read only
 * CKR_ATTRIBUTE_VALUE_INVALID - Attribute value not valid
 * CKR_OK                      - Success
 */
CK_RV modify_true_only(void *dest, CK_ATTRIBUTE_PTR attr);

/**
 * modify_false_only() - Modify a boolean attribute to false only
 * @dest: Destination value
 * @attr: New attribute
 *
 * If new attribute's value is false, replace the @dest attribute value
 * with the new ones.
 * Else if new attribute's value is true and @dest attribute value is
 * false, @dest is a read only attribute.
 *
 * return:
 * CKR_ATTRIBUTE_READ_ONLY     - Attribute is read only
 * CKR_ATTRIBUTE_VALUE_INVALID - Attribute value not valid
 * CKR_OK                      - Success
 */
CK_RV modify_false_only(void *dest, CK_ATTRIBUTE_PTR attr);

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
 * key_to_attr() - Copy a CK_KEY_TYPE to attribute
 * @attr: Attribute destination
 * @src: Source value
 *
 * If attribute @value is defined, copies the @src into
 * attribute of type CK_KEY_TYPE
 *
 * return:
 * CKR_BUFFER_TOO_SMALL        - Attribute length too small
 * CKR_OK                      - Success
 */
CK_RV key_to_attr(CK_ATTRIBUTE_PTR attr, const void *src);

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
 * byte_array_to_attr() - Copy a CK_BYTE array to attribute
 * @attr: Attribute destination
 * @src: Source value
 *
 * If attribute @value is defined, copies the @src into
 * attribute of type CK_BYTE_PTR
 *
 * return:
 * CKR_BUFFER_TOO_SMALL        - Attribute length too small
 * CKR_OK                      - Success
 */
CK_RV byte_array_to_attr(CK_ATTRIBUTE_PTR attr, const void *src);

/**
 * modify_byte_array() - Modify a CK_BYTE array attribute
 * @dest: Destination value
 * @attr: New attribute
 *
 * If new attribute is correct, replace the àdest attribute value
 * with the new ones.
 *
 * return:
 * CKR_ATTRIBUTE_VALUE_INVALID - Attribute value or length not valid
 * CKR_HOST_MEMORY             - Out of memory
 * CKR_OK                      - Success
 */
CK_RV modify_byte_array(void *dest, CK_ATTRIBUTE_PTR attr);

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
 * date_to_attr() - Copy a CK_DATE to attribute
 * @attr: Attribute destination
 * @src: Source value
 *
 * If attribute @value is defined, copies the @src into
 * attribute of type CK_DATE
 *
 * return:
 * CKR_BUFFER_TOO_SMALL        - Attribute length too small
 * CKR_OK                      - Success
 */
CK_RV date_to_attr(CK_ATTRIBUTE_PTR attr, const void *src);

/**
 * modify_date() - Modify a CK_DATE attribute
 * @dest: Destination value
 * @attr: New attribute
 *
 * If new attribute is correct, replace the @dest attribute value
 * with the new ones.
 *
 * return:
 * CKR_ATTRIBUTE_VALUE_INVALID - Attribute value not valid
 * CKR_OK                      - Success
 */
CK_RV modify_date(void *dest, CK_ATTRIBUTE_PTR attr);

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
 * mech_to_attr() - Copy a CK_MECHANISM_TYPE to attribute
 * @attr: Attribute destination
 * @src: Source value
 *
 * If attribute @value is defined, copies the @src into
 * attribute of type CK_MECHANISM_TYPE
 *
 * return:
 * CKR_BUFFER_TOO_SMALL        - Attribute length too small
 * CKR_OK                      - Success
 */
CK_RV mech_to_attr(CK_ATTRIBUTE_PTR attr, const void *src);

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
 * mech_list_to_attr() - Copy a mechanims list to attribute
 * @attr: Attribute destination
 * @src: Source value
 *
 * If attribute @value is defined, copies the @src into
 * attribute of type CK_MECHANISM_TYPE_PTR
 *
 * return:
 * CKR_BUFFER_TOO_SMALL        - Attribute length too small
 * CKR_ARGUMENTS_BAD           - Bad arguments
 * CKR_OK                      - Success
 */
CK_RV mech_list_to_attr(CK_ATTRIBUTE_PTR attr, const void *src);

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
 * attr_list_to_attr() - Copy an attribute list to attribute
 * @attr: Attribute destination
 * @src: Source value
 *
 * If attribute @value is defined, copies the @src into
 * attribute of type CK_ATTRIBUTE_PTR
 *
 * return:
 * CKR_FUNCTION_FAILED         - Function failure
 * CKR_BUFFER_TOO_SMALL        - Attribute length too small
 * CKR_OK                      - Success
 */
CK_RV attr_list_to_attr(CK_ATTRIBUTE_PTR attr, const void *src);

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
 * bignumber_to_attr() - Copy a big number to attribute
 * @attr: Attribute destination
 * @src: Source value
 *
 * If attribute @value is defined, copies the @src into
 * attribute of type CK_BYTE_PTR
 *
 * return:
 * CKR_BUFFER_TOO_SMALL        - Attribute length too small
 * CKR_OK                      - Success
 */
CK_RV bignumber_to_attr(CK_ATTRIBUTE_PTR attr, const void *src);

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
 * ulong_to_attr() - Copy an unsigned long to attribute
 * @attr: Attribute destination
 * @src: Source value
 *
 * If attribute @value is defined, copies the @src into
 * attribute of type CK_ULONG
 *
 * return:
 * CKR_BUFFER_TOO_SMALL        - Attribute length too small
 * CKR_OK                      - Success
 */
CK_RV ulong_to_attr(CK_ATTRIBUTE_PTR attr, const void *src);

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

/**
 * attr_get_obj_value() - Get an object attribute's value
 * @attr: Attribute to get
 * @tattrs: Object attributes definition
 * @nb_tattrs: Number of Object attributes
 * @obj: Object containing the field to get
 *
 * Find in the object @tattrs definition if the attribute @attr is present.
 * If not present, nothing to do, hence return CKR_ATTRIBUTE_TYPE_INVALID.
 * Else
 *   - If @attr's field pValue is NULL,
 *     set field ulValueLen with object attribute value length
 *   - If @attr's field ulValueLen is large enough,
 *     set pValue with object attribute value and update ulValueLen
 *     with object attribute value length
 *   - If @attr's field ulValueLen is not big enough,
 *     set ulValueLen to CK_UNAVAILABLE_INFORMATION
 *
 * return:
 * CKR_FUNCTION_FAILED         - Function failure
 * CKR_ATTRIBUTE_SENSITIVE     - Attribute is sensitive
 * CKR_BUFFER_TOO_SMALL        - Attribute length is too small
 * CKR_ATTRIBUTE_TYPE_INVALID  - Attribute not found
 * CKR_OK                      - Success
 */
CK_RV
attr_get_obj_value(CK_ATTRIBUTE_PTR attr, const struct template_attr *tattrs,
		   size_t nb_tattrs, const void *obj);

/**
 * attr_get_obj_prot_value() - Get an object protected attribute's value
 * @attr: Attribute to get
 * @tattrs: Object attributes definition
 * @nb_tattrs: Number of Object attributes
 * @obj: Object containing the field to get
 * @protect: True if object is sensitive or unextractable
 *
 * Find in the object @tattrs definition if the attribute @attr is present.
 * If not present, nothing to do, hence return CKR_ATTRIBUTE_TYPE_INVALID.
 * Else
 *   - If attribute is sensitive or unextractable,
 *     set value to CK_UNAVAILABLE_INFORMATION
 *   - If @attr's field pValue is NULL,
 *     set field ulValueLen with object attribute value length
 *   - If @attr's field ulValueLen is large enough,
 *     set pValue with object attribute value and update ulValueLen
 *     with object attribute value length
 *   - If @attr's field ulValueLen is not big enough,
 *     set ulValueLen to CK_UNAVAILABLE_INFORMATION
 *
 * return:
 * CKR_FUNCTION_FAILED         - Function failure
 * CKR_ATTRIBUTE_SENSITIVE     - Attribute is sensitive
 * CKR_BUFFER_TOO_SMALL        - Attribute length is too small
 * CKR_ATTRIBUTE_TYPE_INVALID  - Attribute not found
 * CKR_OK                      - Success
 */
CK_RV
attr_get_obj_prot_value(CK_ATTRIBUTE_PTR attr,
			const struct template_attr *tattrs, size_t nb_tattrs,
			const void *obj, bool protect);

/**
 * attr_modify_obj_value() - Modify an object attribute's value
 * @attr: New attribute value
 * @tattrs: Object attributes definition
 * @nb_tattrs: Number of Object attributes
 * @obj: Object containing the field to modify
 *
 * Find in the object @tattrs definition if the attribute @attr is present.
 * If not present, nothing to do, hence return CKR_ATTRIBUTE_TYPE_INVALID.
 * Else calls the attribute modify function if defined.
 * If the attribute modify function is NULL, attribute is read only.
 *
 * return:
 * CKR_ATTRIBUTE_READ_ONLY     - Attribute is read only
 * CKR_ATTRIBUTE_TYPE_INVALID  - Attribute not found
 * CKR_ATTRIBUTE_VALUE_INVALID - Attribute value or length not valid
 * CKR_HOST_MEMORY             - Out of memory
 * CKR_OK                      - Success
 */
CK_RV
attr_modify_obj_value(CK_ATTRIBUTE_PTR attr, const struct template_attr *tattrs,
		      size_t nb_tattrs, void *obj);

#endif /* __ATTRIBUTE_H__ */
