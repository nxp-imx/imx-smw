// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2021 NXP
 */

#include <stdlib.h>
#include <string.h>

#include "attributes.h"

#include "trace.h"

/**
 * obj_find_attr() - Find an attribute type in object template
 * @outattr: Pointer to the attribute entry found
 * @type: Type of attribute to find
 * @attrs: Attributes list
 *
 * Find the attribute @type in the @attrs list. Attribute type must not be
 * duplicated, hence if found a second time return an error.
 * If the attribute type is not present the @outattrs is set to NULL.
 *
 * return:
 * CKR_TEMPLATE_INCONSISTENT - Attribute type more than once
 * CKR_OK                    - Success
 */
static CK_RV obj_find_attr(CK_ATTRIBUTE_PTR *outattr, CK_ATTRIBUTE_TYPE type,
			   struct libattr_list *attrs)
{
	*outattr = NULL;
	for (CK_ULONG idx = 0; idx < attrs->number; idx++) {
		if (attrs->attr[idx].type == type) {
			if (*outattr)
				return CKR_TEMPLATE_INCONSISTENT;

			*outattr = &attrs->attr[idx];
		}
	}

	return CKR_OK;
}

/**
 * set_attr_value_length() - Set the attribute's field ulValueLen
 * @attr: Pointer to the attribute to update
 * @length: Length to set
 *
 * If attribute's field pValue is NULL, set the ulValueLen to @length and
 * return OK.
 * Else, if attribute's field ulValueLen with:
 *  - CK_UNAVAILABLE_INFORMATION if ulValueLen too small
 *  - otherwise @length
 *
 * return:
 * CKR_BUFFER_TOO_SMALL      - Attribute length to return is too small
 * CKR_OK                    - Success
 */
static CK_RV set_attr_value_length(CK_ATTRIBUTE_PTR attr, CK_ULONG length)
{
	if (!attr->pValue) {
		attr->ulValueLen = length;
		return CKR_OK;
	}

	if (attr->ulValueLen < length) {
		attr->ulValueLen = CK_UNAVAILABLE_INFORMATION;
		return CKR_BUFFER_TOO_SMALL;
	}

	attr->ulValueLen = length;
	return CKR_OK;
}

CK_RV attr_to_class(void *dest, CK_ATTRIBUTE_PTR attr)
{
	CK_OBJECT_CLASS *out = dest;

	if (!attr->pValue)
		return CKR_ATTRIBUTE_VALUE_INVALID;

	*out = *(CK_OBJECT_CLASS *)attr->pValue;

	return CKR_OK;
}

CK_RV class_to_attr(CK_ATTRIBUTE_PTR attr, const void *src)
{
	CK_RV ret;
	const CK_OBJECT_CLASS *in = src;

	ret = set_attr_value_length(attr, sizeof(*in));

	if (!attr->pValue || ret != CKR_OK)
		return ret;

	*(CK_OBJECT_CLASS *)attr->pValue = *in;

	return CKR_OK;
}

CK_RV attr_to_rfc2279(void *dest, CK_ATTRIBUTE_PTR attr)
{
	struct librfc2279 *out = dest;

	if (!attr->pValue || !attr->ulValueLen)
		return CKR_ATTRIBUTE_VALUE_INVALID;

	out->length = attr->ulValueLen * sizeof(*out->string);
	out->string = malloc(out->length);
	if (!out->string)
		return CKR_HOST_MEMORY;

	memcpy(out->string, attr->pValue, out->length);

	return CKR_OK;
}

CK_RV rfc2279_to_attr(CK_ATTRIBUTE_PTR attr, const void *src)
{
	CK_RV ret;
	const struct librfc2279 *in = src;

	ret = set_attr_value_length(attr, in->length);

	if (!attr->pValue || ret != CKR_OK)
		return ret;

	memcpy(attr->pValue, in->string, in->length);

	return CKR_OK;
}

CK_RV modify_rfc2279(void *dest, CK_ATTRIBUTE_PTR attr)
{
	CK_RV ret;
	struct librfc2279 *out = dest;
	struct librfc2279 new = { 0 };

	ret = attr_to_rfc2279(&new, attr);
	if (ret != CKR_OK)
		return ret;

	free(out->string);
	out->string = new.string;
	out->length = new.length;

	return CKR_OK;
}

CK_RV attr_to_boolean(void *dest, CK_ATTRIBUTE_PTR attr)
{
	CK_BBOOL *out = dest;

	if (!attr->pValue)
		return CKR_ATTRIBUTE_VALUE_INVALID;

	*out = *(CK_BBOOL *)attr->pValue;

	return CKR_OK;
}

CK_RV boolean_to_attr(CK_ATTRIBUTE_PTR attr, const void *src)
{
	CK_RV ret;
	const CK_BBOOL *in = src;

	ret = set_attr_value_length(attr, sizeof(*in));

	if (!attr->pValue || ret != CKR_OK)
		return ret;

	*(CK_BBOOL *)attr->pValue = *in;

	return CKR_OK;
}

CK_RV modify_boolean(void *dest, CK_ATTRIBUTE_PTR attr)
{
	return attr_to_boolean(dest, attr);
}

CK_RV modify_true_only(void *dest, CK_ATTRIBUTE_PTR attr)
{
	if (!*(CK_BBOOL *)attr->pValue && *(CK_BBOOL *)dest)
		return CKR_ATTRIBUTE_READ_ONLY;

	return attr_to_boolean(dest, attr);
}

CK_RV modify_false_only(void *dest, CK_ATTRIBUTE_PTR attr)
{
	if (*(CK_BBOOL *)attr->pValue && !*(CK_BBOOL *)dest)
		return CKR_ATTRIBUTE_READ_ONLY;

	return attr_to_boolean(dest, attr);
}

CK_RV attr_to_key(void *dest, CK_ATTRIBUTE_PTR attr)
{
	CK_KEY_TYPE *out = dest;

	if (!attr->pValue)
		return CKR_ATTRIBUTE_VALUE_INVALID;

	*out = *(CK_KEY_TYPE *)attr->pValue;

	return CKR_OK;
}

CK_RV key_to_attr(CK_ATTRIBUTE_PTR attr, const void *src)
{
	CK_RV ret;
	const CK_KEY_TYPE *in = src;

	ret = set_attr_value_length(attr, sizeof(*in));

	if (!attr->pValue || ret != CKR_OK)
		return ret;

	*(CK_KEY_TYPE *)attr->pValue = *in;

	return CKR_OK;
}

CK_RV attr_to_byte_array(void *dest, CK_ATTRIBUTE_PTR attr)
{
	struct libbytes *out = dest;

	if (!attr->pValue || !attr->ulValueLen)
		return CKR_ATTRIBUTE_VALUE_INVALID;

	out->number = attr->ulValueLen;
	out->array = malloc(attr->ulValueLen);
	if (!out->array)
		return CKR_HOST_MEMORY;

	memcpy(out->array, attr->pValue, attr->ulValueLen);

	return CKR_OK;
}

CK_RV byte_array_to_attr(CK_ATTRIBUTE_PTR attr, const void *src)
{
	CK_RV ret;
	const struct libbytes *in = src;

	ret = set_attr_value_length(attr, in->number);

	if (!attr->pValue || ret != CKR_OK)
		return ret;

	memcpy(attr->pValue, in->array, in->number);

	return CKR_OK;
}

CK_RV modify_byte_array(void *dest, CK_ATTRIBUTE_PTR attr)
{
	CK_RV ret;
	struct libbytes *out = dest;
	struct libbytes new = { 0 };

	ret = attr_to_byte_array(&new, attr);
	if (ret != CKR_OK)
		return ret;

	free(out->array);
	out->array = new.array;
	out->number = new.number;

	return CKR_OK;
}

CK_RV attr_to_date(void *dest, CK_ATTRIBUTE_PTR attr)
{
	CK_DATE *out = dest;

	if (!attr->pValue)
		return CKR_ATTRIBUTE_VALUE_INVALID;

	*out = *(CK_DATE *)attr->pValue;

	return CKR_OK;
}

CK_RV date_to_attr(CK_ATTRIBUTE_PTR attr, const void *src)
{
	CK_RV ret;
	const CK_DATE *in = src;

	ret = set_attr_value_length(attr, sizeof(*in));

	if (!attr->pValue || ret != CKR_OK)
		return ret;

	*(CK_DATE *)attr->pValue = *in;

	return CKR_OK;
}

CK_RV modify_date(void *dest, CK_ATTRIBUTE_PTR attr)
{
	return attr_to_date(dest, attr);
}

CK_RV attr_to_mech(void *dest, CK_ATTRIBUTE_PTR attr)
{
	CK_MECHANISM_TYPE_PTR out = dest;

	if (!attr->pValue)
		return CKR_ATTRIBUTE_VALUE_INVALID;

	*out = *(CK_MECHANISM_TYPE_PTR)attr->pValue;

	return CKR_OK;
}

CK_RV mech_to_attr(CK_ATTRIBUTE_PTR attr, const void *src)
{
	const CK_MECHANISM_TYPE *in = src;
	CK_RV ret;

	ret = set_attr_value_length(attr, sizeof(*in));

	if (!attr->pValue || ret != CKR_OK)
		return ret;

	*(CK_MECHANISM_TYPE_PTR)attr->pValue = *in;

	return CKR_OK;
}

CK_RV attr_to_mech_list(void *dest, CK_ATTRIBUTE_PTR attr)
{
	struct libmech_list *out = dest;

	if (!attr->pValue || !attr->ulValueLen)
		return CKR_ATTRIBUTE_VALUE_INVALID;

	out->number = attr->ulValueLen;
	out->mech = malloc(out->number * sizeof(*out->mech));
	if (!out->mech)
		return CKR_HOST_MEMORY;

	memcpy(out->mech, attr->pValue, out->number * sizeof(*out->mech));

	return CKR_OK;
}

CK_RV mech_list_to_attr(CK_ATTRIBUTE_PTR attr, const void *src)
{
	CK_RV ret;
	const struct libmech_list *in = src;

	ret = set_attr_value_length(attr, in->number * sizeof(*in->mech));

	if (!attr->pValue || ret != CKR_OK)
		return ret;

	memcpy(attr->pValue, in->mech, in->number * sizeof(*in->mech));

	return CKR_OK;
}

CK_RV attr_to_attr_list(void *dest, CK_ATTRIBUTE_PTR attr)
{
	struct libattr_list *out = dest;

	if (!attr->pValue || !attr->ulValueLen)
		return CKR_ATTRIBUTE_VALUE_INVALID;

	out->number = attr->ulValueLen;
	out->attr = malloc(out->number * sizeof(*out->attr));
	if (!out->attr)
		return CKR_HOST_MEMORY;

	memcpy(out->attr, attr->pValue, out->number * sizeof(*out->attr));

	return CKR_OK;
}

CK_RV attr_list_to_attr(CK_ATTRIBUTE_PTR attr, const void *src)
{
	CK_RV ret;
	const struct libattr_list *in = src;

	ret = set_attr_value_length(attr, in->number * sizeof(*in->attr));

	if (!attr->pValue || ret != CKR_OK)
		return ret;

	memcpy(attr->pValue, in->attr, in->number * sizeof(*in->attr));

	return CKR_OK;
}

CK_RV attr_to_bignumber(void *dest, CK_ATTRIBUTE_PTR attr)
{
	struct libbignumber *out = dest;

	if (!attr->pValue || !attr->ulValueLen)
		return CKR_ATTRIBUTE_VALUE_INVALID;

	out->length = attr->ulValueLen;
	out->value = malloc(out->length * sizeof(*out->value));
	if (!out->value)
		return CKR_HOST_MEMORY;

	memcpy(out->value, attr->pValue, out->length * sizeof(*out->value));

	return CKR_OK;
}

CK_RV bignumber_to_attr(CK_ATTRIBUTE_PTR attr, const void *src)
{
	CK_RV ret;
	const struct libbignumber *in = src;

	ret = set_attr_value_length(attr, in->length * sizeof(*in->value));

	if (!attr->pValue || ret != CKR_OK)
		return ret;

	memcpy(attr->pValue, in->value, in->length * sizeof(*in->value));

	return CKR_OK;
}

CK_RV attr_to_ulong(void *dest, CK_ATTRIBUTE_PTR attr)
{
	CK_ULONG *out = dest;

	if (!attr->pValue)
		return CKR_ATTRIBUTE_VALUE_INVALID;

	*out = *(CK_ULONG *)attr->pValue;

	return CKR_OK;
}

CK_RV ulong_to_attr(CK_ATTRIBUTE_PTR attr, const void *src)
{
	CK_RV ret;
	const CK_ULONG *in = src;

	ret = set_attr_value_length(attr, sizeof(*in));

	if (!attr->pValue || ret != CKR_OK)
		return ret;

	*(CK_ULONG *)attr->pValue = *in;

	return CKR_OK;
}

CK_RV attr_get_value(void *obj, const struct template_attr *tattr,
		     struct libattr_list *attrs, enum attr_req req_overwrite)
{
	CK_RV ret;
	CK_ATTRIBUTE_PTR cattr = NULL;
	enum attr_req req = tattr->req;

	ret = obj_find_attr(&cattr, tattr->type, attrs);
	if (ret != CKR_OK)
		return ret;

	if (req_overwrite != NO_OVERWRITE)
		req = req_overwrite;

	if (!cattr) {
		if (req == MUST) {
			DBG_TRACE("Attribute Type 0x%lx must be present",
				  tattr->type);
			ret = CKR_TEMPLATE_INCOMPLETE;
		}

		return ret;
	}

	switch (req) {
	case MUST_NOT:
		DBG_TRACE("Attribute Type 0x%lx must not be present",
			  tattr->type);
		return CKR_TEMPLATE_INCONSISTENT;

	case READ_ONLY:
		DBG_TRACE("Attribute Type 0x%lx is read only", tattr->type);
		return CKR_ATTRIBUTE_READ_ONLY;

	default:
		break;
	}

	if (!cattr->pValue) {
		DBG_TRACE("Attribute Type 0x%lx not defined", tattr->type);
		return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	/*
	 * If attribute expected length = 0, length is not know, hence don't
	 * verify it.
	 */
	if (tattr->val_len && cattr->ulValueLen != tattr->val_len) {
		DBG_TRACE("Attribute Type 0x%lx size not correct", tattr->type);
		return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	ret = tattr->attr_to(obj + tattr->of_field, cattr);
	return CKR_OK;
}

CK_RV attr_get_obj_prot_value(CK_ATTRIBUTE_PTR attr,
			      const struct template_attr *tattrs,
			      size_t nb_tattrs, const void *obj, bool protect)
{
	size_t idx;
	const struct template_attr *tattr = tattrs;

	for (idx = 0; idx < nb_tattrs; idx++, tattr++) {
		if (attr->type == tattr->type) {
			if (tattr->protect && protect) {
				attr->ulValueLen = CK_UNAVAILABLE_INFORMATION;
				return CKR_ATTRIBUTE_SENSITIVE;
			}

			return tattr->to_attr(attr, obj + tattr->of_field);
		}
	}

	return CKR_ATTRIBUTE_TYPE_INVALID;
}

CK_RV attr_get_obj_value(CK_ATTRIBUTE_PTR attr,
			 const struct template_attr *tattrs, size_t nb_tattrs,
			 const void *obj)
{
	return attr_get_obj_prot_value(attr, tattrs, nb_tattrs, obj, false);
}

CK_RV attr_modify_obj_value(CK_ATTRIBUTE_PTR attr,
			    const struct template_attr *tattrs,
			    size_t nb_tattrs, void *obj)
{
	size_t idx;
	const struct template_attr *tattr = tattrs;

	for (idx = 0; idx < nb_tattrs; idx++, tattr++) {
		if (attr->type == tattr->type) {
			if (tattr->modify)
				return tattr->modify(obj + tattr->of_field,
						     attr);
			else
				return CKR_ATTRIBUTE_READ_ONLY;
		}
	}

	return CKR_ATTRIBUTE_TYPE_INVALID;
}
