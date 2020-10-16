// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020 NXP
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

CK_RV attr_to_class(void *dest, CK_ATTRIBUTE_PTR attr)
{
	CK_OBJECT_CLASS *out = dest;

	if (!attr->pValue)
		return CKR_ATTRIBUTE_VALUE_INVALID;

	*out = *(CK_OBJECT_CLASS *)attr->pValue;

	return CKR_OK;
}

CK_RV attr_to_rfc2279(void *dest, CK_ATTRIBUTE_PTR attr)
{
	struct rfc2279 *out = dest;

	if (!attr->pValue || !attr->ulValueLen)
		return CKR_ATTRIBUTE_VALUE_INVALID;

	out->length = attr->ulValueLen * sizeof(*out->string);
	out->string = malloc(out->length);
	if (!out->string)
		return CKR_HOST_MEMORY;

	memcpy(out->string, attr->pValue, out->length);

	return CKR_OK;
}

CK_RV attr_to_bool(void *dest, CK_ATTRIBUTE_PTR attr)
{
	CK_BBOOL *out = dest;

	if (!attr->pValue)
		return CKR_ATTRIBUTE_VALUE_INVALID;

	*out = *(CK_BBOOL *)attr->pValue;

	return CKR_OK;
}

CK_RV attr_to_key(void *dest, CK_ATTRIBUTE_PTR attr)
{
	CK_KEY_TYPE *out = dest;

	if (!attr->pValue)
		return CKR_ATTRIBUTE_VALUE_INVALID;

	*out = *(CK_KEY_TYPE *)attr->pValue;

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

CK_RV attr_to_date(void *dest, CK_ATTRIBUTE_PTR attr)
{
	CK_DATE *out = dest;

	if (!attr->pValue)
		return CKR_ATTRIBUTE_VALUE_INVALID;

	*out = *(CK_DATE *)attr->pValue;

	return CKR_OK;
}

CK_RV attr_to_mech(void *dest, CK_ATTRIBUTE_PTR attr)
{
	CK_MECHANISM_TYPE_PTR out = dest;

	if (!attr->pValue)
		return CKR_ATTRIBUTE_VALUE_INVALID;

	*out = *(CK_MECHANISM_TYPE_PTR)attr->pValue;

	return CKR_OK;
}

CK_RV attr_to_mech_list(void *dest, CK_ATTRIBUTE_PTR attr)
{
	struct mech_list *out = dest;

	if (!attr->pValue || !attr->ulValueLen)
		return CKR_ATTRIBUTE_VALUE_INVALID;

	out->number = attr->ulValueLen;
	out->mech = malloc(out->number * sizeof(*out->mech));
	if (!out->mech)
		return CKR_HOST_MEMORY;

	memcpy(out->mech, attr->pValue, out->number * sizeof(*out->mech));

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

CK_RV attr_to_ulong(void *dest, CK_ATTRIBUTE_PTR attr)
{
	CK_ULONG *out = dest;

	if (!attr->pValue)
		return CKR_ATTRIBUTE_VALUE_INVALID;

	*out = *(CK_ULONG *)attr->pValue;

	return CKR_OK;
}

CK_RV attr_get_value(void *dest, const struct template_attr *tattr,
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

	ret = tattr->copy_to(dest, cattr);
	return CKR_OK;
}
