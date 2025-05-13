// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024-2025 NXP
 */

#include <string.h>

#include "attributes.h"
#include "data.h"
#include "key.h"

#include "ifsmw_utils.h"

#include "lib_device.h"
#include "lib_object.h"
#include "lib_session.h"
#include "libobj_types.h"

#include "key_desc.h"
#include "object_desc.h"

#include "trace.h"

static CK_RV get_object_class(struct librfc2279 *unique_id,
			      CK_OBJECT_CLASS_PTR object_class)
{
	int ret = CKR_OK;

	struct libbytes id = { 0 };

	id.number =
		util_rfc2279_to_byte_len(unique_id->string, unique_id->length);
	if (!id.number)
		return CKR_FUNCTION_FAILED;

	id.array = malloc(id.number);
	if (!id.array)
		return CKR_HOST_MEMORY;

	if (util_rfc2279_to_byte(id.array, id.number, unique_id->string,
				 unique_id->length) != unique_id->length) {
		ret = CKR_FUNCTION_FAILED;
		goto end;
	}

	if (TO_INT(*object_class, id.array, sizeof(CK_OBJECT_CLASS)))
		ret = CKR_ATTRIBUTE_VALUE_INVALID;

end:
	free(id.array);

	return ret;
}

static CK_RV obj_match_id(struct libobj_obj *obj,
			  struct smw_object_descriptor *desc,
			  CK_OBJECT_CLASS exp_class, bool *match)
{
	unsigned int token_id = 0;

	*match = false;

	switch (obj->class) {
	case CKO_PRIVATE_KEY:
	case CKO_PUBLIC_KEY:
	case CKO_SECRET_KEY:
		token_id = get_key_token_id(obj);
		break;

	case CKO_DATA:
		token_id = get_data_token_id(obj);
		break;

	default:
		DBG_TRACE("Class object %lu not supported", obj->class);
		return CKR_FUNCTION_FAILED;
	}

	if (exp_class == CK_UNAVAILABLE_INFORMATION || exp_class == obj->class)
		*match = (token_id == desc->id) ? true : false;

	return CKR_OK;
}

static void
cleanup_smw_object_descriptor(struct smw_object_descriptor *descriptor)
{
	if (descriptor->label)
		free(descriptor->label);

	if (descriptor->user_id)
		free(descriptor->user_id);

	memset(descriptor, 0, sizeof(struct smw_object_descriptor));
}

static CK_RV get_pkcs11_class(smw_object_type_t type,
			      CK_OBJECT_CLASS *object_class)
{
	if (!object_class)
		return CKR_ARGUMENTS_BAD;

	switch (type) {
	case SMW_OBJECT_TYPE_NAME_DATA:
		*object_class = CKO_DATA;
		break;

	case SMW_OBJECT_TYPE_NAME_SECRET_KEY:
		*object_class = CKO_SECRET_KEY;
		break;

	case SMW_OBJECT_TYPE_NAME_KEY_PAIR:
		*object_class = CKO_PRIVATE_KEY;
		break;

	case SMW_OBJECT_TYPE_NAME_PUBLIC_KEY:
		*object_class = CKO_PUBLIC_KEY;
		break;

	default:
		return CKR_ARGUMENTS_BAD;
	}

	return CKR_OK;
}

static smw_object_type_t get_smw_object_type(CK_OBJECT_CLASS obj_class)
{
	switch (obj_class) {
	case CKO_DATA:
		return SMW_OBJECT_TYPE_NAME_DATA;

	case CKO_PUBLIC_KEY:
	case CKO_PRIVATE_KEY:
		return SMW_OBJECT_TYPE_NAME_KEY_PAIR;

	case CKO_SECRET_KEY:
		return SMW_OBJECT_TYPE_NAME_SECRET_KEY;

	default:
		break;
	}

	return SMW_OBJECT_TYPE_NAME_NONE;
}

static CK_RV attrs_to_object_descriptor(struct smw_object_descriptor *desc,
					CK_ATTRIBUTE_PTR attrs,
					CK_ULONG nb_attrs)
{
	CK_RV ret = CKR_OK;
	CK_OBJECT_CLASS object_class = CKO_DATA;
	CK_KEY_TYPE key_type = CKK_RSA;
	struct librfc2279 unique_id = { 0 };
	struct librfc2279 label = { 0 };
	struct libbytes user_id = { 0 };
	struct libbytes ec_params = { 0 };
	unsigned int i = 0;
	size_t len = 0;

	for (; i < nb_attrs; i++) {
		switch (attrs[i].type) {
		case CKA_OBJECT_ID:
		case CKA_ID:
			if (user_id.array)
				ret = CKR_ARGUMENTS_BAD;
			else
				ret = attr_to_byte_array(&user_id, &attrs[i]);

			break;

		case CKA_UNIQUE_ID:
			if (unique_id.string)
				ret = CKR_ARGUMENTS_BAD;
			else
				ret = attr_to_rfc2279(&unique_id, &attrs[i]);

			if (ret != CKR_OK)
				break;

			ret = libobj_get_id(&unique_id, &desc->id);
			if (ret != CKR_OK)
				break;

			ret = get_object_class(&unique_id, &object_class);
			if (ret != CKR_OK)
				break;

			desc->type = get_smw_object_type(object_class);
			break;

		case CKA_CLASS:
			ret = attr_to_class(&object_class, &attrs[i]);
			if (ret != CKR_OK)
				break;

			desc->type = get_smw_object_type(object_class);
			break;

		case CKA_LABEL:
			if (label.string)
				ret = CKR_ARGUMENTS_BAD;
			else
				ret = attr_to_rfc2279(&label, &attrs[i]);

			break;

		case CKA_KEY_TYPE:
			ret = attr_to_key(&key_type, &attrs[i]);
			if (ret == CKR_OK && !(key_type == CKK_EC))
				ret = key_desc_set_key_type(&desc->key,
							    key_type, NULL);

			break;

		case CKA_EC_PARAMS:
			if (ec_params.array) {
				ret = CKR_ARGUMENTS_BAD;
				break;
			}

			ret = attr_to_byte_array(&ec_params, &attrs[i]);
			if (ret == CKR_OK)
				ret = key_desc_set_key_type(&desc->key, CKK_EC,
							    &ec_params);

			break;

		default:
			continue;
		}

		if (ret)
			goto end;
	}

	if (label.string) {
		len = util_rfc2279_to_byte_len(label.string, label.length);
		if (len) {
			desc->label =
				calloc(1, len + 1 /* zero terminated string */);
			if (!desc->label) {
				ret = CKR_HOST_MEMORY;
				goto end;
			}

			util_rfc2279_to_byte((CK_CHAR_PTR)desc->label, len,
					     label.string, label.length);
		}
	}

	if (user_id.number) {
		len = user_id.number * 2;
		if (len) {
			desc->user_id =
				calloc(1, len + 1 /* zero terminated string */);
			if (!desc->user_id) {
				ret = CKR_HOST_MEMORY;
				goto end;
			}

			if (!util_byte_to_hex((CK_CHAR_PTR)desc->user_id, len,
					      user_id.array, user_id.number)) {
				ret = CKR_ARGUMENTS_BAD;
				goto end;
			}
		}
	}

end:
	if (unique_id.string)
		free(unique_id.string);

	if (user_id.array)
		free(user_id.array);

	if (label.string)
		free(label.string);

	if (ec_params.array)
		free(ec_params.array);

	if (ret != CKR_OK)
		cleanup_smw_object_descriptor(desc);

	DBG_TRACE("%s return %lx", __func__, ret);

	return ret;
}

static CK_RV object_descriptor_to_attrs(struct smw_object_descriptor *desc,
					struct smw_key_attributes *key_attr,
					CK_OBJECT_CLASS req_class,
					CK_ATTRIBUTE_PTR *attrs,
					CK_ULONG_PTR attrs_count)
{
	CK_RV ret = CKR_OK;
	CK_BBOOL bTrue = CK_TRUE;
	CK_BBOOL bFalse = CK_FALSE;
	CK_OBJECT_CLASS object_class = CKO_DATA;
	CK_KEY_TYPE key_type = CKK_RSA;
	CK_ULONG obj_length = 0;
	struct libbytes label = { 0 };
	struct libbytes user_id = { 0 };
	CK_ULONG nb_attrs = 0;
	CK_ATTRIBUTE_PTR p_attr = NULL;
	struct smw_key_descriptor *key = &desc->key;
	struct smw_data_descriptor *data = &desc->data;
	smw_attr_attributes_t obj_attributes = 0;
	CK_ULONG i = 0;

	if (!attrs) {
		ret = CKR_GENERAL_ERROR;
		goto end;
	}

	p_attr = *attrs;

	if (desc->label) {
		if (p_attr) {
			label.array = (CK_BYTE_PTR)desc->label;
			label.number = strlen(desc->label);

			p_attr->type = CKA_LABEL;
			ret = byte_array_to_attr(p_attr, &label);
			if (ret != CKR_OK)
				goto end;

			p_attr++;
		}

		nb_attrs++;
	}

	switch (desc->type) {
	case SMW_OBJECT_TYPE_NAME_SECRET_KEY:
	case SMW_OBJECT_TYPE_NAME_KEY_PAIR:
	case SMW_OBJECT_TYPE_NAME_PUBLIC_KEY:
		obj_attributes = key->attributes.attributes;
		break;

	case SMW_OBJECT_TYPE_NAME_DATA:
		obj_attributes = data->attributes.attributes;
		break;

	default:
		ret = CKR_ARGUMENTS_BAD;
		goto end;
	}

	switch (SMW_ATTR_GET_PERSISTENCE(obj_attributes)) {
	case SMW_ATTR_PERSISTENCE_PERSISTENT:
	case SMW_ATTR_PERSISTENCE_PERMANENT:
		if (p_attr) {
			p_attr->type = CKA_TOKEN;
			ret = boolean_to_attr(p_attr, &bTrue);

			p_attr++;
		}

		nb_attrs++;
		break;

	case SMW_ATTR_PERSISTENCE_TRANSIENT:
		if (p_attr) {
			p_attr->type = CKA_TOKEN;
			ret = boolean_to_attr(p_attr, &bFalse);

			p_attr++;
		}

		nb_attrs++;
		break;

	default:
		ret = CKR_ARGUMENTS_BAD;
		break;
	}

	if (ret != CKR_OK)
		goto end;

	switch (desc->type) {
	case SMW_OBJECT_TYPE_NAME_SECRET_KEY:
	case SMW_OBJECT_TYPE_NAME_KEY_PAIR:
	case SMW_OBJECT_TYPE_NAME_PUBLIC_KEY:
		if (p_attr) {
			obj_length = key->security_size;
			p_attr->type = CKA_VALUE_LEN;
			ret = ulong_to_attr(p_attr, &obj_length);

			p_attr++;
		}

		nb_attrs++;

		if (p_attr) {
			ret = key_desc_get_key_type(&key_type, key);
			if (ret == CKR_OK) {
				p_attr->type = CKA_KEY_TYPE;
				ret = key_to_attr(p_attr, &key_type);
			}

			p_attr++;
		}

		nb_attrs++;
		break;

	case SMW_OBJECT_TYPE_NAME_DATA:
		if (p_attr) {
			obj_length = data->length;
			p_attr->type = CKA_VALUE_LEN;
			ret = ulong_to_attr(p_attr, &obj_length);

			p_attr++;
		}

		nb_attrs++;
		break;

	default:
		ret = CKR_ARGUMENTS_BAD;
		break;
	}

	if (ret != CKR_OK)
		goto end;

	ret = get_pkcs11_class(desc->type, &object_class);
	if (ret != CKR_OK)
		goto end;

	if (p_attr) {
		if (req_class != CK_UNAVAILABLE_INFORMATION)
			object_class = req_class;

		p_attr->type = CKA_CLASS;
		ret = class_to_attr(p_attr, &object_class);
		if (ret != CKR_OK)
			goto end;

		p_attr++;
	}

	nb_attrs++;

	if (desc->user_id) {
		if (p_attr) {
			if (object_class == CKO_DATA)
				p_attr->type = CKA_OBJECT_ID;
			else
				p_attr->type = CKA_ID;

			user_id.array = (CK_BYTE_PTR)desc->user_id;
			user_id.number = strlen(desc->user_id);

			if (p_attr->ulValueLen < user_id.number / 2) {
				p_attr->ulValueLen = user_id.number / 2;
			} else if (!util_hex_to_byte(p_attr->pValue,
						     p_attr->ulValueLen,
						     user_id.array,
						     user_id.number)) {
				ret = CKR_ARGUMENTS_BAD;
				goto end;
			}
		}

		nb_attrs++;
	}

	if (!*attrs) {
		*attrs_count = nb_attrs;

		/* Step 1. Allocate the attributes array */
		*attrs = calloc(1, nb_attrs * sizeof(CK_ATTRIBUTE));
		if (!*attrs) {
			ret = CKR_HOST_MEMORY;
			goto end;
		}

		/* Step 2. Get all values length */
		ret = object_descriptor_to_attrs(desc, key_attr, req_class,
						 attrs, attrs_count);
		if (ret != CKR_OK)
			goto end;

		/* Step 3. Allocate attribute value buffer */
		for (p_attr = *attrs; i < nb_attrs; i++, p_attr++) {
			p_attr->pValue = calloc(1, p_attr->ulValueLen);
			if (!p_attr->pValue) {
				ret = CKR_HOST_MEMORY;
				goto end;
			}
		}

		/* Step 4. Get all values */
		ret = object_descriptor_to_attrs(desc, key_attr, req_class,
						 attrs, attrs_count);
		if (ret != CKR_OK)
			goto end;
	}

	ret = CKR_OK;

end:

	if (ret != CKR_OK)
		attr_free(attrs, attrs_count);

	DBG_TRACE("%s return %lx", __func__, ret);
	return ret;
}

static bool is_obj_class_retrievable(CK_OBJECT_CLASS object_class)
{
	bool ret = false;

	switch (object_class) {
	case CK_UNAVAILABLE_INFORMATION:
	case CKO_DATA:
	case CKO_PRIVATE_KEY:
	case CKO_PUBLIC_KEY:
	case CKO_SECRET_KEY:
		ret = true;
		break;

	default:
		break;
	}

	return ret;
}

CK_RV obj_db_get(struct libobj_obj *obj,
		 struct smw_object_descriptor *descriptor)
{
	CK_RV ret = CKR_OBJECT_HANDLE_INVALID;
	enum smw_status_code status = SMW_STATUS_OK;
	struct smw_find_object_db_args find_args = { 0 };
	smw_attr_attributes_t obj_attributes = 0;

	if (!obj)
		return CKR_ARGUMENTS_BAD;

	if (is_token_obj(obj, storage))
		obj_attributes = SMW_ATTR_PERSISTENCE_PERSISTENT;
	else
		obj_attributes = SMW_ATTR_PERSISTENCE_TRANSIENT;

	switch (obj->class) {
	case CKO_DATA:
		descriptor->type = SMW_OBJECT_TYPE_NAME_DATA;
		break;

	case CKO_PUBLIC_KEY:
	case CKO_PRIVATE_KEY:
		descriptor->type = SMW_OBJECT_TYPE_NAME_KEY_PAIR;
		break;

	case CKO_SECRET_KEY:
		descriptor->type = SMW_OBJECT_TYPE_NAME_SECRET_KEY;
		break;

	default:
		break;
	}

	switch (obj->class) {
	case CKO_SECRET_KEY:
	case CKO_PUBLIC_KEY:
	case CKO_PRIVATE_KEY:
		descriptor->id = get_key_token_id(obj);
		descriptor->key.attributes.attributes = obj_attributes;
		ret = CKR_OK;
		break;

	case CKO_DATA:
		descriptor->id = get_data_token_id(obj);
		descriptor->data.attributes.attributes = obj_attributes;
		ret = CKR_OK;
		break;

	default:
		break;
	}

	if (ret != CKR_OK)
		return ret;

	if (!descriptor->id)
		return CKR_OBJECT_HANDLE_INVALID;

	find_args.object_descriptor = descriptor;
	status = smw_find_object_db(&find_args);
	if (status != SMW_STATUS_OK)
		ret = smw_status_to_ck_rv(status);

	return ret;
}

CK_RV obj_db_update(struct libobj_obj *obj)
{
	CK_RV ret = CKR_OK;
	enum smw_status_code status = SMW_STATUS_OK;
	struct libobj_key *key = NULL;
	struct libobj_data *data = NULL;
	struct libobj_storage *obj_storage = get_object_from(obj);
	struct libbytes label = { 0 };
	struct libbytes user_id = { 0 };
	struct smw_object_descriptor descriptor = { 0 };
	size_t len = 0;

	ret = obj_db_get(obj, &descriptor);
	if (ret)
		return ret;

	if (!get_unique_id_obj(obj, storage)->length) {
		ret = libobj_set_unique_id(obj, descriptor.id);
		if (ret)
			return ret;
	}

	if (obj_storage && obj_storage->label.length) {
		label.number =
			util_rfc2279_to_byte_len(obj_storage->label.string,
						 obj_storage->label.length) +
			1 /* zero terminated string */;
		if (label.number) {
			label.array = malloc(label.number);
			if (!label.array) {
				ret = CKR_HOST_MEMORY;
				goto end;
			}

			util_rfc2279_to_byte(label.array, label.number,
					     obj_storage->label.string,
					     obj_storage->label.length);
			label.array[label.number - 1] = 0;

			descriptor.label = (char *)label.array;
		}
	}

	switch (obj->class) {
	case CKO_DATA:
		data = get_subobj_from(obj, storage);
		if (data && data->id.number) {
			user_id.number = data->id.number;
			user_id.array = data->id.array;
		}

		break;

	case CKO_PRIVATE_KEY:
	case CKO_PUBLIC_KEY:
	case CKO_SECRET_KEY:
		key = get_subobj_from(obj, storage);
		if (key && key->id.number) {
			user_id.number = key->id.number;
			user_id.array = key->id.array;
		}

		break;

	default:
		break;
	}

	if (user_id.number) {
		len = user_id.number * 2;
		descriptor.user_id = calloc(1, len + 1);
		if (!descriptor.user_id) {
			ret = CKR_HOST_MEMORY;
			goto end;
		}

		if (!util_byte_to_hex((CK_CHAR_PTR)descriptor.user_id, len,
				      user_id.array, user_id.number)) {
			ret = CKR_ARGUMENTS_BAD;
			goto end;
		}
	}

	status = smw_update_object_db(&descriptor);
	if (status != SMW_STATUS_OK)
		ret = smw_status_to_ck_rv(status);

end:
	cleanup_smw_object_descriptor(&descriptor);

	return ret;
}

CK_RV obj_db_retrieve(CK_SESSION_HANDLE hsession, CK_ATTRIBUTE_PTR attrs,
		      CK_ULONG nb_attrs, CK_ULONG *pnb_retrieved)
{
	CK_RV ret = CKR_ARGUMENTS_BAD;
	int status = SMW_STATUS_OK;
	struct smw_find_object_db_args find_args = { 0 };
	struct smw_object_descriptor descriptor = { 0 };
	struct smw_key_attributes *key_attr = NULL;
	struct smw_get_key_attributes_args attr_args = { 0 };
	smw_attr_attributes_t persistence = 0;
	CK_ATTRIBUTE_PTR attributes = NULL_PTR;
	CK_ULONG attributes_count = 0;
	CK_ULONG nb_retrieved = 0;
	CK_OBJECT_CLASS object_class = CK_UNAVAILABLE_INFORMATION;
	CK_SLOT_ID slotid = 0;
	const struct libdev *devinfo = NULL;
	struct libdevice *dev = NULL;
	struct libobj_obj *libobj = NULL;
	unsigned int i = 0;
	bool is_present = false;

	if (!pnb_retrieved)
		goto end;

	/*
	 * Do not search the DB for profile objects, as they are not stored
	 * there and exit this function.
	 */
	for (; i < nb_attrs; i++) {
		if (attrs[i].type == CKA_CLASS) {
			object_class = *(CK_OBJECT_CLASS *)attrs[i].pValue;
			break;
		}
	}

	/*
	 * If the input attributes template to search defined the class,
	 * operation check the class value and if not supported, exit with
	 * status ok but no object retrieved.
	 */
	if (!is_obj_class_retrievable(object_class)) {
		DBG_TRACE("%s object class 0x%lx not supported", __func__,
			  object_class);
		ret = CKR_OK;
		goto end;
	}

	ret = libsess_get_slotid(hsession, &slotid);
	if (ret != CKR_OK)
		goto end;

	devinfo = libdev_get_devinfo(slotid);
	if (!devinfo) {
		ret = CKR_SLOT_ID_INVALID;
		goto end;
	}

	ret = libsess_get_device(hsession, &dev);
	if (ret != CKR_OK)
		return ret;

	ret = attrs_to_object_descriptor(&descriptor, attrs, nb_attrs);
	if (ret != CKR_OK)
		goto end;

	/*
	 * Only retrieve persistent token object.
	 */
	persistence = SMW_ATTR_SET_PERSISTENT(0);
	descriptor.persistency = persistence;

	switch (descriptor.type) {
	case SMW_OBJECT_TYPE_NAME_DATA:
		descriptor.data.attributes.attributes = persistence;
		break;

	case SMW_OBJECT_TYPE_NAME_SECRET_KEY:
	case SMW_OBJECT_TYPE_NAME_PUBLIC_KEY:
	case SMW_OBJECT_TYPE_NAME_KEY_PAIR:
		descriptor.key.attributes.attributes = persistence;
		break;

	default:
		break;
	}

	find_args.object_descriptor = &descriptor;

	status = smw_find_object_db_init(&find_args);
	ret = smw_status_to_ck_rv(status);
	if (ret != CKR_OK)
		goto end;

	cleanup_smw_object_descriptor(&descriptor);

	while (smw_find_object_db_next(&find_args) == SMW_STATUS_OK) {
		/*
		 * Look in token list objects of object token id already
		 * present or not. If not, get all object information and
		 * add it in the token list.
		 */
		is_present = false;
		for (libobj = LIST_FIRST(&dev->objects); libobj;
		     libobj = LIST_NEXT(libobj)) {
			if (!is_obj_class_retrievable(libobj->class))
				continue;

			ret = obj_match_id(libobj, &descriptor, object_class,
					   &is_present);
			if (ret != CKR_OK)
				goto end;

			if (is_present)
				break;
		}

		if (is_present)
			continue;

		/*
		 * Get key attributes
		 */
		switch (descriptor.type) {
		case SMW_OBJECT_TYPE_NAME_KEY_PAIR:
		case SMW_OBJECT_TYPE_NAME_PUBLIC_KEY:
		case SMW_OBJECT_TYPE_NAME_SECRET_KEY:
			attr_args.subsystem_name = devinfo->name;
			attr_args.key_descriptor = &descriptor.key;
			descriptor.key.id = descriptor.id;

			status = smw_get_key_attributes(&attr_args);
			ret = smw_status_to_ck_rv(status);
			if (ret != CKR_OK)
				goto end;

			key_attr = &attr_args.key_descriptor->attributes;
			break;

		default:
			break;
		}

		/* Build the attributes template to create the PKCS11 object */
		ret = object_descriptor_to_attrs(&descriptor, key_attr,
						 object_class, &attributes,
						 &attributes_count);
		if (ret != CKR_OK)
			goto end;

		if (descriptor.type == SMW_OBJECT_TYPE_NAME_KEY_PAIR)
			ret = libobj_keypair_retrieve(hsession, attributes,
						      attributes_count,
						      descriptor.id);
		else
			ret = libobj_retrieve(hsession, attributes,
					      attributes_count, descriptor.id);

		if (ret != CKR_OK)
			goto end;

		nb_retrieved++;

		attr_free(&attributes, &attributes_count);
		cleanup_smw_object_descriptor(&descriptor);
	}

end:
	if (pnb_retrieved)
		*pnb_retrieved = nb_retrieved;

	status = smw_find_object_db_final(&find_args);
	if (ret == CKR_OK)
		ret = smw_status_to_ck_rv(status);

	attr_free(&attributes, &attributes_count);

	cleanup_smw_object_descriptor(&descriptor);

	DBG_TRACE("%s return %lx", __func__, ret);

	return ret;
}
