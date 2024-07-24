// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024 NXP
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

#include "object_desc.h"

#include "trace.h"

static CK_RV get_object_id(struct librfc2279 *unique_id,
			   unsigned int *object_id)
{
	int ret = CKR_OK;

	struct libbytes id = { 0 };

	if (!unique_id->length)
		return CKR_ATTRIBUTE_VALUE_INVALID;

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

	if (TO_INT(*object_id, &id.array[sizeof(CK_OBJECT_CLASS)],
		   sizeof(unsigned int)))
		ret = CKR_ATTRIBUTE_VALUE_INVALID;

end:
	free(id.array);

	return ret;
}

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

static CK_RV obj_match_descriptor(struct libobj_obj *obj,
				  struct smw_object_descriptor *desc,
				  bool *match)
{
	CK_RV ret = CKR_OK;
	struct librfc2279 *unique_id = get_unique_id_obj(obj, storage);
	unsigned int id = 0;

	if (!match)
		return CKR_ARGUMENTS_BAD;

	*match = false;

	if (!unique_id->length)
		return CKR_OK;

	ret = get_object_id(unique_id, &id);
	if (ret != CKR_OK)
		return ret;

	if (id == desc->id)
		*match = true;

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

static CK_RV get_pkcs11_key_type(smw_key_type_t type, smw_attr_algo_t algo,
				 CK_KEY_TYPE *key_type)
{
	CK_RV ret = CKR_ARGUMENTS_BAD;

	if (!key_type)
		goto end;

	switch (type) {
	case SMW_KEY_TYPE_NAME_AES:
		*key_type = CKK_AES;
		break;

	case SMW_KEY_TYPE_NAME_DES:
		*key_type = CKK_DES;
		break;

	case SMW_KEY_TYPE_NAME_DES3:
		*key_type = CKK_DES3;
		break;

	case SMW_KEY_TYPE_NAME_DSA_SM2_FP:
		*key_type = CKK_DSA;
		break;

	case SMW_KEY_TYPE_NAME_SM4:
		*key_type = CKK_SM4;
		break;

	case SMW_KEY_TYPE_NAME_RSA:
		*key_type = CKK_RSA;
		break;

	case SMW_KEY_TYPE_NAME_DH:
		*key_type = CKK_DH;
		break;

	case SMW_KEY_TYPE_NAME_HMAC:
		switch (SMW_ATTR_GET_HASH(algo)) {
		case SMW_HASH_ALGO_NAME_MD5:
			*key_type = CKK_MD5_HMAC;
			break;

		case SMW_HASH_ALGO_NAME_SHA1:
			*key_type = CKK_SHA_1_HMAC;
			break;

		case SMW_HASH_ALGO_NAME_SHA224:
			*key_type = CKK_SHA224_HMAC;
			break;

		case SMW_HASH_ALGO_NAME_SHA256:
			*key_type = CKK_SHA256_HMAC;
			break;

		case SMW_HASH_ALGO_NAME_SHA384:
			*key_type = CKK_SHA384_HMAC;
			break;

		case SMW_HASH_ALGO_NAME_SHA512:
			*key_type = CKK_SHA512_HMAC;
			break;

		case SMW_HASH_ALGO_NAME_SHA3_224:
			*key_type = CKK_SHA3_224_HMAC;
			break;

		case SMW_HASH_ALGO_NAME_SHA3_256:
			*key_type = CKK_SHA3_256_HMAC;
			break;

		case SMW_HASH_ALGO_NAME_SHA3_384:
			*key_type = CKK_SHA3_384_HMAC;
			break;

		case SMW_HASH_ALGO_NAME_SHA3_512:
			*key_type = CKK_SHA3_512_HMAC;
			break;

		default:
			goto end;
		}
		break;

	case SMW_KEY_TYPE_NAME_DERIVE:
		*key_type = CKK_GENERIC_SECRET;
		break;

	case SMW_KEY_TYPE_NAME_ED25519:
		*key_type = CKK_EC_EDWARDS;
		break;

	case SMW_KEY_TYPE_NAME_BRAINPOOL_R1:
	case SMW_KEY_TYPE_NAME_BRAINPOOL_T1:
	case SMW_KEY_TYPE_NAME_SECP_R1:
		*key_type = CKK_EC;
		break;

	default:
		goto end;
	}

	ret = CKR_OK;

end:
	return ret;
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
	CK_BBOOL token = CK_TRUE;
	CK_OBJECT_CLASS object_class = CKO_DATA;
	struct librfc2279 unique_id = { 0 };
	struct librfc2279 label = { 0 };
	struct libbytes user_id = { 0 };
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

			ret = get_object_id(&unique_id, &desc->id);
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

		case CKA_TOKEN:
			ret = attr_to_boolean(&token, &attrs[i]);
			if (token)
				desc->attributes =
					SMW_ATTR_PERSISTENCE_PERSISTENT;
			else
				ret = CKR_ATTRIBUTE_VALUE_INVALID;

			break;

		default:
			continue;
		}

		if (ret)
			goto end;
	}

	if (label.string) {
		len = util_rfc2279_to_byte_len(label.string, label.length) +
		      1 /* zero terminated string */;
		if (len) {
			desc->label = malloc(len);
			if (!desc->label) {
				ret = CKR_HOST_MEMORY;
				goto end;
			}

			util_rfc2279_to_byte((CK_CHAR_PTR)desc->label, len,
					     label.string, label.length);
			desc->label[len - 1] = 0;
		}
	}

	if (user_id.number) {
		desc->user_id = malloc(user_id.number + 1);
		if (!desc->user_id) {
			ret = CKR_HOST_MEMORY;
			goto end;
		}

		memcpy(desc->user_id, user_id.array, user_id.number);

		/* zero terminated string */;
		desc->user_id[user_id.number] = 0;
	}

end:
	if (unique_id.string)
		free(unique_id.string);

	if (user_id.array)
		free(user_id.array);

	if (label.string)
		free(label.string);

	if (ret != CKR_OK) {
		if (desc->label)
			free(desc->label);

		if (desc->user_id)
			free(desc->user_id);
	}

	DBG_TRACE("%s returning ret = %lx", __func__, ret);

	return ret;
}

static CK_RV object_descriptor_to_attrs(struct smw_object_descriptor *desc,
					struct smw_key_attributes *key_attr,
					CK_ATTRIBUTE_PTR attrs,
					CK_ULONG_PTR attrs_count)
{
	CK_RV ret = CKR_OK;
	CK_BBOOL bTrue = CK_TRUE;
	CK_BBOOL bFalse = CK_FALSE;
	CK_OBJECT_CLASS object_class = CKO_DATA;
	CK_KEY_TYPE key_type = CKK_RSA;
	CK_ULONG obj_length = 0;
	struct libbytes label = { 0 };
	CK_ULONG attrs_index = 0;
	struct smw_key_descriptor *key = &desc->key;
	struct smw_data_descriptor *data = &desc->data;

	if (desc->label) {
		label.array = (CK_BYTE_PTR)desc->label;
		label.number = strlen(desc->label);
		if (attrs) {
			attrs[attrs_index].type = CKA_LABEL;
			ret = byte_array_to_attr(&attrs[attrs_index], &label);
			if (ret != CKR_OK)
				goto end;
		}

		attrs_index++;
	}

	switch (desc->attributes) {
	case SMW_ATTR_PERSISTENCE_PERSISTENT:
	case SMW_ATTR_PERSISTENCE_PERMANENT:
		if (attrs) {
			attrs[attrs_index].type = CKA_TOKEN;
			ret = boolean_to_attr(&attrs[attrs_index], &bTrue);
		}

		attrs_index++;
		break;

	case SMW_ATTR_PERSISTENCE_TRANSIENT:
		if (attrs) {
			attrs[attrs_index].type = CKA_TOKEN;
			ret = boolean_to_attr(&attrs[attrs_index], &bFalse);
		}

		attrs_index++;
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
		obj_length = key->security_size;
		if (attrs) {
			attrs[attrs_index].type = CKA_VALUE_LEN;
			ret = ulong_to_attr(&attrs[attrs_index], &obj_length);
			if (ret != CKR_OK)
				goto end;
		}

		attrs_index++;

		ret = get_pkcs11_key_type(key->type_name,
					  key_attr->permitted_algo, &key_type);
		if (ret != CKR_OK)
			goto end;

		if (attrs) {
			attrs[attrs_index].type = CKA_KEY_TYPE;
			ret = key_to_attr(&attrs[attrs_index], &key_type);
			if (ret != CKR_OK)
				goto end;
		}

		attrs_index++;

		break;

	case SMW_OBJECT_TYPE_NAME_DATA:
		obj_length = data->length;
		if (attrs) {
			attrs[attrs_index].type = CKA_VALUE_LEN;
			ret = ulong_to_attr(&attrs[attrs_index], &obj_length);
			if (ret != CKR_OK)
				goto end;
		}

		attrs_index++;

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

	if (attrs) {
		attrs[attrs_index].type = CKA_CLASS;
		ret = class_to_attr(&attrs[attrs_index], &object_class);
		if (ret != CKR_OK)
			goto end;
	}

	attrs_index++;

	if (desc->user_id) {
		if (attrs) {
			if (object_class == CKO_DATA)
				attrs[attrs_index].type = CKA_OBJECT_ID;
			else
				attrs[attrs_index].type = CKA_ID;

			if (attrs[attrs_index].ulValueLen <
			    strlen(desc->user_id))
				attrs[attrs_index].ulValueLen =
					strlen(desc->user_id);
			else
				memcpy(attrs[attrs_index].pValue, desc->user_id,
				       strlen(desc->user_id));
		}

		attrs_index++;
	}

	*attrs_count = attrs_index;

	ret = CKR_OK;

end:
	DBG_TRACE("%s returning ret = %lx", __func__, ret);

	return ret;
}

static void free_attrs(CK_ATTRIBUTE_PTR attrs, CK_ULONG nb_attrs)
{
	unsigned int idx = 0;

	for (; idx < nb_attrs; idx++)
		if (attrs[idx].pValue)
			free(attrs[idx].pValue);

	free(attrs);
}

CK_RV obj_db_get(struct libobj_obj *obj,
		 struct smw_object_descriptor *descriptor)
{
	CK_RV ret = CKR_OBJECT_HANDLE_INVALID;
	enum smw_status_code status = SMW_STATUS_OK;
	struct libobj_storage *obj_storage = get_object_from(obj);

	if (!obj)
		return CKR_ARGUMENTS_BAD;

	if (obj_storage->token)
		descriptor->attributes = SMW_ATTR_PERSISTENCE_PERSISTENT;
	else
		descriptor->attributes = SMW_ATTR_PERSISTENCE_TRANSIENT;

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
		ret = key_get_id(&descriptor->id, obj);
		break;

	case CKO_DATA:
		ret = data_get_id(&descriptor->id, obj);
		break;

	default:
		break;
	}

	if (ret != CKR_OK)
		return ret;

	if (!descriptor->id)
		return CKR_OBJECT_HANDLE_INVALID;

	status = smw_find_object_db(descriptor);
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
	struct smw_object_descriptor descriptor = { 0 };

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
			descriptor.user_id = malloc(data->id.number + 1);
			if (!descriptor.user_id) {
				ret = CKR_HOST_MEMORY;
				goto end;
			}

			memcpy(descriptor.user_id, data->id.array,
			       data->id.number);

			/* zero terminated string */;
			descriptor.user_id[data->id.number] = 0;
		}

		break;

	case CKO_PRIVATE_KEY:
	case CKO_PUBLIC_KEY:
	case CKO_SECRET_KEY:
		key = get_subobj_from(obj, storage);
		if (key && key->id.number) {
			descriptor.user_id = malloc(key->id.number + 1);
			if (!descriptor.user_id) {
				ret = CKR_HOST_MEMORY;
				goto end;
			}

			memcpy(descriptor.user_id, key->id.array,
			       key->id.number);

			/* zero terminated string */;
			descriptor.user_id[key->id.number] = 0;
		}

		break;

	default:
		break;
	}

	status = smw_update_object_db(&descriptor);
	if (status != SMW_STATUS_OK)
		ret = smw_status_to_ck_rv(status);

end:
	if (label.array)
		free(label.array);

	if (descriptor.user_id)
		free(descriptor.user_id);

	return ret;
}

CK_RV obj_db_retrieve(CK_SESSION_HANDLE hsession, CK_ATTRIBUTE_PTR attrs,
		      CK_ULONG nb_attrs, CK_ULONG *pnb_retrieved)
{
	CK_RV ret = CKR_OK;
	void *find_ctx = NULL;
	int status = SMW_STATUS_OK;
	struct smw_object_descriptor descriptor = { 0 };
	struct smw_key_attributes *key_attr = NULL;
	struct smw_get_key_attributes_args attr_args = { 0 };
	CK_OBJECT_HANDLE hObj = CK_INVALID_HANDLE;
	CK_ATTRIBUTE_PTR attributes = NULL_PTR;
	CK_ULONG attributes_count = 0;
	CK_ULONG nb_retrieved = 0;
	CK_OBJECT_CLASS object_class = CKO_DATA;
	CK_SLOT_ID slotid = 0;
	const struct libdev *devinfo = NULL;
	struct libdevice *dev = NULL;
	struct libobj_obj *libobj = NULL;
	struct libobj_list *list = NULL;
	bool class_found = false;
	unsigned int i = 0;
	unsigned int k = 0;
	bool is_present = false;
	unsigned int nb_match = 0;

	if (!pnb_retrieved)
		return CKR_ARGUMENTS_BAD;

	*pnb_retrieved = 0;

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

	ret = libsess_get_objects(hsession, &list);
	if (ret != CKR_OK)
		goto end;

	ret = attrs_to_object_descriptor(&descriptor, attrs, nb_attrs);
	if (ret != CKR_OK) {
		/*
		 *  Ignore CKA_TOKEN = false attribute.
		 */
		if (ret == CKR_ATTRIBUTE_VALUE_INVALID)
			ret = CKR_OK;
		goto end;
	}

	/*
	 * Only retrieve persistent token object.
	 */
	descriptor.attributes =
		SMW_ATTR_SET_PERSISTENCE(descriptor.attributes,
					 SMW_ATTR_PERSISTENCE_PERSISTENT);

	for (; i < nb_attrs; i++) {
		if (attrs[i].type == CKA_CLASS) {
			ret = attr_to_class(&object_class, &attrs[i]);
			if (ret != CKR_OK)
				goto end;

			class_found = true;
			break;
		}
	}

	status = smw_find_object_db_init(&find_ctx, descriptor.attributes,
					 &descriptor);
	if (status != SMW_STATUS_OK)
		goto end;

	cleanup_smw_object_descriptor(&descriptor);

	while (smw_find_object_db_next(find_ctx, &descriptor) ==
	       SMW_STATUS_OK) {
		/*
		 * Look in token objects
		 */
		is_present = false;
		for (libobj = LIST_FIRST(&dev->objects); libobj;
		     libobj = LIST_NEXT(libobj)) {
			ret = obj_match_descriptor(libobj, &descriptor,
						   &is_present);
			if (ret != CKR_OK)
				goto end;

			if (is_present) {
				if (class_found) {
					if (libobj->class == object_class)
						break;

					is_present = false;
				} else {
					break;
				}
			}
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

			key_attr = &attr_args.key_attributes;
			break;

		default:
			break;
		}

		/* Get number of attributes */
		ret = object_descriptor_to_attrs(&descriptor, key_attr,
						 attributes, &attributes_count);
		if (ret != CKR_OK)
			goto end;

		attributes = calloc(1, attributes_count * sizeof(CK_ATTRIBUTE));
		if (!attributes)
			return CKR_HOST_MEMORY;

		/* Get size of attributes values */
		ret = object_descriptor_to_attrs(&descriptor, key_attr,
						 attributes, &attributes_count);
		if (ret != CKR_OK)
			goto end;

		for (i = 0; i < attributes_count; i++)
			if (!attributes[i].pValue)
				attributes[i].pValue =
					calloc(1, attributes[i].ulValueLen);

		/* Get attributes values */
		ret = object_descriptor_to_attrs(&descriptor, key_attr,
						 attributes, &attributes_count);
		if (ret != CKR_OK)
			goto end;

		if (class_found) {
			for (i = 0; i < attributes_count; i++) {
				if (attributes[i].type == CKA_CLASS) {
					class_to_attr(&attributes[i],
						      &object_class);
					break;
				}
			}
		}

		nb_match = 0;
		for (k = 0; k < nb_attrs; k++) {
			/*
			 * Unique ID attribute could not be define when
			 * creating an object
			 */
			if (attrs[k].type == CKA_UNIQUE_ID) {
				nb_match++;
				continue;
			}

			for (i = 0; i < attributes_count; i++) {
				if (attrs[k].type == attributes[i].type) {
					if (attrs[k].ulValueLen ==
						    attributes[i].ulValueLen &&
					    !memcmp(attrs[k].pValue,
						    attributes[i].pValue,
						    attributes[i].ulValueLen)) {
						nb_match++;
						break;
					}
				}
			}
		}

		if (nb_match == nb_attrs) {
			ret = libobj_retrieve(hsession, attributes,
					      attributes_count, &hObj,
					      descriptor.id);
			if (ret != CKR_OK)
				goto end;

			nb_retrieved++;
		}

		free_attrs(attributes, attributes_count);
		attributes = NULL_PTR;
		attributes_count = 0;
		cleanup_smw_object_descriptor(&descriptor);
	}

end:
	*pnb_retrieved = nb_retrieved;

	if (find_ctx)
		status = smw_find_object_db_final(find_ctx);

	if (attributes)
		free_attrs(attributes, attributes_count);

	cleanup_smw_object_descriptor(&descriptor);

	if (ret == CKR_OK)
		ret = smw_status_to_ck_rv(status);

	DBG_TRACE("%s returning ret = %lx", __func__, ret);

	return ret;
}
