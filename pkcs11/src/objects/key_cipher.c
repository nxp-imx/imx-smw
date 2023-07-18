// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2023 NXP
 */

#include <stdlib.h>

#include "attributes.h"
#include "key_cipher.h"

#include "lib_device.h"
#include "libobj_types.h"
#include "util.h"

#include "trace.h"

enum attr_key_cipher_list {
	SEC_VALUE = 0,
	SEC_VALUE_LEN,
};

const struct template_attr attr_key_cipher[] = {
	[SEC_VALUE] = TATTR_P(key_cipher, value, VALUE, 0, MUST, byte_array),
	[SEC_VALUE_LEN] = TATTR(key_cipher, value_len, VALUE_LEN,
				sizeof(CK_ULONG), MUST_NOT, ulong),
};

/**
 * key_cipher_allocate() - Allocate and initialize Cipher secret key
 * @obj: Cipher key object
 *
 * return:
 * CKR_OK             - Success
 * CKR_HOST_MEMORY    - Out of memory
 */
static CK_RV key_cipher_allocate(struct libobj_obj *obj)
{
	CK_RV ret = CKR_HOST_MEMORY;
	struct libobj_key_cipher *key = NULL;

	key = calloc(1, sizeof(*key));
	if (key) {
		set_subkey_to(obj, key);
		ret = CKR_OK;
	}

	DBG_TRACE("Allocated a new Cipher secret key (%p) (ret=%ld)", key, ret);

	return ret;
}

void key_cipher_free(struct libobj_obj *obj)
{
	struct libobj_key_cipher *key = get_subkey_from(obj);

	if (!key)
		return;

	(void)libdev_delete_key(key->key_id);

	if (key->value.array)
		free(key->value.array);

	free(key);

	set_subkey_to(obj, NULL);
}

CK_RV key_cipher_create(CK_SESSION_HANDLE hsession, struct libobj_obj *obj,
			struct libattr_list *attrs)
{
	CK_RV ret = CKR_OK;
	struct libobj_key_cipher *new_key = NULL;

	ret = key_cipher_allocate(obj);
	if (ret != CKR_OK)
		goto end;

	new_key = get_subkey_from(obj);

	DBG_TRACE("Create a new Cipher secret key (%p)", new_key);

	ret = attr_get_value(new_key, &attr_key_cipher[SEC_VALUE], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		goto end;

	/* Verify the key size value is not defined */
	ret = attr_get_value(new_key, &attr_key_cipher[SEC_VALUE_LEN], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		goto end;

	/* Set the Key object value length equal to the buffer value length */
	new_key->value_len = new_key->value.number;

	/* Import the secret key in the SMW library session's subsystem */
	ret = libdev_import_key(hsession, obj);
	DBG_TRACE("Cipher Key ID 0x%X", new_key->key_id);

end:
	if (ret != CKR_OK)
		key_cipher_free(obj);

	return ret;
}

CK_RV key_cipher_get_attribute(CK_ATTRIBUTE_PTR attr,
			       const struct libobj_obj *obj, bool protect)
{
	CK_RV ret = CKR_OK;

	DBG_TRACE("Get attribute type=%#lx protected=%s", attr->type,
		  protect ? "YES" : "NO");

	ret = attr_get_obj_prot_value(attr, attr_key_cipher,
				      ARRAY_SIZE(attr_key_cipher),
				      get_subkey_from(obj), protect);
	if (ret == CKR_ATTRIBUTE_TYPE_INVALID)
		attr->ulValueLen = CK_UNAVAILABLE_INFORMATION;

	DBG_TRACE("Get attribute type=%#lx ret %ld", attr->type, ret);
	return ret;
}

CK_RV key_cipher_modify_attribute(CK_ATTRIBUTE_PTR attr, struct libobj_obj *obj)
{
	CK_RV ret = CKR_OK;

	DBG_TRACE("Modify attribute type=%#lx", attr->type);

	ret = attr_modify_obj_value(attr, attr_key_cipher,
				    ARRAY_SIZE(attr_key_cipher),
				    get_subkey_from(obj));

	DBG_TRACE("Modify attribute type=%#lx ret %ld", attr->type, ret);
	return ret;
}

CK_RV key_cipher_generate(CK_SESSION_HANDLE hsession, CK_MECHANISM_PTR mech,
			  struct libobj_obj *obj, struct libattr_list *attrs)
{
	CK_RV ret = CKR_OK;
	struct libobj_key_cipher *key = NULL;

	ret = key_cipher_allocate(obj);
	if (ret != CKR_OK)
		goto end;

	key = get_subkey_from(obj);

	DBG_TRACE("Generate a Cipher key (%p)", key);

	/* Verify the key attributes */
	ret = attr_get_value(key, &attr_key_cipher[SEC_VALUE], attrs, MUST_NOT);
	if (ret != CKR_OK)
		goto end;

	if (get_key_type(obj) == CKK_AES)
		ret = attr_get_value(key, &attr_key_cipher[SEC_VALUE_LEN],
				     attrs, MUST);
	else
		ret = attr_get_value(key, &attr_key_cipher[SEC_VALUE_LEN],
				     attrs, NO_OVERWRITE);

	if (ret != CKR_OK)
		goto end;

	/* Generate the secret key with SMW library */
	ret = libdev_operate_mechanism(hsession, mech, obj);
	DBG_TRACE("Cipher Key ID 0x%X", key->key_id);

end:
	if (ret != CKR_OK)
		key_cipher_free(obj);

	return ret;
}

CK_RV key_cipher_get_id(struct libbytes *id, struct libobj_obj *obj,
			size_t prefix_len)
{
	struct libobj_key_cipher *key_cipher = NULL;

	if (!obj || !id)
		return CKR_GENERAL_ERROR;

	key_cipher = get_subkey_from(obj);

	id->number = prefix_len + sizeof(key_cipher->key_id);
	id->array = malloc(id->number);
	if (!id->array)
		return CKR_HOST_MEMORY;

	DBG_TRACE("Cipher Key ID 0x%X", key_cipher->key_id);

	TO_CK_BYTES(&id->array[prefix_len], key_cipher->key_id);

	return CKR_OK;
}
