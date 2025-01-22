// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2025 NXP
 */

#include <stdlib.h>

#include "attributes.h"
#include "key.h"
#include "key_cipher.h"

#include "lib_device.h"
#include "lib_object.h"
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

	if (is_force_destroy_obj(obj) || !is_token_obj(obj, storage))
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

	/* Import only the token key to the subsystem */
	if (is_token_obj(obj, storage)) {
		ret = libdev_import_key(hsession, obj);
		DBG_TRACE("Cipher Key ID 0x%X", new_key->key_id);
	}

end:
	if (ret != CKR_OK)
		key_cipher_free(obj);

	return ret;
}

CK_RV key_cipher_retrieve(CK_SESSION_HANDLE hsession, struct libobj_obj *obj,
			  struct libattr_list *attrs)
{
	CK_RV ret = CKR_OK;
	struct libobj_key_cipher *new_key = NULL;
	struct librfc2279 *unique_id = get_unique_id_obj(obj, storage);

	ret = key_cipher_allocate(obj);
	if (ret != CKR_OK)
		goto end;

	new_key = get_subkey_from(obj);

	DBG_TRACE("Retrieve a Cipher secret key (%p)", new_key);

	/* Verify the key size value is defined */
	ret = attr_get_value(new_key, &attr_key_cipher[SEC_VALUE_LEN], attrs,
			     MUST);
	if (ret != CKR_OK)
		goto end;

	ret = libobj_get_id(unique_id, &new_key->key_id);
	if (ret != CKR_OK)
		goto end;

	/* Get the secret key attributes from the SMW library */
	ret = libdev_get_key_attributes(hsession, obj);
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
	struct libobj_key_cipher *new_key = NULL;
	enum attr_req req = NO_OVERWRITE;

	ret = key_cipher_allocate(obj);
	if (ret != CKR_OK)
		goto end;

	new_key = get_subkey_from(obj);

	DBG_TRACE("Generate a Cipher key (%p)", new_key);

	/* Verify the key attributes */
	ret = attr_get_value(new_key, &attr_key_cipher[SEC_VALUE], attrs,
			     MUST_NOT);
	if (ret != CKR_OK)
		goto end;

	switch (get_key_type(obj)) {
	case CKK_AES:
	case CKK_SM4:
		req = MUST;
		break;

	default:
		break;
	}

	ret = attr_get_value(new_key, &attr_key_cipher[SEC_VALUE_LEN], attrs,
			     req);
	if (ret != CKR_OK)
		goto end;

	/* Generate the secret key with SMW library */
	ret = libdev_operate_mechanism(hsession, mech, obj);
	DBG_TRACE("Cipher Key ID 0x%X", new_key->key_id);

end:
	if (ret != CKR_OK)
		key_cipher_free(obj);

	return ret;
}

CK_RV key_cipher_get_id(unsigned int *id, struct libobj_obj *obj)
{
	struct libobj_key_cipher *key_cipher = NULL;

	if (!obj || !id)
		return CKR_GENERAL_ERROR;

	key_cipher = get_subkey_from(obj);

	DBG_TRACE("Cipher Key ID 0x%X", key_cipher->key_id);

	*id = key_cipher->key_id;

	return CKR_OK;
}

CK_RV key_cipher_derive(CK_SESSION_HANDLE hsession, CK_MECHANISM_PTR mech,
			struct libobj_key_derive_params *derive_params,
			struct libattr_list *attrs)
{
	CK_RV ret = CKR_OK;
	struct libobj_key_cipher *cipher_key = NULL;

	ret = key_cipher_allocate(derive_params->derived_key);
	if (ret != CKR_OK)
		goto end;

	cipher_key = get_subkey_from(derive_params->derived_key);

	DBG_TRACE("Derive a cipher key (%p)", cipher_key);

	/* Verify the key attributes */
	ret = attr_get_value(cipher_key, &attr_key_cipher[SEC_VALUE], attrs,
			     MUST_NOT);
	if (ret != CKR_OK)
		goto end;

	ret = attr_get_value(cipher_key, &attr_key_cipher[SEC_VALUE_LEN], attrs,
			     MUST);
	if (ret != CKR_OK)
		goto end;

	/* Derive a secret key with SMW library */
	ret = libdev_operate_mechanism(hsession, mech, derive_params);

end:
	if (ret != CKR_OK)
		key_cipher_free(derive_params->derived_key);

	return ret;
}
