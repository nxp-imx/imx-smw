// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020 NXP
 */

#include <stdlib.h>

#include "smw_keymgr.h"

#include "attributes.h"
#include "key_cipher.h"
#include "lib_device.h"
#include "util.h"

#include "trace.h"

struct cipher_def {
	CK_KEY_TYPE ck_key_type;
	const char *smw_name;
};

const struct cipher_def ciphers[] = {
	{ CKK_AES, "AES" },
	{ CKK_DES, "DES" },
	{ CKK_DES3, "DES3" },
	{ 0 },
};

struct key_cipher {
	unsigned long long key_id;
	struct libbytes value;
};

enum attr_key_cipher_list {
	SEC_VALUE = 0,
	SEC_VALUE_LEN,
};

const struct template_attr attr_key_cipher[] = {
	[SEC_VALUE] = { CKA_VALUE, 0, MUST, attr_to_byte_array },
	[SEC_VALUE_LEN] = { CKA_VALUE_LEN, sizeof(CK_ULONG), MUST_NOT,
			    attr_to_ulong },
};

/**
 * get_smw_name() - Get the SMW key name
 * @key_type: Cryptoki key type
 *
 * Function converts the Cryptoki key type value to SMW key type name
 *
 * return:
 * Pointer to string name or NULL if not found.
 */
static const char *get_smw_name(CK_KEY_TYPE key_type)
{
	const struct cipher_def *cipher = ciphers;

	while (cipher->smw_name) {
		if (key_type == cipher->ck_key_type)
			break;
		cipher++;
	};

	return cipher->smw_name;
}

/**
 * key_cipher_allocate() - Allocate and initialize Cipher secret key
 *
 * return:
 * Key allocated if success
 * NULL otherwise
 */
static struct key_cipher *key_cipher_allocate(void)
{
	struct key_cipher *key = NULL;

	key = calloc(1, sizeof(*key));

	DBG_TRACE("Allocated a new Cipher secret key (%p)", key);

	return key;
}

void key_cipher_free(void *obj)
{
	struct key_cipher *key = obj;

	if (!key)
		return;

	(void)libdev_delete_key(key->key_id);

	if (key->value.array)
		free(key->value.array);

	free(key);
}

CK_RV key_cipher_create(void **obj, struct libattr_list *attrs)
{
	CK_RV ret;
	struct key_cipher *new_key;

	new_key = key_cipher_allocate();
	if (!new_key)
		return CKR_HOST_MEMORY;

	*obj = new_key;

	DBG_TRACE("Create a new Cipher secret key (%p)", new_key);

	ret = attr_get_value(&new_key->value, &attr_key_cipher[SEC_VALUE],
			     attrs, NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	/* Verify the key size value is not defined */
	ret = attr_get_value(NULL, &attr_key_cipher[SEC_VALUE_LEN], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	return CKR_OK;
}

CK_RV key_cipher_generate(CK_SESSION_HANDLE hsession, CK_MECHANISM_PTR mech,
			  CK_KEY_TYPE key_type, void **obj,
			  struct libattr_list *attrs)
{
	CK_RV ret;
	struct key_cipher *key;
	struct smw_generate_key_args gen_args = { 0 };
	struct smw_key_descriptor key_desc = { 0 };
	CK_ULONG key_size_bytes = 0;

	key = key_cipher_allocate();
	if (!key)
		return CKR_HOST_MEMORY;

	*obj = key;

	DBG_TRACE("Generate a Cipher key (%p)", key);

	/* Verify the key attributes */
	ret = attr_get_value(&key->value, &attr_key_cipher[SEC_VALUE], attrs,
			     MUST_NOT);
	if (ret != CKR_OK)
		return ret;

	if (key_type == CKK_AES) {
		ret = attr_get_value(&key_size_bytes,
				     &attr_key_cipher[SEC_VALUE_LEN], attrs,
				     MUST);
	} else {
		ret = attr_get_value(&key_size_bytes,
				     &attr_key_cipher[SEC_VALUE_LEN], attrs,
				     NO_OVERWRITE);
	}

	if (ret != CKR_OK)
		return ret;

	switch (key_type) {
	case CKK_DES:
		key_desc.security_size = 56;
		break;

	case CKK_DES3:
		key_desc.security_size = 168;
		break;

	case CKK_AES:
		if (key_size_bytes != 16 && key_size_bytes != 24 &&
		    key_size_bytes != 32)
			return CKR_ATTRIBUTE_VALUE_INVALID;
		key_desc.security_size = key_size_bytes * 8;
		break;

	default:
		/* This case should never occurred, but ... */
		return CKR_GENERAL_ERROR;
	}

	/* Generate the keypair with SMW library */
	key_desc.type_name = get_smw_name(key_type);
	gen_args.key_descriptor = &key_desc;

	ret = libdev_operate_mechanism(hsession, mech, &gen_args);

	if (ret == CKR_OK) {
		/*
		 * Save the SMW key identifier in key object
		 */
		key->key_id = key_desc.id;
		DBG_TRACE("Cipher Key ID 0x%llX", key->key_id);
	}

	return ret;
}

CK_RV key_cipher_get_id(struct libbytes *id, void *key, size_t prefix_len)
{
	struct key_cipher *key_cipher = key;

	if (!key || !id)
		return CKR_GENERAL_ERROR;

	id->number = prefix_len + sizeof(key_cipher->key_id);
	id->array = malloc(id->number);
	if (!id->array)
		return CKR_HOST_MEMORY;

	DBG_TRACE("Cipher Key ID 0x%llX", key_cipher->key_id);

	TO_CK_BYTES(&id->array[prefix_len], key_cipher->key_id);

	return CKR_OK;
}
