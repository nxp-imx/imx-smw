// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2021 NXP
 */

#include <stdlib.h>

#include "attributes.h"
#include "key_ec.h"

#include "lib_device.h"
#include "libobj_types.h"
#include "util.h"

#include "trace.h"

#define EC_KEY_PUBLIC  BIT(0)
#define EC_KEY_PRIVATE BIT(1)
#define EC_KEY_PAIR    (EC_KEY_PUBLIC | EC_KEY_PRIVATE)

enum attr_key_ec_public_list {
	PUB_PARAMS = 0,
	PUB_POINT,
};

const struct template_attr attr_key_ec_public[] = {
	[PUB_PARAMS] = { CKA_EC_PARAMS, 0, MUST, attr_to_byte_array },
	[PUB_POINT] = { CKA_EC_POINT, 0, MUST, attr_to_byte_array },
};

enum attr_key_ec_private_list {
	PRIV_PARAMS = 0,
	PRIV_VALUE,
	PRIV_PUB_POINT,
};

const struct template_attr attr_key_ec_private[] = {
	[PRIV_PARAMS] =
		TATTR(key_ec_pair, params, EC_PARAMS, 0, MUST, byte_array),
	[PRIV_VALUE] = TATTR_P(key_ec_pair, value_d, VALUE, 0, MUST, bignumber),
	[PRIV_PUB_POINT] =
		TATTR(key_ec_pair, point_q, EC_POINT, 0, MUST, byte_array),
};

/**
 * key_ec_allocate() - Allocate and initialize EC keypair
 * @pub_obj: EC Public key object
 * @priv_obj: EC Private key object
 * @type: Type of Key to allocate
 *
 * Allocation and set the @type of key to allocate which is:
 *   EC_KEY_PUBLIC
 *   EC_KEY_PRIVATE
 *   EC_KEY_PAIR
 *
 * return:
 * Key allocated if success
 * NULL otherwise
 */
static struct libobj_key_ec_pair *key_ec_allocate(struct libobj_obj *pub_obj,
						  struct libobj_obj *priv_obj,
						  unsigned int type)
{
	struct libobj_key_ec_pair *key = NULL;

	key = calloc(1, sizeof(*key));
	if (key) {
		key->type = type;

		if (type & EC_KEY_PUBLIC)
			set_subkey_to(pub_obj, key);

		if (type & EC_KEY_PRIVATE)
			set_subkey_to(priv_obj, key);
	}

	DBG_TRACE("Allocated a new EC key (%p) of type %d", key, type);

	return key;
}

/**
 * key_ec_free() - Free private or public key
 * @obj: EC Keypair object
 * @type: Type of key private/public to free
 *
 * Free the key's field related to the request @type.
 *
 * Then, if the requested key @type to free is the same of the @key type:
 *    - Delete the key from SMW subsystem if key'id set
 *    - Free the keypair common fields
 *    - Free the keypair object itself
 *
 * Else key is a keypair, hence switch the key type to the remaining
 * key type part not freed.
 */
static void key_ec_free(struct libobj_obj *obj, unsigned int type)
{
	struct libobj_key_ec_pair *key = get_subkey_from(obj);

	if (!key)
		return;

	switch (type) {
	case EC_KEY_PUBLIC:
		if (key->point_q.array) {
			free(key->point_q.array);
			key->point_q.array = NULL;
		}
		break;

	case EC_KEY_PRIVATE:
		if (key->value_d.value) {
			free(key->value_d.value);
			key->value_d.value = NULL;
		}
		if (key->type == EC_KEY_PRIVATE && key->point_q.array) {
			free(key->point_q.array);
			key->point_q.array = NULL;
		}
		break;
	default:
		return;
	}

	if (key->type == type) {
		if (key->params.array)
			free(key->params.array);

		(void)libdev_delete_key(key->key_id);

		free(key);
	} else {
		key->type &= ~type;
	}

	set_subkey_to(obj, NULL);
}

void key_ec_public_free(struct libobj_obj *obj)
{
	key_ec_free(obj, EC_KEY_PUBLIC);
}

void key_ec_private_free(struct libobj_obj *obj)
{
	key_ec_free(obj, EC_KEY_PRIVATE);
}

CK_RV key_ec_public_create(CK_SESSION_HANDLE hsession, struct libobj_obj *obj,
			   struct libattr_list *attrs)
{
	CK_RV ret;
	struct libobj_key_ec_pair *new_key;

	new_key = key_ec_allocate(obj, NULL, EC_KEY_PUBLIC);
	if (!new_key)
		return CKR_HOST_MEMORY;

	DBG_TRACE("Create a new EC public key (%p)", new_key);

	ret = attr_get_value(&new_key->params, &attr_key_ec_public[PUB_PARAMS],
			     attrs, NO_OVERWRITE);
	if (ret != CKR_OK)
		goto end;

	ret = attr_get_value(&new_key->point_q, &attr_key_ec_public[PUB_POINT],
			     attrs, NO_OVERWRITE);
	if (ret != CKR_OK)
		goto end;

	ret = libdev_import_key(hsession, obj);
	DBG_TRACE("Public Key ID 0x%llX", new_key->key_id);

end:
	if (ret != CKR_OK)
		key_ec_public_free(obj);

	return ret;
}

CK_RV key_ec_private_create(CK_SESSION_HANDLE hsession, struct libobj_obj *obj,
			    struct libattr_list *attrs)
{
	CK_RV ret;
	struct libobj_key_ec_pair *new_key;

	new_key = key_ec_allocate(NULL, obj, EC_KEY_PRIVATE);
	if (!new_key)
		return CKR_HOST_MEMORY;

	DBG_TRACE("Create a new EC private key (%p)", new_key);

	ret = attr_get_value(&new_key->params,
			     &attr_key_ec_private[PRIV_PARAMS], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		goto end;

	ret = attr_get_value(&new_key->value_d,
			     &attr_key_ec_private[PRIV_VALUE], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		goto end;

	/*
	 * Private key required the public point to be imported
	 * in token.
	 */
	ret = attr_get_value(new_key, &attr_key_ec_private[PRIV_PUB_POINT],
			     attrs, NO_OVERWRITE);
	if (ret != CKR_OK)
		goto end;

	ret = libdev_import_key(hsession, obj);
	DBG_TRACE("Private Key ID 0x%llX", new_key->key_id);

end:
	if (ret != CKR_OK)
		key_ec_private_free(obj);

	return ret;
}

CK_RV key_ec_keypair_generate(CK_SESSION_HANDLE hsession, CK_MECHANISM_PTR mech,
			      struct libobj_obj *pub_obj,
			      struct libattr_list *pub_attrs,
			      struct libobj_obj *priv_obj,
			      struct libattr_list *priv_attrs)
{
	(void)hsession;
	(void)mech;
	CK_RV ret;
	struct libobj_key_ec_pair *keypair;

	keypair = key_ec_allocate(pub_obj, priv_obj, EC_KEY_PAIR);
	if (!keypair)
		return CKR_HOST_MEMORY;

	DBG_TRACE("Generate an EC keypair (%p)", keypair);

	/* Verify the public key attributes */
	ret = attr_get_value(&keypair->params, &attr_key_ec_public[PUB_PARAMS],
			     pub_attrs, NO_OVERWRITE);
	if (ret != CKR_OK)
		goto end;

	ret = attr_get_value(&keypair->point_q, &attr_key_ec_public[PUB_POINT],
			     pub_attrs, MUST_NOT);
	if (ret != CKR_OK)
		goto end;

	/* Verify the private key attributes */
	ret = attr_get_value(&keypair->params,
			     &attr_key_ec_private[PRIV_PARAMS], priv_attrs,
			     MUST_NOT);
	if (ret != CKR_OK)
		goto end;

	ret = attr_get_value(&keypair->value_d,
			     &attr_key_ec_private[PRIV_VALUE], priv_attrs,
			     MUST_NOT);
	if (ret != CKR_OK)
		goto end;

	ret = libdev_operate_mechanism(hsession, mech, priv_obj);
	DBG_TRACE("Key Pair ID 0x%llX", keypair->key_id);

end:
	if (ret != CKR_OK) {
		key_ec_public_free(pub_obj);
		key_ec_private_free(priv_obj);
	}

	return ret;
}

CK_RV key_ec_get_id(struct libbytes *id, struct libobj_obj *obj,
		    size_t prefix_len)
{
	struct libobj_key_ec_pair *keypair;

	if (!obj || !id)
		return CKR_GENERAL_ERROR;

	keypair = get_subkey_from(obj);

	id->number = prefix_len + sizeof(keypair->key_id);
	id->array = malloc(id->number);
	if (!id->array)
		return CKR_HOST_MEMORY;

	DBG_TRACE("EC Key ID 0x%llX", keypair->key_id);

	TO_CK_BYTES(&id->array[prefix_len], keypair->key_id);

	return CKR_OK;
}
