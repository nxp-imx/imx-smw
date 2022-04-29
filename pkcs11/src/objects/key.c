// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2022 NXP
 */

#include <stdlib.h>

#include "attributes.h"
#include "key.h"
#include "key_cipher.h"
#include "key_ec.h"
#include "key_rsa.h"

#include "lib_session.h"
#include "libobj_types.h"
#include "util.h"

#include "trace.h"

enum attr_key_common_list {
	KEY_TYPE = 0,
	KEY_ID,
	KEY_START_DATE,
	KEY_END_DATE,
	KEY_DERIVE,
	KEY_LOCAL,
	KEY_GEN_MECH,
	KEY_ALLOWED_MECH,
};

const struct template_attr attr_key_common[] = {
	[KEY_TYPE] = TATTR(key, type, KEY_TYPE, sizeof(CK_KEY_TYPE), MUST, key),
	[KEY_ID] = TATTR_M(key, id, ID, 0, OPTIONAL, byte_array),
	[KEY_START_DATE] = TATTR_M(key, start_date, START_DATE, sizeof(CK_DATE),
				   OPTIONAL, date),
	[KEY_END_DATE] = TATTR_M(key, end_date, END_DATE, sizeof(CK_DATE),
				 OPTIONAL, date),
	[KEY_DERIVE] = TATTR_M(key, derive, DERIVE, sizeof(CK_BBOOL), OPTIONAL,
			       boolean),
	[KEY_LOCAL] =
		TATTR(key, local, LOCAL, sizeof(CK_BBOOL), OPTIONAL, boolean),
	[KEY_GEN_MECH] = TATTR(key, gen_mech, KEY_GEN_MECHANISM,
			       sizeof(CK_MECHANISM_TYPE), OPTIONAL, mech),
	[KEY_ALLOWED_MECH] =
		TATTR(key, mech, ALLOWED_MECHANISMS, 0, OPTIONAL, mech_list),
};

enum attr_key_public_list {
	PUB_SUBJECT = 0,
	PUB_ENCRYPT,
	PUB_VERIFY,
	PUB_VERIFY_RECOVER,
	PUB_TRUSTED,
	PUB_WRAP,
	PUB_WRAP_TEMPLATE,
	PUB_INFO
};

const struct template_attr attr_key_public[] = {
	[PUB_SUBJECT] =
		TATTR_M(key_public, subject, SUBJECT, 0, OPTIONAL, byte_array),
	[PUB_ENCRYPT] = TATTR_M(key_public, encrypt, ENCRYPT, sizeof(CK_BBOOL),
				OPTIONAL, boolean),
	[PUB_VERIFY] = TATTR_M(key_public, verify, VERIFY, sizeof(CK_BBOOL),
			       OPTIONAL, boolean),
	[PUB_VERIFY_RECOVER] =
		TATTR_M(key_public, verify_recover, VERIFY_RECOVER,
			sizeof(CK_BBOOL), OPTIONAL, boolean),
	[PUB_TRUSTED] = TATTR(key_public, trusted, TRUSTED, sizeof(CK_BBOOL),
			      OPTIONAL, boolean),
	[PUB_WRAP] = TATTR_M(key_public, wrap, WRAP, sizeof(CK_BBOOL), OPTIONAL,
			     boolean),
	[PUB_WRAP_TEMPLATE] = TATTR(key_public, wrap_attrs, WRAP_TEMPLATE, 0,
				    OPTIONAL, attr_list),
	[PUB_INFO] = TATTR(key_public, info, PUBLIC_KEY_INFO, 0, OPTIONAL,
			   byte_array),
};

enum attr_key_private_list {
	PRIV_SUBJECT = 0,
	PRIV_SENSITIVE,
	PRIV_ALWAYS_SENSITIVE,
	PRIV_DECRYPT,
	PRIV_SIGN,
	PRIV_SIGN_RECOVER,
	PRIV_EXTRACTABLE,
	PRIV_NEVER_EXTRACTABLE,
	PRIV_WRAP_WITH_TRUSTED,
	PRIV_UNWRAP,
	PRIV_UNWRAP_TEMPLATE,
	PRIV_ALWAYS_AUTHENTICATE,
	PRIV_INFO
};

const struct template_attr attr_key_private[] = {
	[PRIV_SUBJECT] =
		TATTR_M(key_private, subject, SUBJECT, 0, OPTIONAL, byte_array),
	[PRIV_SENSITIVE] =
		TATTR_MS(key_private, sensitive, SENSITIVE, sizeof(CK_BBOOL),
			 OPTIONAL, boolean, true_only),
	[PRIV_ALWAYS_SENSITIVE] =
		TATTR(key_private, always_sensitive, ALWAYS_SENSITIVE,
		      sizeof(CK_BBOOL), OPTIONAL, boolean),
	[PRIV_DECRYPT] = TATTR_M(key_private, decrypt, DECRYPT,
				 sizeof(CK_BBOOL), OPTIONAL, boolean),
	[PRIV_SIGN] = TATTR_M(key_private, sign, SIGN, sizeof(CK_BBOOL),
			      OPTIONAL, boolean),
	[PRIV_SIGN_RECOVER] = TATTR_M(key_private, sign_recover, SIGN_RECOVER,
				      sizeof(CK_BBOOL), OPTIONAL, boolean),
	[PRIV_EXTRACTABLE] =
		TATTR_MS(key_private, extractable, EXTRACTABLE,
			 sizeof(CK_BBOOL), OPTIONAL, boolean, false_only),
	[PRIV_NEVER_EXTRACTABLE] =
		TATTR(key_private, never_extractable, NEVER_EXTRACTABLE,
		      sizeof(CK_BBOOL), OPTIONAL, boolean),
	[PRIV_WRAP_WITH_TRUSTED] =
		TATTR(key_private, wrap_with_trusted, WRAP_WITH_TRUSTED,
		      sizeof(CK_BBOOL), OPTIONAL, boolean),
	[PRIV_UNWRAP] = TATTR_M(key_private, unwrap, UNWRAP, sizeof(CK_BBOOL),
				OPTIONAL, boolean),
	[PRIV_UNWRAP_TEMPLATE] = TATTR(key_private, unwrap_attrs,
				       UNWRAP_TEMPLATE, 0, OPTIONAL, attr_list),
	[PRIV_ALWAYS_AUTHENTICATE] =
		TATTR(key_private, always_authenticate, ALWAYS_AUTHENTICATE,
		      sizeof(CK_BBOOL), OPTIONAL, boolean),
	[PRIV_INFO] = TATTR_M(key_private, info, PUBLIC_KEY_INFO, 0, OPTIONAL,
			      byte_array),
};

enum attr_key_secret_list {
	SECR_SENSITIVE = 0,
	SECR_ALWAYS_SENSITIVE,
	SECR_ENCRYPT,
	SECR_DECRYPT,
	SECR_SIGN,
	SECR_VERIFY,
	SECR_EXTRACTABLE,
	SECR_NEVER_EXTRACTABLE,
	SECR_WRAP,
	SECR_WRAP_TEMPLATE,
	SECR_WRAP_WITH_TRUSTED,
	SECR_UNWRAP,
	SECR_UNWRAP_TEMPLATE,
	SECR_TRUSTED,
	SECR_CHECK_VALUE,
};

const struct template_attr attr_key_secret[] = {
	[SECR_SENSITIVE] =
		TATTR_MS(key_secret, sensitive, SENSITIVE, sizeof(CK_BBOOL),
			 OPTIONAL, boolean, true_only),
	[SECR_ALWAYS_SENSITIVE] =
		TATTR(key_secret, always_sensitive, ALWAYS_SENSITIVE,
		      sizeof(CK_BBOOL), OPTIONAL, boolean),
	[SECR_ENCRYPT] = TATTR_M(key_secret, encrypt, ENCRYPT, sizeof(CK_BBOOL),
				 OPTIONAL, boolean),
	[SECR_DECRYPT] = TATTR_M(key_secret, decrypt, DECRYPT, sizeof(CK_BBOOL),
				 OPTIONAL, boolean),
	[SECR_SIGN] = TATTR_M(key_secret, sign, SIGN, sizeof(CK_BBOOL),
			      OPTIONAL, boolean),
	[SECR_VERIFY] = TATTR_M(key_secret, verify, VERIFY, sizeof(CK_BBOOL),
				OPTIONAL, boolean),
	[SECR_EXTRACTABLE] = TATTR(key_secret, extractable, EXTRACTABLE,
				   sizeof(CK_BBOOL), OPTIONAL, boolean),
	[SECR_NEVER_EXTRACTABLE] =
		TATTR_MS(key_secret, never_extractable, NEVER_EXTRACTABLE,
			 sizeof(CK_BBOOL), OPTIONAL, boolean, false_only),
	[SECR_WRAP] = TATTR_M(key_secret, wrap, WRAP, sizeof(CK_BBOOL),
			      OPTIONAL, boolean),
	[SECR_WRAP_TEMPLATE] = TATTR(key_secret, wrap_attrs, WRAP_TEMPLATE, 0,
				     OPTIONAL, attr_list),
	[SECR_WRAP_WITH_TRUSTED] =
		TATTR(key_secret, wrap_with_trusted, WRAP_WITH_TRUSTED,
		      sizeof(CK_BBOOL), OPTIONAL, boolean),
	[SECR_UNWRAP] = TATTR_M(key_secret, unwrap, UNWRAP, sizeof(CK_BBOOL),
				OPTIONAL, boolean),
	[SECR_UNWRAP_TEMPLATE] = TATTR(key_secret, unwrap_attrs,
				       UNWRAP_TEMPLATE, 0, OPTIONAL, attr_list),
	[SECR_TRUSTED] = TATTR(key_secret, trusted, TRUSTED, sizeof(CK_BBOOL),
			       OPTIONAL, boolean),
	[SECR_CHECK_VALUE] = TATTR(key_secret, checksum, CHECK_VALUE,
				   3 * sizeof(CK_BYTE), OPTIONAL, byte_array),
};

/**
 * key_allocate() - Allocate and initialize common key
 * @obj: Key object
 *
 * return:
 * Reference to allocated common key if success
 * NULL otherwise
 */
static struct libobj_key *key_allocate(struct libobj_obj *obj)
{
	struct libobj_key *key;

	key = calloc(1, sizeof(*key));
	if (key)
		set_subobj_to(obj, storage, key);

	DBG_TRACE("Allocated a new key (%p)", key);
	return key;
}

/**
 * key_secret_allocate() - Allocate and initialize secret key
 * @key: Key allocated
 *
 * return:
 * CKR_HOST_MEMORY - Out of memory
 * CKR_OK          - Success
 */
static CK_RV key_secret_allocate(struct libobj_key_secret **key)
{
	*key = calloc(1, sizeof(**key));
	if (!*key)
		return CKR_HOST_MEMORY;

	DBG_TRACE("Allocated a new secret key (%p)", *key);

	return CKR_OK;
}

/**
 * key_private_allocate() - Allocate and initialize private key
 * @key: Key allocated
 *
 * return:
 * CKR_HOST_MEMORY - Out of memory
 * CKR_OK          - Success
 */
static CK_RV key_private_allocate(struct libobj_key_private **key)
{
	*key = calloc(1, sizeof(**key));
	if (!*key)
		return CKR_HOST_MEMORY;

	DBG_TRACE("Allocated a new private key (%p)", *key);

	return CKR_OK;
}

/**
 * key_public_allocate() - Allocate and initialize public key
 * @key: Key allocated
 *
 * return:
 * CKR_HOST_MEMORY - Out of memory
 * CKR_OK          - Success
 */
static CK_RV key_public_allocate(struct libobj_key_public **key)
{
	*key = calloc(1, sizeof(**key));
	if (!*key)
		return CKR_HOST_MEMORY;

	DBG_TRACE("Allocated a new public key (%p)", *key);

	return CKR_OK;
}

/**
 * key_secret_free() - Free a secret key object
 * @obj: Key object
 */
static void key_secret_free(struct libobj_obj *obj)
{
	struct libobj_key_secret *sec_key = get_key_from(obj);

	if (!sec_key)
		return;

	switch (get_key_type(obj)) {
	case CKK_AES:
	case CKK_DES:
	case CKK_DES3:
		key_cipher_free(obj);
		break;

	default:
		break;
	}

	DBG_TRACE("Free secret key (%p)", sec_key);

	if (sec_key->wrap_attrs.attr)
		free(sec_key->wrap_attrs.attr);

	if (sec_key->unwrap_attrs.attr)
		free(sec_key->unwrap_attrs.attr);

	if (sec_key->checksum.array)
		free(sec_key->checksum.array);

	free(sec_key);
}

/**
 * key_private_free() - Free a private key object
 * @obj: Key object
 */
static void key_private_free(struct libobj_obj *obj)
{
	struct libobj_key_private *priv_key = get_key_from(obj);

	if (!priv_key)
		return;

	DBG_TRACE("Free private key (%p)", priv_key);

	switch (get_key_type(obj)) {
	case CKK_EC:
		key_ec_private_free(obj);
		break;

	case CKK_RSA:
		key_rsa_private_free(obj);
		break;

	default:
		break;
	}

	if (priv_key->subject.array)
		free(priv_key->subject.array);

	if (priv_key->unwrap_attrs.attr)
		free(priv_key->unwrap_attrs.attr);

	if (priv_key->info.array)
		free(priv_key->info.array);

	free(priv_key);
}

/**
 * key_public_free() - Free a public key object
 * @obj: Key object
 */
static void key_public_free(struct libobj_obj *obj)
{
	struct libobj_key_public *pub_key = get_key_from(obj);

	if (!pub_key)
		return;

	DBG_TRACE("Free public key (%p)", pub_key);

	switch (get_key_type(obj)) {
	case CKK_EC:
		key_ec_public_free(obj);
		break;

	case CKK_RSA:
		key_rsa_public_free(obj);
		break;

	default:
		break;
	}

	if (pub_key->subject.array)
		free(pub_key->subject.array);

	if (pub_key->wrap_attrs.attr)
		free(pub_key->wrap_attrs.attr);

	if (pub_key->info.array)
		free(pub_key->info.array);

	free(pub_key);
}

/**
 * key_secret_new() - Create a new secret key object
 * @obj: Key object
 * @attrs: List of object attributes
 *
 * Allocate a new secret key object and setup it with given object
 * attribute list.
 *
 * return:
 * CKR_FUNCTION_FAILED           - Function failure
 * CKR_TEMPLATE_INCOMPLETE       - Attribute type not found
 * CKR_TEMPLATE_INCONSISTENT     - Attribute type must not be defined
 * CKR_ATTRIBUTE_VALUE_INVALID   - Attribute length is not valid
 * CKR_HOST_MEMORY               - Allocation error
 * CKR_OK                        - Success
 */
static CK_RV key_secret_new(struct libobj_obj *obj, struct libattr_list *attrs)
{
	CK_RV ret;
	struct libobj_key_secret *new_key = NULL;

	ret = key_secret_allocate(&new_key);
	if (ret != CKR_OK)
		return ret;

	set_key_to(obj, new_key);

	DBG_TRACE("Create a new secret key (%p)", new_key);

	ret = attr_get_value(new_key, &attr_key_secret[SECR_SENSITIVE], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(new_key, &attr_key_secret[SECR_ALWAYS_SENSITIVE],
			     attrs, MUST_NOT);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(new_key, &attr_key_secret[SECR_ENCRYPT], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(new_key, &attr_key_secret[SECR_DECRYPT], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(new_key, &attr_key_secret[SECR_SIGN], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(new_key, &attr_key_secret[SECR_VERIFY], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(new_key, &attr_key_secret[SECR_EXTRACTABLE], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(new_key, &attr_key_secret[SECR_NEVER_EXTRACTABLE],
			     attrs, MUST_NOT);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(new_key, &attr_key_secret[SECR_WRAP], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(new_key, &attr_key_secret[SECR_WRAP_TEMPLATE],
			     attrs, NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(new_key, &attr_key_secret[SECR_WRAP_WITH_TRUSTED],
			     attrs, NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(new_key, &attr_key_secret[SECR_UNWRAP], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(new_key, &attr_key_secret[SECR_UNWRAP_TEMPLATE],
			     attrs, NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(new_key, &attr_key_secret[SECR_TRUSTED], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(new_key, &attr_key_secret[SECR_CHECK_VALUE], attrs,
			     NO_OVERWRITE);

	return ret;
}

/**
 * key_private_new() - Create a new private key object
 * @obj: Key object
 * @attrs: List of object attributes
 *
 * Allocate a new private key object and setup it with given object
 * attribute list.
 *
 * return:
 * CKR_FUNCTION_FAILED           - Function failure
 * CKR_TEMPLATE_INCOMPLETE       - Attribute type not found
 * CKR_TEMPLATE_INCONSISTENT     - Attribute type must not be defined
 * CKR_ATTRIBUTE_VALUE_INVALID   - Attribute length is not valid
 * CKR_HOST_MEMORY               - Allocation error
 * CKR_OK                        - Success
 */
static CK_RV key_private_new(struct libobj_obj *obj, struct libattr_list *attrs)
{
	CK_RV ret;
	struct libobj_key_private *new_key = NULL;

	ret = key_private_allocate(&new_key);
	if (ret != CKR_OK)
		return ret;

	set_key_to(obj, new_key);

	DBG_TRACE("Create a new private key (%p)", new_key);

	ret = attr_get_value(new_key, &attr_key_private[PRIV_SUBJECT], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(new_key, &attr_key_private[PRIV_SENSITIVE], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(new_key, &attr_key_private[PRIV_ALWAYS_SENSITIVE],
			     attrs, MUST_NOT);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(new_key, &attr_key_private[PRIV_DECRYPT], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(new_key, &attr_key_private[PRIV_SIGN], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(new_key, &attr_key_private[PRIV_SIGN_RECOVER],
			     attrs, NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(new_key, &attr_key_private[PRIV_EXTRACTABLE],
			     attrs, NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(new_key, &attr_key_private[PRIV_NEVER_EXTRACTABLE],
			     attrs, MUST_NOT);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(new_key, &attr_key_private[PRIV_WRAP_WITH_TRUSTED],
			     attrs, NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(new_key, &attr_key_private[PRIV_UNWRAP], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(new_key, &attr_key_private[PRIV_UNWRAP_TEMPLATE],
			     attrs, NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(new_key, &attr_key_private[PRIV_INFO], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(new_key,
			     &attr_key_private[PRIV_ALWAYS_AUTHENTICATE], attrs,
			     NO_OVERWRITE);

	return ret;
}

/**
 * key_public_new() - Create a new public key object
 * @hsession: Session handle
 * @obj: Key object
 * @attrs: List of object attributes
 *
 * Allocate a new public key object and setup it with given object
 * attribute list.
 *
 * return:
 * CKR_CRYPTOKI_NOT_INITIALIZED  - Context not initialized
 * CKR_GENERAL_ERROR             - No slot defined
 * CKR_SESSION_HANDLE_INVALID    - Session Handle invalid
 * CKR_ATTRIBUTE_READ_ONLY       - One attribute is read only
 * CKR_FUNCTION_FAILED           - Function failure
 * CKR_TEMPLATE_INCOMPLETE       - Attribute type not found
 * CKR_TEMPLATE_INCONSISTENT     - Attribute type must not be defined
 * CKR_ATTRIBUTE_VALUE_INVALID   - Attribute length is not valid
 * CKR_HOST_MEMORY               - Allocation error
 * CKR_OK                        - Success
 */
static CK_RV key_public_new(CK_SESSION_HANDLE hsession, struct libobj_obj *obj,
			    struct libattr_list *attrs)
{
	CK_RV ret;
	struct libobj_key_public *new_key = NULL;
	CK_USER_TYPE user;

	ret = key_public_allocate(&new_key);
	if (ret != CKR_OK)
		return ret;

	set_key_to(obj, new_key);

	DBG_TRACE("Create a new public key (%p)", new_key);

	ret = attr_get_value(new_key, &attr_key_public[PUB_SUBJECT], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(new_key, &attr_key_public[PUB_ENCRYPT], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(new_key, &attr_key_public[PUB_VERIFY], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(new_key, &attr_key_public[PUB_VERIFY_RECOVER],
			     attrs, NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(new_key, &attr_key_public[PUB_TRUSTED], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	if (new_key->trusted) {
		ret = libsess_get_user(hsession, &user);
		if (ret != CKR_OK)
			return ret;

		if (user != CKU_SO)
			return CKR_ATTRIBUTE_READ_ONLY;
	}

	ret = attr_get_value(new_key, &attr_key_public[PUB_WRAP], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(new_key, &attr_key_public[PUB_WRAP_TEMPLATE],
			     attrs, NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(new_key, &attr_key_public[PUB_INFO], attrs,
			     NO_OVERWRITE);

	return ret;
}

/**
 * subkey_secret_create() - Create a secret subkey object
 * @hsession: Session handle
 * @obj: Key object
 * @attrs: List of object attributes
 *
 * Call the key object type creation function.
 *
 * return:
 * CKR_CRYPTOKI_NOT_INITIALIZED  - Context not initialized
 * CKR_GENERAL_ERROR             - No slot defined
 * CKR_SESSION_HANDLE_INVALID    - Session Handle invalid
 * CKR_SLOT_ID_INVALID           - Slot ID is not valid
 * CKR_ATTRIBUTE_VALUE_INVALID   - Attribute value is not valid
 * CKR_FUNCTION_FAILED           - Function failure
 * CKR_TEMPLATE_INCOMPLETE       - Attribute template incomplete
 * CKR_TEMPLATE_INCONSISTENT     - One of the attribute is not valid
 * CKR_HOST_MEMORY               - Allocation error
 * CKR_GENERAL_ERROR             - General error defined
 * CKR_FUNCTION_FAILED           - Function failure
 * CKR_OK                        - Success
 */
static CK_RV subkey_secret_create(CK_SESSION_HANDLE hsession,
				  struct libobj_obj *obj,
				  struct libattr_list *attrs)
{
	CK_RV ret;

	switch (get_key_type(obj)) {
	case CKK_AES:
	case CKK_DES:
	case CKK_DES3:
		ret = key_cipher_create(hsession, obj, attrs);
		break;

	default:
		ret = CKR_FUNCTION_FAILED;
	}

	return ret;
}

/**
 * subkey_secret_get_attribute() - Get an attribute from the secret key
 * @attr: Attribute to get
 * @obj: Key object
 *
 * Get the given attribute @attr from the secret key object,
 * if not present, call the secret key type get attribute function.
 *
 * return:
 * CKR_ATTRIBUTE_SENSITIVE       - Attribute is sensitive
 * CKR_BUFFER_TOO_SMALL          - Attribute length is too small
 * CKR_ATTRIBUTE_TYPE_INVALID    - Attribute not found
 * CKR_FUNCTION_FAILED           - Object not supported
 * CKR_OK                        - Success
 */
static CK_RV subkey_secret_get_attribute(CK_ATTRIBUTE_PTR attr,
					 const struct libobj_obj *obj)
{
	CK_RV ret;
	const struct libobj_key_secret *secret_key = get_key_from(obj);
	bool protect = false;

	if (secret_key->sensitive || !secret_key->extractable)
		protect = true;

	DBG_TRACE("Get attribute type=%#lx protected=%s", attr->type,
		  protect ? "YES" : "NO");

	/* Get attribute from the secret key attribute */
	ret = attr_get_obj_prot_value(attr, attr_key_secret,
				      ARRAY_SIZE(attr_key_secret), secret_key,
				      protect);
	if (ret != CKR_ATTRIBUTE_TYPE_INVALID)
		return ret;

	/*
	 * Attribute not present in the secret key object attributes,
	 * try to get it from the specific key type
	 */
	switch (get_key_type(obj)) {
	case CKK_AES:
	case CKK_DES:
	case CKK_DES3:
		ret = key_cipher_get_attribute(attr, obj, protect);
		break;

	default:
		ret = CKR_FUNCTION_FAILED;
	}

	DBG_TRACE("Get attribute type=%#lx ret %ld", attr->type, ret);
	return ret;
}

/**
 * subkey_secret_modify_attribute() - Modify an attribute of the secret key
 * @attr: Attribute to modify
 * @obj: Key object
 *
 * Modify the given attribute @attr of the secret key object,
 * if not present, call the secret key type modify attribute function.
 *
 * return:
 * CKR_ATTRIBUTE_READ_ONLY     - Attribute is read only
 * CKR_ATTRIBUTE_TYPE_INVALID  - Attribute not found
 * CKR_ATTRIBUTE_VALUE_INVALID - Attribute value or length not valid
 * CKR_HOST_MEMORY             - Out of memory
 * CKR_FUNCTION_FAILED           - Object not supported
 * CKR_OK                        - Success
 */
static CK_RV subkey_secret_modify_attribute(CK_ATTRIBUTE_PTR attr,
					    struct libobj_obj *obj)
{
	CK_RV ret;

	DBG_TRACE("Modify attribute type=%#lx", attr->type);

	/* Modifyt attribute of the secret key attribute */
	ret = attr_modify_obj_value(attr, attr_key_secret,
				    ARRAY_SIZE(attr_key_secret),
				    get_key_from(obj));
	if (ret != CKR_ATTRIBUTE_TYPE_INVALID)
		return ret;

	/*
	 * Attribute not present in the secret key object attributes,
	 * try to modify it in the specific key type
	 */
	switch (get_key_type(obj)) {
	case CKK_AES:
	case CKK_DES:
	case CKK_DES3:
		ret = key_cipher_modify_attribute(attr, obj);
		break;

	default:
		ret = CKR_FUNCTION_FAILED;
	}

	DBG_TRACE("Modify attribute type=%#lx ret %ld", attr->type, ret);
	return ret;
}

/**
 * subkey_private_create() - Create a private subkey object
 * @hsession: Session handle
 * @obj: Key object
 * @attrs: List of object attributes
 *
 * Call the key object type creation function.
 *
 * return:
 * CKR_CRYPTOKI_NOT_INITIALIZED  - Context not initialized
 * CKR_GENERAL_ERROR             - No slot defined
 * CKR_SESSION_HANDLE_INVALID    - Session Handle invalid
 * CKR_SLOT_ID_INVALID           - Slot ID is not valid
 * CKR_CURVE_NOT_SUPPORTED       - Curve is not supported
 * CKR_ATTRIBUTE_VALUE_INVALID   - Attribute value is not valid
 * CKR_FUNCTION_FAILED           - Function failure
 * CKR_TEMPLATE_INCOMPLETE       - Attribute template incomplete
 * CKR_TEMPLATE_INCONSISTENT     - One of the attribute is not valid
 * CKR_HOST_MEMORY               - Allocation error
 * CKR_GENERAL_ERROR             - General error defined
 * CKR_FUNCTION_FAILED           - Function failure
 * CKR_OK                        - Success
 */
static CK_RV subkey_private_create(CK_SESSION_HANDLE hsession,
				   struct libobj_obj *obj,
				   struct libattr_list *attrs)
{
	CK_RV ret;

	switch (get_key_type(obj)) {
	case CKK_EC:
		ret = key_ec_private_create(hsession, obj, attrs);
		break;

	case CKK_RSA:
		ret = key_rsa_private_create(hsession, obj, attrs);
		break;

	default:
		ret = CKR_FUNCTION_FAILED;
	}

	return ret;
}

/**
 * subkey_private_get_attribute() - Get an attribute from the private key
 * @attr: Attribute to get
 * @obj: Key object
 *
 * Get the given attribute @attr from the private key object,
 * if not present, call the private key type get attribute function.
 *
 * return:
 * CKR_ATTRIBUTE_SENSITIVE       - Attribute is sensitive
 * CKR_BUFFER_TOO_SMALL          - Attribute length is too small
 * CKR_ATTRIBUTE_TYPE_INVALID    - Attribute not found
 * CKR_FUNCTION_FAILED           - Object not supported
 * CKR_OK                        - Success
 */
static CK_RV subkey_private_get_attribute(CK_ATTRIBUTE_PTR attr,
					  const struct libobj_obj *obj)
{
	CK_RV ret;
	const struct libobj_key_private *priv_key = get_key_from(obj);
	bool protect = false;

	if (priv_key->sensitive || !priv_key->extractable)
		protect = true;

	DBG_TRACE("Get attribute type=%#lx protected=%s", attr->type,
		  protect ? "YES" : "NO");

	/* Get attribute from the private key attribute */
	ret = attr_get_obj_prot_value(attr, attr_key_private,
				      ARRAY_SIZE(attr_key_private), priv_key,
				      protect);
	if (ret != CKR_ATTRIBUTE_TYPE_INVALID)
		return ret;

	/*
	 * Attribute not present in the private key object attributes,
	 * try to get it from the specific key type
	 */
	switch (get_key_type(obj)) {
	case CKK_EC:
		ret = key_ec_private_get_attribute(attr, obj, protect);
		break;

	case CKK_RSA:
		ret = key_rsa_private_get_attribute(attr, obj, protect);
		break;

	default:
		ret = CKR_FUNCTION_FAILED;
	}

	DBG_TRACE("Get attribute type=%#lx ret %ld", attr->type, ret);
	return ret;
}

/**
 * subkey_private_modify_attribute() - Modify an attribute of the private key
 * @attr: Attribute to modify
 * @obj: Key object
 *
 * Modify the given attribute @attr of the private key object,
 * if not present, call the private key type modify attribute function.
 *
 * return:
 * CKR_ATTRIBUTE_READ_ONLY     - Attribute is read only
 * CKR_ATTRIBUTE_TYPE_INVALID  - Attribute not found
 * CKR_ATTRIBUTE_VALUE_INVALID - Attribute value or length not valid
 * CKR_HOST_MEMORY             - Out of memory
 * CKR_FUNCTION_FAILED           - Object not supported
 * CKR_OK                        - Success
 */
static CK_RV subkey_private_modify_attribute(CK_ATTRIBUTE_PTR attr,
					     struct libobj_obj *obj)
{
	CK_RV ret;

	DBG_TRACE("Modify attribute type=%#lx", attr->type);

	/* Modify attribute of the private key attribute */
	ret = attr_modify_obj_value(attr, attr_key_private,
				    ARRAY_SIZE(attr_key_private),
				    get_key_from(obj));

	if (ret != CKR_ATTRIBUTE_TYPE_INVALID)
		return ret;

	/*
	 * Attribute not present in the private key object attributes,
	 * try to modify it in the specific key type
	 */
	switch (get_key_type(obj)) {
	case CKK_EC:
		ret = key_ec_private_modify_attribute(attr, obj);
		break;

	case CKK_RSA:
		ret = key_rsa_private_modify_attribute(attr, obj);
		break;

	default:
		ret = CKR_FUNCTION_FAILED;
	}

	DBG_TRACE("Modify attribute type=%#lx ret %ld", attr->type, ret);
	return ret;
}

/**
 * subkey_public_create() - Create a public subkey object
 * @hsession: Session handle
 * @obj: Key object
 * @attrs: List of object attributes
 *
 * Call the key object type creation function.
 *
 * return:
 * CKR_CRYPTOKI_NOT_INITIALIZED  - Context not initialized
 * CKR_GENERAL_ERROR             - No slot defined
 * CKR_SESSION_HANDLE_INVALID    - Session Handle invalid
 * CKR_SLOT_ID_INVALID           - Slot ID is not valid
 * CKR_CURVE_NOT_SUPPORTED       - Curve is not supported
 * CKR_ATTRIBUTE_VALUE_INVALID   - Attribute value is not valid
 * CKR_FUNCTION_FAILED           - Function failure
 * CKR_TEMPLATE_INCOMPLETE       - Attribute template incomplete
 * CKR_TEMPLATE_INCONSISTENT     - One of the attribute is not valid
 * CKR_HOST_MEMORY               - Allocation error
 * CKR_GENERAL_ERROR             - General error defined
 * CKR_FUNCTION_FAILED           - Function failure
 * CKR_OK                        - Success
 */
static CK_RV subkey_public_create(CK_SESSION_HANDLE hsession,
				  struct libobj_obj *obj,
				  struct libattr_list *attrs)
{
	CK_RV ret;

	switch (get_key_type(obj)) {
	case CKK_EC:
		ret = key_ec_public_create(hsession, obj, attrs);
		break;

	case CKK_RSA:
		ret = key_rsa_public_create(hsession, obj, attrs);
		break;

	default:
		ret = CKR_FUNCTION_FAILED;
	}

	return ret;
}

/**
 * subkey_public_get_attribute() - Get an attribute from the public key
 * @attr: Attribute to get
 * @key: Key object
 *
 * Get the given attribute @attr from the public key object,
 * if not present, call the public key type get attribute function.
 *
 * return:
 * CKR_BUFFER_TOO_SMALL          - Attribute length is too small
 * CKR_ATTRIBUTE_TYPE_INVALID    - Attribute not found
 * CKR_FUNCTION_FAILED           - Object not supported
 * CKR_OK                        - Success
 */
static CK_RV subkey_public_get_attribute(CK_ATTRIBUTE_PTR attr,
					 const struct libobj_obj *obj)
{
	CK_RV ret;

	DBG_TRACE("Get attribute type=%#lx", attr->type);

	/* Get attribute from the public key attribute */
	ret = attr_get_obj_value(attr, attr_key_public,
				 ARRAY_SIZE(attr_key_public),
				 get_key_from(obj));
	if (ret != CKR_ATTRIBUTE_TYPE_INVALID)
		return ret;

	/*
	 * Attribute not present in the public key object attributes,
	 * try to get it from the specific key type
	 */
	switch (get_key_type(obj)) {
	case CKK_EC:
		ret = key_ec_public_get_attribute(attr, obj);
		break;

	case CKK_RSA:
		ret = key_rsa_public_get_attribute(attr, obj);
		break;

	default:
		ret = CKR_FUNCTION_FAILED;
	}

	DBG_TRACE("Get attribute type=%#lx ret %ld", attr->type, ret);
	return ret;
}

/**
 * subkey_public_modify_attribute() - Modify an attribute from the public key
 * @attr: Attribute to modify
 * @obj: Key object
 *
 * Modify the given attribute @attr of the public key object,
 * if not present, call the public key type modify attribute function.
 *
 * return:
 * CKR_ATTRIBUTE_READ_ONLY     - Attribute is read only
 * CKR_ATTRIBUTE_TYPE_INVALID  - Attribute not found
 * CKR_ATTRIBUTE_VALUE_INVALID - Attribute value or length not valid
 * CKR_HOST_MEMORY             - Out of memory
 * CKR_FUNCTION_FAILED           - Object not supported
 * CKR_OK                        - Success
 */
static CK_RV subkey_public_modify_attribute(CK_ATTRIBUTE_PTR attr,
					    struct libobj_obj *obj)
{
	CK_RV ret;

	DBG_TRACE("Modify attribute type=%#lx", attr->type);

	/* Modify attribute of the public key attribute */
	ret = attr_modify_obj_value(attr, attr_key_public,
				    ARRAY_SIZE(attr_key_public),
				    get_key_from(obj));
	if (ret != CKR_ATTRIBUTE_TYPE_INVALID)
		return ret;

	/*
	 * Attribute not present in the public key object attributes,
	 * try to modify it in the specific key type
	 */
	switch (get_key_type(obj)) {
	case CKK_EC:
		ret = key_ec_public_modify_attribute(attr, obj);
		break;

	case CKK_RSA:
		ret = key_rsa_public_modify_attribute(attr, obj);
		break;

	default:
		ret = CKR_FUNCTION_FAILED;
	}

	DBG_TRACE("Modify attribute type=%#lx ret %ld", attr->type, ret);
	return ret;
}

/**
 * create_key_new() - New common key object for object creation
 * @obj: Key object uncer creation
 * @attrs: List of object attributes
 *
 * Allocate a new key object and setup it with given object
 * attribute list following the C_CreateObject requirements
 *
 * return:
 * CKR_TEMPLATE_INCOMPLETE    - Attribute type not found
 * CKR_TEMPLATE_INCONSISTENT  - Attribute type must not be defined
 * CKR_ATTRIBUTE_VALUE_INVALID- Attribute length is not valid
 * CKR_HOST_MEMORY            - Allocation error
 * CKR_OK                     - Success
 */
static CK_RV create_key_new(struct libobj_obj *obj, struct libattr_list *attrs)
{
	CK_RV ret;
	struct libobj_key *new_key = NULL;

	new_key = key_allocate(obj);
	if (!new_key)
		return CKR_HOST_MEMORY;

	DBG_TRACE("Create a new key (%p)", new_key);

	ret = attr_get_value(new_key, &attr_key_common[KEY_TYPE], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(new_key, &attr_key_common[KEY_ID], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(new_key, &attr_key_common[KEY_START_DATE], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(new_key, &attr_key_common[KEY_END_DATE], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(new_key, &attr_key_common[KEY_DERIVE], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(new_key, &attr_key_common[KEY_LOCAL], attrs,
			     MUST_NOT);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(new_key, &attr_key_common[KEY_GEN_MECH], attrs,
			     MUST_NOT);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(new_key, &attr_key_common[KEY_ALLOWED_MECH], attrs,
			     NO_OVERWRITE);
	return ret;
}

/**
 * generate_key_new() - New common key object for key generation
 * @obj: Key object
 * @attrs: List of object attributes
 * @mech: Generate mechanism definition
 * @key_type: Key type of the key to generate
 *
 * Allocate a new key object and setup it with given object
 * attribute list following the C_GenerateKey or C_GenerateKeyPair
 * requirement
 *
 * return:
 * CKR_TEMPLATE_INCOMPLETE    - Attribute type not found
 * CKR_TEMPLATE_INCONSISTENT  - Attribute type must not be defined
 * CKR_ATTRIBUTE_VALUE_INVALID- Attribute length is not valid
 * CKR_HOST_MEMORY            - Allocation error
 * CKR_MECHANISM_INVALID      - Mechanism not supported
 * CKR_OK                     - Success
 */
static CK_RV generate_key_new(struct libobj_obj *obj,
			      struct libattr_list *attrs, CK_MECHANISM_PTR mech,
			      CK_KEY_TYPE key_type)
{
	CK_RV ret;
	struct libobj_key *new_key = NULL;

	new_key = key_allocate(obj);
	if (!new_key)
		return CKR_HOST_MEMORY;

	DBG_TRACE("Generate a new key (%p)", new_key);

	new_key->type = key_type;
	ret = attr_get_value(new_key, &attr_key_common[KEY_TYPE], attrs,
			     OPTIONAL);
	if (ret != CKR_OK)
		return ret;

	if (new_key->type != key_type)
		return CKR_TEMPLATE_INCONSISTENT;

	ret = attr_get_value(new_key, &attr_key_common[KEY_ID], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(new_key, &attr_key_common[KEY_START_DATE], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(new_key, &attr_key_common[KEY_END_DATE], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(new_key, &attr_key_common[KEY_DERIVE], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(new_key, &attr_key_common[KEY_LOCAL], attrs,
			     MUST_NOT);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(new_key, &attr_key_common[KEY_GEN_MECH], attrs,
			     MUST_NOT);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(new_key, &attr_key_common[KEY_ALLOWED_MECH], attrs,
			     NO_OVERWRITE);

	/* Set the generate mechanism and the local flag */
	new_key->gen_mech = mech->mechanism;
	new_key->local = true;

	return ret;
}

void key_free(struct libobj_obj *obj)
{
	struct libobj_key *key = get_subobj_from(obj, storage);

	if (!key)
		return;

	DBG_TRACE("Free key (%p)", key);

	if (key->id.array)
		free(key->id.array);

	if (key->mech.mech)
		free(key->mech.mech);

	switch (obj->class) {
	case CKO_PUBLIC_KEY:
		key_public_free(obj);
		break;

	case CKO_PRIVATE_KEY:
		key_private_free(obj);
		break;

	case CKO_SECRET_KEY:
		key_secret_free(obj);
		break;

	default:
		break;
	}

	free(key);
}

CK_RV key_create(CK_SESSION_HANDLE hsession, struct libobj_obj *obj,
		 struct libattr_list *attrs)
{
	CK_RV ret;

	DBG_TRACE("Create a new key type object");

	if (!obj)
		return CKR_GENERAL_ERROR;

	/* Create the common key object */
	ret = create_key_new(obj, attrs);
	if (ret == CKR_OK) {
		switch (obj->class) {
		case CKO_PUBLIC_KEY:
			ret = key_public_new(hsession, obj, attrs);
			if (ret == CKR_OK)
				ret = subkey_public_create(hsession, obj,
							   attrs);
			break;

		case CKO_PRIVATE_KEY:
			ret = key_private_new(obj, attrs);
			if (ret == CKR_OK)
				ret = subkey_private_create(hsession, obj,
							    attrs);
			break;

		case CKO_SECRET_KEY:
			ret = key_secret_new(obj, attrs);
			if (ret == CKR_OK)
				ret = subkey_secret_create(hsession, obj,
							   attrs);
			break;

		default:
			ret = CKR_GENERAL_ERROR;
			break;
		}
	}

	DBG_TRACE("Key type object (%p) creation return %ld", obj, ret);
	return ret;
}

CK_RV key_get_attribute(CK_ATTRIBUTE_PTR attr, const struct libobj_obj *obj)
{
	CK_RV ret;

	DBG_TRACE("Get attribute type=%#lx", attr->type);

	/* Get attribute from the common key attribute */
	ret = attr_get_obj_value(attr, attr_key_common,
				 ARRAY_SIZE(attr_key_common),
				 get_subobj_from(obj, storage));

	if (ret != CKR_ATTRIBUTE_TYPE_INVALID)
		return ret;

	/*
	 * Attribute not present in the common key object attributes,
	 * try to get it from the specific key class type
	 */
	switch (obj->class) {
	case CKO_PUBLIC_KEY:
		ret = subkey_public_get_attribute(attr, obj);
		break;

	case CKO_PRIVATE_KEY:
		ret = subkey_private_get_attribute(attr, obj);
		break;

	case CKO_SECRET_KEY:
		ret = subkey_secret_get_attribute(attr, obj);
		break;

	default:
		ret = CKR_FUNCTION_FAILED;
	}

	DBG_TRACE("Get attribute type=%#lx ret %ld", attr->type, ret);
	return ret;
}

CK_RV key_modify_attribute(CK_ATTRIBUTE_PTR attr, struct libobj_obj *obj)
{
	CK_RV ret;

	DBG_TRACE("Modify attribute type=%#lx", attr->type);

	/* Get attribute from the common key attribute */
	ret = attr_modify_obj_value(attr, attr_key_common,
				    ARRAY_SIZE(attr_key_common),
				    get_subobj_from(obj, storage));

	if (ret != CKR_ATTRIBUTE_TYPE_INVALID)
		return ret;

	/*
	 * Attribute not present in the common key object attributes,
	 * try to modify it in the specific key class type
	 */
	switch (obj->class) {
	case CKO_PUBLIC_KEY:
		ret = subkey_public_modify_attribute(attr, obj);
		break;

	case CKO_PRIVATE_KEY:
		ret = subkey_private_modify_attribute(attr, obj);
		break;

	case CKO_SECRET_KEY:
		ret = subkey_secret_modify_attribute(attr, obj);
		break;

	default:
		ret = CKR_FUNCTION_FAILED;
	}

	DBG_TRACE("Modify attribute type=%#lx ret %ld", attr->type, ret);
	return ret;
}

CK_RV key_keypair_generate(CK_SESSION_HANDLE hsession, CK_MECHANISM_PTR mech,
			   struct libobj_obj *pub_key,
			   struct libattr_list *pub_attrs,
			   struct libobj_obj *priv_key,
			   struct libattr_list *priv_attrs)
{
	CK_RV ret;
	CK_KEY_TYPE key_type;

	DBG_TRACE("Generate a new keypair type object");

	if (!pub_key || !priv_key)
		return CKR_GENERAL_ERROR;

	switch (mech->mechanism) {
	case CKM_EC_KEY_PAIR_GEN:
		key_type = CKK_EC;
		break;

	case CKM_RSA_PKCS_KEY_PAIR_GEN:
	case CKM_RSA_X9_31_KEY_PAIR_GEN:
		key_type = CKK_RSA;
		break;

	default:
		return CKR_MECHANISM_INVALID;
	}

	DBG_TRACE("Create Public key (%p)", pub_key);

	ret = generate_key_new(pub_key, pub_attrs, mech, key_type);
	if (ret != CKR_OK)
		goto end;

	ret = key_public_new(hsession, pub_key, pub_attrs);
	if (ret != CKR_OK)
		goto end;

	DBG_TRACE("Create Private key (%p)", priv_key);

	ret = generate_key_new(priv_key, priv_attrs, mech, key_type);
	if (ret != CKR_OK)
		goto end;

	ret = key_private_new(priv_key, priv_attrs);
	if (ret != CKR_OK)
		goto end;

	if (key_type == CKK_EC)
		ret = key_ec_keypair_generate(hsession, mech, pub_key,
					      pub_attrs, priv_key, priv_attrs);
	else
		ret = key_rsa_keypair_generate(hsession, mech, pub_key,
					       pub_attrs, priv_key, priv_attrs);

end:
	DBG_TRACE("Keypair object (pub=%p priv=%p) generate return %ld",
		  pub_key, priv_key, ret);
	return ret;
}

CK_RV key_secret_key_generate(CK_SESSION_HANDLE hsession, CK_MECHANISM_PTR mech,
			      struct libobj_obj *obj,
			      struct libattr_list *attrs)
{
	CK_RV ret;
	CK_KEY_TYPE key_type;

	DBG_TRACE("Generate a new secret key type object");

	if (!obj)
		return CKR_GENERAL_ERROR;

	switch (mech->mechanism) {
	case CKM_AES_KEY_GEN:
		key_type = CKK_AES;
		break;
	case CKM_DES_KEY_GEN:
		key_type = CKK_DES;
		break;
	case CKM_DES3_KEY_GEN:
		key_type = CKK_DES3;
		break;
	default:
		return CKR_MECHANISM_INVALID;
	}

	ret = generate_key_new(obj, attrs, mech, key_type);
	if (ret != CKR_OK)
		goto end;

	key_type = get_key_type(obj);

	ret = key_secret_new(obj, attrs);
	if (ret != CKR_OK)
		goto end;

	switch (key_type) {
	case CKK_AES:
	case CKK_DES:
	case CKK_DES3:
		ret = key_cipher_generate(hsession, mech, obj, attrs);
		break;

	default:
		ret = CKR_FUNCTION_FAILED;
		break;
	}

end:
	DBG_TRACE("Secret Key object (%p) generate return %ld", obj, ret);
	return ret;
}

CK_RV key_get_id(struct libbytes *id, struct libobj_obj *obj, size_t prefix_len)
{
	CK_RV ret;

	if (!id || !obj)
		return CKR_GENERAL_ERROR;

	switch (get_key_type(obj)) {
	case CKK_AES:
	case CKK_DES:
	case CKK_DES3:
		ret = key_cipher_get_id(id, obj, prefix_len);
		break;

	case CKK_EC:
		ret = key_ec_get_id(id, obj, prefix_len);
		break;

	case CKK_RSA:
		ret = key_rsa_get_id(id, obj, prefix_len);
		break;

	default:
		ret = CKR_FUNCTION_FAILED;
		break;
	}

	return ret;
}
