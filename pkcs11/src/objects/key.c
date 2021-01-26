// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2021 NXP
 */

#include <stdlib.h>

#include "attributes.h"
#include "key.h"
#include "key_cipher.h"
#include "key_ec.h"

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
	[KEY_TYPE] = { CKA_KEY_TYPE, sizeof(CK_KEY_TYPE), MUST, attr_to_key },
	[KEY_ID] = { CKA_ID, 0, OPTIONAL, attr_to_byte_array },
	[KEY_START_DATE] = { CKA_START_DATE, sizeof(CK_DATE), OPTIONAL,
			     attr_to_date },
	[KEY_END_DATE] = { CKA_END_DATE, sizeof(CK_DATE), OPTIONAL,
			   attr_to_date },
	[KEY_DERIVE] = { CKA_DERIVE, sizeof(CK_BBOOL), OPTIONAL, attr_to_bool },
	[KEY_LOCAL] = { CKA_LOCAL, sizeof(CK_BBOOL), OPTIONAL, attr_to_bool },
	[KEY_GEN_MECH] = { CKA_KEY_GEN_MECHANISM, sizeof(CK_MECHANISM_TYPE),
			   OPTIONAL, attr_to_mech },
	[KEY_ALLOWED_MECH] = { CKA_ALLOWED_MECHANISMS, 0, OPTIONAL,
			       attr_to_mech_list },
};

struct libobj_key_public {
	struct libbytes subject;
	bool encrypt;
	bool verify;
	bool verify_recover;
	bool wrap;
	bool trusted;
	struct libattr_list wrap_attrs;
	struct libbytes info;
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
	[PUB_SUBJECT] = { CKA_SUBJECT, 0, OPTIONAL, attr_to_byte_array },
	[PUB_ENCRYPT] = { CKA_ENCRYPT, sizeof(CK_BBOOL), OPTIONAL,
			  attr_to_bool },
	[PUB_VERIFY] = { CKA_VERIFY, sizeof(CK_BBOOL), OPTIONAL, attr_to_bool },
	[PUB_VERIFY_RECOVER] = { CKA_VERIFY_RECOVER, sizeof(CK_BBOOL), OPTIONAL,
				 attr_to_bool },
	[PUB_TRUSTED] = { CKA_TRUSTED, sizeof(CK_BBOOL), OPTIONAL,
			  attr_to_bool },
	[PUB_WRAP] = { CKA_WRAP, sizeof(CK_BBOOL), OPTIONAL, attr_to_bool },
	[PUB_WRAP_TEMPLATE] = { CKA_WRAP_TEMPLATE, 0, OPTIONAL,
				attr_to_attr_list },
	[PUB_INFO] = { CKA_PUBLIC_KEY_INFO, 0, OPTIONAL, attr_to_byte_array },
};

struct libobj_key_private {
	struct libbytes subject;
	bool sensitive;
	bool always_sensitive;
	bool decrypt;
	bool sign;
	bool sign_recover;
	bool extractable;
	bool never_extractable;
	bool wrap_with_trusted;
	bool unwrap;
	struct libattr_list unwrap_attrs;
	bool always_authenticate;
	struct libbytes info;
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
	[PRIV_SUBJECT] = { CKA_SUBJECT, 0, OPTIONAL, attr_to_byte_array },
	[PRIV_SENSITIVE] = { CKA_SENSITIVE, sizeof(CK_BBOOL), OPTIONAL,
			     attr_to_bool },
	[PRIV_ALWAYS_SENSITIVE] = { CKA_ALWAYS_SENSITIVE, sizeof(CK_BBOOL),
				    OPTIONAL, attr_to_bool },
	[PRIV_DECRYPT] = { CKA_DECRYPT, sizeof(CK_BBOOL), OPTIONAL,
			   attr_to_bool },
	[PRIV_SIGN] = { CKA_SIGN, sizeof(CK_BBOOL), OPTIONAL, attr_to_bool },
	[PRIV_SIGN_RECOVER] = { CKA_SIGN_RECOVER, sizeof(CK_BBOOL), OPTIONAL,
				attr_to_bool },
	[PRIV_EXTRACTABLE] = { CKA_EXTRACTABLE, sizeof(CK_BBOOL), OPTIONAL,
			       attr_to_bool },
	[PRIV_NEVER_EXTRACTABLE] = { CKA_NEVER_EXTRACTABLE, sizeof(CK_BBOOL),
				     OPTIONAL, attr_to_bool },
	[PRIV_WRAP_WITH_TRUSTED] = { CKA_WRAP_WITH_TRUSTED, sizeof(CK_BBOOL),
				     OPTIONAL, attr_to_bool },
	[PRIV_UNWRAP] = { CKA_UNWRAP, sizeof(CK_BBOOL), OPTIONAL,
			  attr_to_bool },
	[PRIV_UNWRAP_TEMPLATE] = { CKA_UNWRAP_TEMPLATE, 0, OPTIONAL,
				   attr_to_attr_list },
	[PRIV_ALWAYS_AUTHENTICATE] = { CKA_ALWAYS_AUTHENTICATE,
				       sizeof(CK_BBOOL), OPTIONAL,
				       attr_to_bool },
	[PRIV_INFO] = { CKA_PUBLIC_KEY_INFO, 0, OPTIONAL, attr_to_byte_array },
};

struct libobj_key_secret {
	bool sensitive;
	bool always_sensitive;
	bool encrypt;
	bool decrypt;
	bool sign;
	bool verify;
	bool extractable;
	bool never_extractable;
	bool wrap;
	struct libattr_list wrap_attrs;
	bool wrap_with_trusted;
	bool unwrap;
	struct libattr_list unwrap_attrs;
	bool trusted;
	struct libbytes checksum;
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
	[SECR_SENSITIVE] = { CKA_SENSITIVE, sizeof(CK_BBOOL), OPTIONAL,
			     attr_to_bool },
	[SECR_ALWAYS_SENSITIVE] = { CKA_ALWAYS_SENSITIVE, sizeof(CK_BBOOL),
				    OPTIONAL, attr_to_bool },
	[SECR_ENCRYPT] = { CKA_ENCRYPT, sizeof(CK_BBOOL), OPTIONAL,
			   attr_to_bool },
	[SECR_DECRYPT] = { CKA_DECRYPT, sizeof(CK_BBOOL), OPTIONAL,
			   attr_to_bool },
	[SECR_SIGN] = { CKA_SIGN, sizeof(CK_BBOOL), OPTIONAL, attr_to_bool },
	[SECR_VERIFY] = { CKA_VERIFY, sizeof(CK_BBOOL), OPTIONAL,
			  attr_to_bool },
	[SECR_EXTRACTABLE] = { CKA_EXTRACTABLE, sizeof(CK_BBOOL), OPTIONAL,
			       attr_to_bool },
	[SECR_NEVER_EXTRACTABLE] = { CKA_NEVER_EXTRACTABLE, sizeof(CK_BBOOL),
				     OPTIONAL, attr_to_bool },
	[SECR_WRAP] = { CKA_WRAP, sizeof(CK_BBOOL), OPTIONAL, attr_to_bool },
	[SECR_WRAP_TEMPLATE] = { CKA_WRAP_TEMPLATE, 0, OPTIONAL,
				 attr_to_attr_list },
	[SECR_WRAP_WITH_TRUSTED] = { CKA_WRAP_WITH_TRUSTED, sizeof(CK_BBOOL),
				     OPTIONAL, attr_to_bool },
	[SECR_UNWRAP] = { CKA_UNWRAP, sizeof(CK_BBOOL), OPTIONAL,
			  attr_to_bool },
	[SECR_UNWRAP_TEMPLATE] = { CKA_UNWRAP_TEMPLATE, 0, OPTIONAL,
				   attr_to_attr_list },
	[SECR_TRUSTED] = { CKA_TRUSTED, sizeof(CK_BBOOL), OPTIONAL,
			   attr_to_bool },
	[SECR_CHECK_VALUE] = { CKA_CHECK_VALUE, 3 * sizeof(CK_BYTE), OPTIONAL,
			       attr_to_byte_array },
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

	ret = attr_get_value(&new_key->sensitive,
			     &attr_key_secret[SECR_SENSITIVE], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(&new_key->always_sensitive,
			     &attr_key_secret[SECR_ALWAYS_SENSITIVE], attrs,
			     MUST_NOT);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(&new_key->encrypt, &attr_key_secret[SECR_ENCRYPT],
			     attrs, NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(&new_key->decrypt, &attr_key_secret[SECR_DECRYPT],
			     attrs, NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(&new_key->sign, &attr_key_secret[SECR_SIGN], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(&new_key->verify, &attr_key_secret[SECR_VERIFY],
			     attrs, NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(&new_key->extractable,
			     &attr_key_secret[SECR_EXTRACTABLE], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(&new_key->never_extractable,
			     &attr_key_secret[SECR_NEVER_EXTRACTABLE], attrs,
			     MUST_NOT);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(&new_key->wrap, &attr_key_secret[SECR_WRAP], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(&new_key->wrap_attrs,
			     &attr_key_secret[SECR_WRAP_TEMPLATE], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(&new_key->wrap_with_trusted,
			     &attr_key_secret[SECR_WRAP_WITH_TRUSTED], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(&new_key->unwrap, &attr_key_secret[SECR_UNWRAP],
			     attrs, NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(&new_key->unwrap_attrs,
			     &attr_key_secret[SECR_UNWRAP_TEMPLATE], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(&new_key->trusted, &attr_key_secret[SECR_TRUSTED],
			     attrs, NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(&new_key->checksum,
			     &attr_key_secret[SECR_CHECK_VALUE], attrs,
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

	ret = attr_get_value(&new_key->subject, &attr_key_private[PRIV_SUBJECT],
			     attrs, NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(&new_key->sensitive,
			     &attr_key_private[PRIV_SENSITIVE], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(&new_key->always_sensitive,
			     &attr_key_private[PRIV_ALWAYS_SENSITIVE], attrs,
			     MUST_NOT);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(&new_key->decrypt, &attr_key_private[PRIV_DECRYPT],
			     attrs, NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(&new_key->sign, &attr_key_private[PRIV_SIGN],
			     attrs, NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(&new_key->sign_recover,
			     &attr_key_private[PRIV_SIGN_RECOVER], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(&new_key->extractable,
			     &attr_key_private[PRIV_EXTRACTABLE], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(&new_key->never_extractable,
			     &attr_key_private[PRIV_NEVER_EXTRACTABLE], attrs,
			     MUST_NOT);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(&new_key->wrap_with_trusted,
			     &attr_key_private[PRIV_WRAP_WITH_TRUSTED], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(&new_key->unwrap, &attr_key_private[PRIV_UNWRAP],
			     attrs, NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(&new_key->unwrap_attrs,
			     &attr_key_private[PRIV_UNWRAP_TEMPLATE], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(&new_key->info, &attr_key_private[PRIV_INFO],
			     attrs, NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(&new_key->always_authenticate,
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

	ret = attr_get_value(&new_key->subject, &attr_key_public[PUB_SUBJECT],
			     attrs, NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(&new_key->encrypt, &attr_key_public[PUB_ENCRYPT],
			     attrs, NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(&new_key->verify, &attr_key_public[PUB_VERIFY],
			     attrs, NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(&new_key->verify_recover,
			     &attr_key_public[PUB_VERIFY_RECOVER], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(&new_key->trusted, &attr_key_public[PUB_TRUSTED],
			     attrs, NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	if (new_key->trusted) {
		ret = libsess_get_user(hsession, &user);
		if (ret != CKR_OK)
			return ret;

		if (user != CKU_SO)
			return CKR_ATTRIBUTE_READ_ONLY;
	}

	ret = attr_get_value(&new_key->wrap, &attr_key_public[PUB_WRAP], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(&new_key->wrap_attrs,
			     &attr_key_public[PUB_WRAP_TEMPLATE], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(&new_key->info, &attr_key_public[PUB_INFO], attrs,
			     NO_OVERWRITE);

	return ret;
}

/**
 * subkey_secret_create() - Create a secret subkey object
 * @obj: Key object
 * @attrs: List of object attributes
 *
 * Call the key object type creation function.
 *
 * return:
 * CKR_ATTRIBUTE_VALUE_INVALID   - Attribute value is not valid
 * CKR_FUNCTION_FAILED           - Function failure
 * CKR_TEMPLATE_INCOMPLETE       - Attribute template incomplete
 * CKR_TEMPLATE_INCONSISTENT     - One of the attribute is not valid
 * CKR_HOST_MEMORY               - Allocation error
 * CKR_GENERAL_ERROR             - General error defined
 * CKR_FUNCTION_FAILED           - Function failure
 * CKR_OK                        - Success
 */
static CK_RV subkey_secret_create(struct libobj_obj *obj,
				  struct libattr_list *attrs)
{
	CK_RV ret;

	switch (get_key_type(obj)) {
	case CKK_AES:
	case CKK_DES:
	case CKK_DES3:
		ret = key_cipher_create(obj, attrs);
		break;

	default:
		ret = CKR_FUNCTION_FAILED;
	}

	return ret;
}

/**
 * subkey_private_create() - Create a private subkey object
 * @obj: Key object
 * @attrs: List of object attributes
 *
 * Call the key object type creation function.
 *
 * return:
 * CKR_CRYPTOKI_NOT_INITIALIZED  - Context not initialized
 * CKR_ATTRIBUTE_VALUE_INVALID   - Attribute value is not valid
 * CKR_FUNCTION_FAILED           - Function failure
 * CKR_TEMPLATE_INCOMPLETE       - Attribute template incomplete
 * CKR_TEMPLATE_INCONSISTENT     - One of the attribute is not valid
 * CKR_HOST_MEMORY               - Allocation error
 * CKR_GENERAL_ERROR             - General error defined
 * CKR_FUNCTION_FAILED           - Function failure
 * CKR_OK                        - Success
 */
static CK_RV subkey_private_create(struct libobj_obj *obj,
				   struct libattr_list *attrs)
{
	CK_RV ret;

	switch (get_key_type(obj)) {
	case CKK_EC:
		ret = key_ec_private_create(obj, attrs);
		break;

	default:
		ret = CKR_FUNCTION_FAILED;
	}

	return ret;
}

/**
 * subkey_public_create() - Create a public subkey object
 * @obj: Key object
 * @attrs: List of object attributes
 *
 * Call the key object type creation function.
 *
 * return:
 * CKR_CRYPTOKI_NOT_INITIALIZED  - Context not initialized
 * CKR_GENERAL_ERROR             - No slot defined
 * CKR_FUNCTION_FAILED           - Function failure
 * CKR_TEMPLATE_INCOMPLETE       - Attribute template incomplete
 * CKR_TEMPLATE_INCONSISTENT     - One of the attribute is not valid
 * CKR_HOST_MEMORY               - Allocation error
 * CKR_GENERAL_ERROR             - General error defined
 * CKR_FUNCTION_FAILED           - Function failure
 * CKR_OK                        - Success
 */
static CK_RV subkey_public_create(struct libobj_obj *obj,
				  struct libattr_list *attrs)
{
	CK_RV ret;

	switch (get_key_type(obj)) {
	case CKK_EC:
		ret = key_ec_public_create(obj, attrs);
		break;

	default:
		ret = CKR_FUNCTION_FAILED;
	}

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

	ret = attr_get_value(&new_key->type, &attr_key_common[KEY_TYPE], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(&new_key->id, &attr_key_common[KEY_ID], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(&new_key->start_date,
			     &attr_key_common[KEY_START_DATE], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(&new_key->end_date, &attr_key_common[KEY_END_DATE],
			     attrs, NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(&new_key->derive, &attr_key_common[KEY_DERIVE],
			     attrs, NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(&new_key->local, &attr_key_common[KEY_LOCAL],
			     attrs, MUST_NOT);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(&new_key->gen_mech, &attr_key_common[KEY_GEN_MECH],
			     attrs, MUST_NOT);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(&new_key->mech, &attr_key_common[KEY_ALLOWED_MECH],
			     attrs, NO_OVERWRITE);
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
	ret = attr_get_value(&new_key->type, &attr_key_common[KEY_TYPE], attrs,
			     OPTIONAL);
	if (ret != CKR_OK)
		return ret;

	if (new_key->type != key_type)
		return CKR_TEMPLATE_INCONSISTENT;

	ret = attr_get_value(&new_key->id, &attr_key_common[KEY_ID], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(&new_key->start_date,
			     &attr_key_common[KEY_START_DATE], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(&new_key->end_date, &attr_key_common[KEY_END_DATE],
			     attrs, NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(&new_key->derive, &attr_key_common[KEY_DERIVE],
			     attrs, NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(&new_key->local, &attr_key_common[KEY_LOCAL],
			     attrs, MUST_NOT);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(&new_key->gen_mech, &attr_key_common[KEY_GEN_MECH],
			     attrs, MUST_NOT);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(&new_key->mech, &attr_key_common[KEY_ALLOWED_MECH],
			     attrs, NO_OVERWRITE);

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
				ret = subkey_public_create(obj, attrs);
			break;

		case CKO_PRIVATE_KEY:
			ret = key_private_new(obj, attrs);
			if (ret == CKR_OK)
				ret = subkey_private_create(obj, attrs);
			break;

		case CKO_SECRET_KEY:
			ret = key_secret_new(obj, attrs);
			if (ret == CKR_OK)
				ret = subkey_secret_create(obj, attrs);
			break;

		default:
			ret = CKR_GENERAL_ERROR;
			break;
		}
	}

	DBG_TRACE("Key type object (%p) creation return %ld", obj, ret);
	return ret;
}

CK_RV key_keypair_generate(CK_SESSION_HANDLE hsession, CK_MECHANISM_PTR mech,
			   struct libobj_obj *pub_key,
			   struct libattr_list *pub_attrs,
			   struct libobj_obj *priv_key,
			   struct libattr_list *priv_attrs)
{
	CK_RV ret;

	DBG_TRACE("Generate a new keypair type object");

	if (!pub_key || !priv_key)
		return CKR_GENERAL_ERROR;

	/* Support only EC Keypair generation */
	if (mech->mechanism != CKM_EC_KEY_PAIR_GEN)
		return CKR_MECHANISM_INVALID;

	DBG_TRACE("Create Public key (%p)", pub_key);

	ret = generate_key_new(pub_key, pub_attrs, mech, CKK_EC);
	if (ret != CKR_OK)
		goto end;

	ret = key_public_new(hsession, pub_key, pub_attrs);
	if (ret != CKR_OK)
		goto end;

	DBG_TRACE("Create Private key (%p)", priv_key);

	ret = generate_key_new(priv_key, priv_attrs, mech, CKK_EC);
	if (ret != CKR_OK)
		goto end;

	ret = key_private_new(priv_key, priv_attrs);
	if (ret != CKR_OK)
		goto end;

	ret = key_ec_keypair_generate(hsession, mech, pub_key, pub_attrs,
				      priv_key, priv_attrs);

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

	default:
		ret = CKR_FUNCTION_FAILED;
		break;
	}

	return ret;
}
