// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2025 NXP
 */

#include <stdlib.h>
#include <string.h>

#include "attributes.h"
#include "key.h"
#include "key_cipher.h"
#include "key_hmac.h"
#include "key_ec.h"
#include "key_rsa.h"

#include "lib_device.h"
#include "lib_session.h"
#include "lib_object.h"
#include "libobj_types.h"

#include "util.h"

#include "trace.h"

/*
 * TLS 1.3 expanded_label is composed of:
 * - 2 bytes: args->length as uint16_t
 * - 1 byte: prefix_length (6) + args->label_length
 * - 6 bytes: the prefix ("tls13 ")
 * - `args->label_length` bytes: the input args->label
 */
#define TLS13_LABEL_OFFSET (2 + 1 + 6)

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
	[KEY_ALLOWED_MECH] = TATTR(key, mech_list, ALLOWED_MECHANISMS, 0,
				   OPTIONAL, mech_list),
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
	struct libobj_key *key = NULL;

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
	case CKK_SM4:
		key_cipher_free(obj);
		break;

	case CKK_MD5_HMAC:
	case CKK_SHA_1_HMAC:
	case CKK_SHA224_HMAC:
	case CKK_SHA256_HMAC:
	case CKK_SHA384_HMAC:
	case CKK_SHA512_HMAC:
	case CKK_SHA3_224_HMAC:
	case CKK_SHA3_256_HMAC:
	case CKK_SHA3_384_HMAC:
	case CKK_SHA3_512_HMAC:
	case CKK_GENERIC_SECRET:
	case CKK_HKDF:
		key_hmac_free(obj);
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
	case CKK_EC_EDWARDS:
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
	case CKK_EC_EDWARDS:
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
 * @is_derived_key: True, if @obj is a derived key object.
 *
 * Allocate a new secret key object and setup it with given object
 * attribute list.
 *
 * For derived key, the SECR_ALWAYS_SENSITIVE and SECR_NEVER_EXTRACTABLE are set
 * based on the base key attributes in the function set_derived_key_attr().
 *
 * return:
 * CKR_FUNCTION_FAILED           - Function failure
 * CKR_TEMPLATE_INCOMPLETE       - Attribute type not found
 * CKR_TEMPLATE_INCONSISTENT     - Attribute type must not be defined
 * CKR_ATTRIBUTE_VALUE_INVALID   - Attribute length is not valid
 * CKR_HOST_MEMORY               - Allocation error
 * CKR_OK                        - Success
 */
static CK_RV key_secret_new(struct libobj_obj *obj, struct libattr_list *attrs,
			    bool is_derived_key)
{
	CK_RV ret = CKR_OK;
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

	if (!is_derived_key) {
		ret = attr_get_value(new_key,
				     &attr_key_secret[SECR_ALWAYS_SENSITIVE],
				     attrs, MUST_NOT);
		if (ret != CKR_OK)
			return ret;
	}

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

	if (!is_derived_key) {
		ret = attr_get_value(new_key,
				     &attr_key_secret[SECR_NEVER_EXTRACTABLE],
				     attrs, MUST_NOT);
		if (ret != CKR_OK)
			return ret;
	}

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
	CK_RV ret = CKR_OK;
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
	CK_RV ret = CKR_OK;
	struct libobj_key_public *new_key = NULL;
	CK_USER_TYPE user = CKU_USER;

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
	CK_RV ret = CKR_FUNCTION_FAILED;

	switch (get_key_type(obj)) {
	case CKK_AES:
	case CKK_DES:
	case CKK_DES3:
	case CKK_SM4:
		ret = key_cipher_create(hsession, obj, attrs);
		break;

	case CKK_MD5_HMAC:
	case CKK_SHA_1_HMAC:
	case CKK_SHA224_HMAC:
	case CKK_SHA256_HMAC:
	case CKK_SHA384_HMAC:
	case CKK_SHA512_HMAC:
	case CKK_SHA3_224_HMAC:
	case CKK_SHA3_256_HMAC:
	case CKK_SHA3_384_HMAC:
	case CKK_SHA3_512_HMAC:
	case CKK_GENERIC_SECRET:
	case CKK_HKDF:
		ret = key_hmac_create(hsession, obj, attrs);
		break;

	default:
		break;
	}

	return ret;
}

/**
 * subkey_secret_retrieve() - Retrieve a secret subkey object
 * @hsession: Session handle
 * @obj: Key object
 * @attrs: List of object attributes
 *
 * Call the key object type retrieve function.
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
static CK_RV subkey_secret_retrieve(CK_SESSION_HANDLE hsession,
				    struct libobj_obj *obj,
				    struct libattr_list *attrs)
{
	CK_RV ret = CKR_FUNCTION_FAILED;

	switch (get_key_type(obj)) {
	case CKK_AES:
	case CKK_DES:
	case CKK_DES3:
	case CKK_SM4:
		ret = key_cipher_retrieve(hsession, obj, attrs);
		break;

	case CKK_MD5_HMAC:
	case CKK_SHA_1_HMAC:
	case CKK_SHA224_HMAC:
	case CKK_SHA256_HMAC:
	case CKK_SHA384_HMAC:
	case CKK_SHA512_HMAC:
	case CKK_SHA3_224_HMAC:
	case CKK_SHA3_256_HMAC:
	case CKK_SHA3_384_HMAC:
	case CKK_SHA3_512_HMAC:
	case CKK_GENERIC_SECRET:
	case CKK_HKDF:
		ret = key_hmac_retrieve(hsession, obj, attrs);
		break;

	default:
		break;
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
	CK_RV ret = CKR_OK;
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
	case CKK_SM4:
		ret = key_cipher_get_attribute(attr, obj, protect);
		break;

	case CKK_MD5_HMAC:
	case CKK_SHA_1_HMAC:
	case CKK_SHA224_HMAC:
	case CKK_SHA256_HMAC:
	case CKK_SHA384_HMAC:
	case CKK_SHA512_HMAC:
	case CKK_SHA3_224_HMAC:
	case CKK_SHA3_256_HMAC:
	case CKK_SHA3_384_HMAC:
	case CKK_SHA3_512_HMAC:
	case CKK_GENERIC_SECRET:
	case CKK_HKDF:
		ret = key_hmac_get_attribute(attr, obj, protect);
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
	CK_RV ret = CKR_OK;

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
	case CKK_SM4:
		ret = key_cipher_modify_attribute(attr, obj);
		break;

	case CKK_MD5_HMAC:
	case CKK_SHA_1_HMAC:
	case CKK_SHA224_HMAC:
	case CKK_SHA256_HMAC:
	case CKK_SHA384_HMAC:
	case CKK_SHA512_HMAC:
	case CKK_SHA3_224_HMAC:
	case CKK_SHA3_256_HMAC:
	case CKK_SHA3_384_HMAC:
	case CKK_SHA3_512_HMAC:
	case CKK_GENERIC_SECRET:
	case CKK_HKDF:
		ret = key_hmac_modify_attribute(attr, obj);
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
	CK_RV ret = CKR_FUNCTION_FAILED;

	switch (get_key_type(obj)) {
	case CKK_EC:
	case CKK_EC_EDWARDS:
		ret = key_ec_private_create(hsession, obj, attrs);
		break;

	case CKK_RSA:
		ret = key_rsa_private_create(hsession, obj, attrs);
		break;

	default:
		break;
	}

	return ret;
}

/**
 * subkey_private_retrieve() - Retrieve a private subkey object
 * @hsession: Session handle
 * @obj: Key object
 * @attrs: List of object attributes
 *
 * Call the key object type retrieve function.
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
static CK_RV subkey_private_retrieve(CK_SESSION_HANDLE hsession,
				     struct libobj_obj *obj)
{
	CK_RV ret = CKR_FUNCTION_FAILED;

	switch (get_key_type(obj)) {
	case CKK_EC:
	case CKK_EC_EDWARDS:
		ret = key_ec_private_retrieve(hsession, obj);
		break;

	case CKK_RSA:
		ret = key_rsa_private_retrieve(hsession, obj);
		break;

	default:
		break;
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
	CK_RV ret = CKR_OK;
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
	case CKK_EC_EDWARDS:
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
	CK_RV ret = CKR_OK;

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
	case CKK_EC_EDWARDS:
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
	CK_RV ret = CKR_FUNCTION_FAILED;

	switch (get_key_type(obj)) {
	case CKK_EC:
	case CKK_EC_EDWARDS:
		ret = key_ec_public_create(hsession, obj, attrs);
		break;

	case CKK_RSA:
		ret = key_rsa_public_create(hsession, obj, attrs);
		break;

	default:
		break;
	}

	return ret;
}

/**
 * subkey_public_retrieve() - Retrieve a public subkey object
 * @hsession: Session handle
 * @obj: Key object
 * @attrs: List of object attributes
 *
 * Call the key object type retrieve function.
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
static CK_RV subkey_public_retrieve(CK_SESSION_HANDLE hsession,
				    struct libobj_obj *obj)
{
	CK_RV ret = CKR_FUNCTION_FAILED;

	switch (get_key_type(obj)) {
	case CKK_EC:
	case CKK_EC_EDWARDS:
		ret = key_ec_public_retrieve(hsession, obj);
		break;

	case CKK_RSA:
		ret = key_rsa_public_retrieve(hsession, obj);
		break;

	default:
		break;
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
	CK_RV ret = CKR_OK;

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
	case CKK_EC_EDWARDS:
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
	CK_RV ret = CKR_OK;

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
	case CKK_EC_EDWARDS:
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
	CK_RV ret = CKR_HOST_MEMORY;
	struct libobj_key *new_key = NULL;

	new_key = key_allocate(obj);
	if (!new_key)
		return ret;

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
	CK_RV ret = CKR_HOST_MEMORY;
	struct libobj_key *new_key = NULL;

	new_key = key_allocate(obj);
	if (!new_key)
		return ret;

	DBG_TRACE("Generate a new key (%p)", new_key);

	new_key->type = key_type;
	ret = attr_get_value(new_key, &attr_key_common[KEY_TYPE], attrs,
			     OPTIONAL);
	if (ret != CKR_OK)
		return ret;

	if (new_key->type != key_type && key_type != CKK_GENERIC_SECRET)
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

static CK_RV allocate_derived_key(struct libobj_obj *obj,
				  struct libattr_list *attrs)
{
	CK_RV ret = CKR_HOST_MEMORY;
	struct libobj_key *new_key = NULL;

	new_key = key_allocate(obj);
	if (!new_key)
		return ret;

	DBG_TRACE("Derived key (%p)", new_key);

	ret = attr_get_value(new_key, &attr_key_common[KEY_TYPE], attrs,
			     OPTIONAL);
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

void key_free(struct libobj_obj *obj)
{
	struct libobj_key *key = get_subobj_from(obj, storage);

	if (!key)
		return;

	DBG_TRACE("Free key (%p)", key);

	if (key->id.array)
		free(key->id.array);

	if (key->mech_list.mech)
		free(key->mech_list.mech);

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
	CK_RV ret = CKR_GENERAL_ERROR;

	DBG_TRACE("Create a new key type object");

	if (!obj)
		return ret;

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
			ret = key_secret_new(obj, attrs, false);
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

CK_RV key_keypair_retrieve(CK_SESSION_HANDLE hsession,
			   struct libobj_obj *pub_obj,
			   struct libobj_obj *priv_obj,
			   struct libattr_list *attrs, unsigned int id)
{
	CK_RV ret = CKR_GENERAL_ERROR;

	DBG_TRACE("Retrieve a keypair object Public key (%p) Private key (%p)",
		  pub_obj, priv_obj);

	if (!pub_obj || !priv_obj)
		return ret;

	/*
	 * Create the public key
	 */
	ret = create_key_new(pub_obj, attrs);
	if (ret != CKR_OK)
		goto end;

	ret = key_public_new(hsession, pub_obj, attrs);
	if (ret != CKR_OK)
		goto end;

	/*
	 * Create the private key
	 */
	ret = create_key_new(priv_obj, attrs);
	if (ret != CKR_OK)
		goto end;

	ret = key_private_new(priv_obj, attrs);
	if (ret != CKR_OK)
		goto end;

	set_key_token_id(pub_obj, id);
	set_key_token_id(priv_obj, id);

	switch (get_key_type(priv_obj)) {
	case CKK_EC:
	case CKK_EC_EDWARDS:
		ret = key_ec_keypair_retrieve(hsession, pub_obj, priv_obj);
		break;

	case CKK_RSA:
		ret = key_rsa_keypair_retrieve(hsession, pub_obj, priv_obj);
		break;

	default:
		ret = CKR_FUNCTION_FAILED;
		break;
	}

end:
	DBG_TRACE("Keypair object (pub=%p priv=%p) retrieve return %ld",
		  pub_obj, priv_obj, ret);
	return ret;
}

CK_RV key_retrieve(CK_SESSION_HANDLE hsession, struct libobj_obj *obj,
		   struct libattr_list *attrs, unsigned int id)
{
	CK_RV ret = CKR_GENERAL_ERROR;

	DBG_TRACE("Retrieve a key type object");

	if (!obj)
		return ret;

	ret = create_key_new(obj, attrs);
	if (ret != CKR_OK)
		goto end;

	switch (obj->class) {
	case CKO_PUBLIC_KEY:
		ret = key_public_new(hsession, obj, attrs);
		if (ret == CKR_OK) {
			set_key_token_id(obj, id);
			ret = subkey_public_retrieve(hsession, obj);
		}
		break;

	case CKO_PRIVATE_KEY:
		ret = key_private_new(obj, attrs);
		if (ret == CKR_OK) {
			set_key_token_id(obj, id);
			ret = subkey_private_retrieve(hsession, obj);
		}
		break;

	case CKO_SECRET_KEY:
		ret = key_secret_new(obj, attrs, false);
		if (ret == CKR_OK) {
			set_key_token_id(obj, id);
			ret = subkey_secret_retrieve(hsession, obj, attrs);
		}
		break;

	default:
		ret = CKR_GENERAL_ERROR;
		break;
	}

end:
	DBG_TRACE("Key type object (%p) return %ld", obj, ret);
	return ret;
}

CK_RV key_get_attribute(CK_ATTRIBUTE_PTR attr, const struct libobj_obj *obj)
{
	CK_RV ret = CKR_OK;

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
	CK_RV ret = CKR_OK;

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
	CK_RV ret = CKR_GENERAL_ERROR;
	CK_KEY_TYPE key_type = 0;

	DBG_TRACE("Generate a new keypair type object");

	if (!pub_key || !priv_key)
		return ret;

	switch (mech->mechanism) {
	case CKM_EC_KEY_PAIR_GEN:
		key_type = CKK_EC;
		break;

	case CKM_EC_EDWARDS_KEY_PAIR_GEN:
		key_type = CKK_EC_EDWARDS;
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

	switch (key_type) {
	case CKK_EC:
	case CKK_EC_EDWARDS:
		ret = key_ec_keypair_generate(hsession, mech, pub_key,
					      pub_attrs, priv_key, priv_attrs);
		break;

	case CKK_RSA:
		ret = key_rsa_keypair_generate(hsession, mech, pub_key,
					       pub_attrs, priv_key, priv_attrs);
		break;
	}

end:
	DBG_TRACE("Keypair object (pub=%p priv=%p) generate return %ld",
		  pub_key, priv_key, ret);
	return ret;
}

CK_RV key_secret_key_generate(CK_SESSION_HANDLE hsession, CK_MECHANISM_PTR mech,
			      struct libobj_obj *obj,
			      struct libattr_list *attrs)
{
	CK_RV ret = CKR_GENERAL_ERROR;
	CK_KEY_TYPE key_type = 0;

	DBG_TRACE("Generate a new secret key type object");

	if (!obj)
		return ret;

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

	case CKM_SM4_KEY_GEN:
		key_type = CKK_SM4;
		break;

	case CKM_GENERIC_SECRET_KEY_GEN:
		key_type = CKK_GENERIC_SECRET;
		break;

	case CKM_HKDF_KEY_GEN:
		key_type = CKK_HKDF;
		break;

	default:
		return CKR_MECHANISM_INVALID;
	}

	ret = generate_key_new(obj, attrs, mech, key_type);
	if (ret != CKR_OK)
		goto end;

	key_type = get_key_type(obj);

	ret = key_secret_new(obj, attrs, false);
	if (ret != CKR_OK)
		goto end;

	switch (key_type) {
	case CKK_AES:
	case CKK_DES:
	case CKK_DES3:
	case CKK_SM4:
		ret = key_cipher_generate(hsession, mech, obj, attrs);
		break;

	case CKK_MD5_HMAC:
	case CKK_SHA_1_HMAC:
	case CKK_SHA224_HMAC:
	case CKK_SHA256_HMAC:
	case CKK_SHA384_HMAC:
	case CKK_SHA512_HMAC:
	case CKK_SHA3_224_HMAC:
	case CKK_SHA3_256_HMAC:
	case CKK_SHA3_384_HMAC:
	case CKK_SHA3_512_HMAC:
	case CKK_GENERIC_SECRET:
	case CKK_HKDF:
		ret = key_hmac_generate(hsession, mech, obj, attrs);
		break;

	default:
		ret = CKR_FUNCTION_FAILED;
		break;
	}

end:
	DBG_TRACE("Secret Key object (%p) generate return %ld", obj, ret);
	return ret;
}

static CK_RV
check_hkdf_derive_mech_params(CK_MECHANISM_PTR mech,
			      struct libobj_key_derive_params *derive_params)
{
	CK_RV ret = CKR_MECHANISM_PARAM_INVALID;
	CK_HKDF_PARAMS_PTR hkdf_params = NULL_PTR;

	if (!mech->pParameter) {
		DBG_TRACE("CKM_HKDF_DERIVE mechanism pParameter not set");
		goto end;
	}

	if (mech->ulParameterLen != sizeof(CK_HKDF_PARAMS)) {
		DBG_TRACE("CKM_HKDF_DERIVE mechanism ulParameterLen error");
		goto end;
	}

	hkdf_params = (CK_HKDF_PARAMS_PTR)mech->pParameter;
	if (!hkdf_params->bExtract && !hkdf_params->bExpand)
		goto end;

	derive_params->hkdf_params.extract = hkdf_params->bExtract;
	derive_params->hkdf_params.expand = hkdf_params->bExpand;

	derive_params->hkdf_params.prf_hash_mech =
		hkdf_params->prfHashMechanism;

	derive_params->hkdf_params.salt_type = hkdf_params->ulSaltType;
	if (hkdf_params->bExtract) {
		if (hkdf_params->ulSaltType == CKF_HKDF_SALT_KEY) {
			if (!derive_params->ctx) {
				DBG_TRACE("CKF_HKDF_SALT_KEY not supported");
				ret = CKR_FUNCTION_NOT_SUPPORTED;
				goto end;
			}
		} else if (hkdf_params->ulSaltType == CKF_HKDF_SALT_DATA) {
			if (!hkdf_params->pSalt != !hkdf_params->ulSaltLen)
				goto end;

			derive_params->hkdf_params.salt = hkdf_params->pSalt;
			derive_params->hkdf_params.salt_len =
				hkdf_params->ulSaltLen;
		}
	}

	if (hkdf_params->bExpand) {
		if (!hkdf_params->pInfo != !hkdf_params->ulInfoLen)
			goto end;

		derive_params->hkdf_params.info = hkdf_params->pInfo;
		derive_params->hkdf_params.info_len = hkdf_params->ulInfoLen;
	}

	ret = CKR_OK;

end:
	return ret;
}

static CK_RV
check_ecdh_derive_mech_params(CK_MECHANISM_PTR mech,
			      struct libobj_key_derive_params *derive_params)
{
	CK_RV ret = CKR_MECHANISM_PARAM_INVALID;
	CK_ECDH1_DERIVE_PARAMS_PTR ecdh_params = NULL_PTR;

	if (!mech->pParameter) {
		DBG_TRACE("CKM_ECDH1_DERIVE mechanism pParameter not set");
		goto end;
	}

	if (mech->ulParameterLen != sizeof(CK_ECDH1_DERIVE_PARAMS)) {
		DBG_TRACE("CKM_ECDH1_DERIVE mechanism ulParameterLen error");
		goto end;
	}

	ecdh_params = (CK_ECDH1_DERIVE_PARAMS_PTR)mech->pParameter;

	derive_params->ecdh_params.kdf = ecdh_params->kdf;
	derive_params->ecdh_params.pPublicData = ecdh_params->pPublicData;
	derive_params->ecdh_params.pSharedData = ecdh_params->pSharedData;
	derive_params->ecdh_params.ulPublicDataLen =
		ecdh_params->ulPublicDataLen;
	derive_params->ecdh_params.ulSharedDataLen =
		ecdh_params->ulSharedDataLen;

	ret = CKR_OK;

end:
	return ret;
}

static CK_RV
check_tls12_derive_mech_params(CK_MECHANISM_PTR mech,
			       struct libobj_key_derive_params *derive_params)
{
	CK_RV ret = CKR_MECHANISM_PARAM_INVALID;
	CK_TLS12_KEY_MAT_PARAMS_PTR tls12_params = NULL_PTR;
	CK_TLS12_MASTER_KEY_DERIVE_PARAMS_PTR tls12_master_params = NULL_PTR;
	CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS_PTR
	tls12_extended_master_params = NULL_PTR;

	if (!mech->pParameter) {
		DBG_TRACE("TLS 1.2 mechanism pParameter not set");
		goto end;
	}

	switch (mech->mechanism) {
	case CKM_TLS12_KEY_AND_MAC_DERIVE:
		if (mech->ulParameterLen != sizeof(CK_TLS12_KEY_MAT_PARAMS)) {
			DBG_TRACE("TLS 1.2 mechanism ulParameterLen error");
			goto end;
		}
		tls12_params = (CK_TLS12_KEY_MAT_PARAMS_PTR)mech->pParameter;

		derive_params->tls12_params.bIsExport = tls12_params->bIsExport;
		derive_params->tls12_params.pReturnedKeyMaterial =
			tls12_params->pReturnedKeyMaterial;
		derive_params->tls12_params.prfHashMechanism =
			tls12_params->prfHashMechanism;
		derive_params->tls12_params.RandomInfo =
			tls12_params->RandomInfo;
		derive_params->tls12_params.ulIVSizeInBits =
			tls12_params->ulIVSizeInBits;
		derive_params->tls12_params.ulKeySizeInBits =
			tls12_params->ulKeySizeInBits;
		derive_params->tls12_params.ulMacSizeInBits =
			tls12_params->ulMacSizeInBits;
		ret = CKR_OK;
		break;

	case CKM_TLS12_MASTER_KEY_DERIVE_DH:
		if (mech->ulParameterLen !=
		    sizeof(CK_TLS12_MASTER_KEY_DERIVE_PARAMS)) {
			DBG_TRACE("TLS 1.2 mechanism ulParameterLen error");
			goto end;
		}
		tls12_master_params =
			(CK_TLS12_MASTER_KEY_DERIVE_PARAMS_PTR)mech->pParameter;

		derive_params->tls12_params.prfHashMechanism =
			tls12_master_params->prfHashMechanism;
		derive_params->tls12_params.RandomInfo =
			tls12_master_params->RandomInfo;
		derive_params->tls12_params.pVersion =
			tls12_master_params->pVersion;
		ret = CKR_OK;
		break;

	case CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH:
		if (mech->ulParameterLen !=
		    sizeof(CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS)) {
			DBG_TRACE("TLS 1.2 mechanism ulParameterLen error");
			goto end;
		}
		tls12_extended_master_params =
			(CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS_PTR)
				mech->pParameter;

		derive_params->tls12_params.prfHashMechanism =
			tls12_extended_master_params->prfHashMechanism;
		derive_params->tls12_params.pSessionHash =
			tls12_extended_master_params->pSessionHash;
		derive_params->tls12_params.ulSessionHashLen =
			tls12_extended_master_params->ulSessionHashLen;
		derive_params->tls12_params.pVersion =
			tls12_extended_master_params->pVersion;
		ret = CKR_OK;
		break;

	default:
		break;
	}

end:
	return ret;
}

static CK_RV check_input_params(CK_KEY_TYPE base_key_type,
				CK_MECHANISM_PTR mech,
				struct libobj_key_derive_params *derive_params)
{
	CK_RV ret = CKR_FUNCTION_NOT_SUPPORTED;

	switch (mech->mechanism) {
	case CKM_HKDF_DERIVE:
		if (base_key_type != CKK_HKDF &&
		    base_key_type != CKK_GENERIC_SECRET) {
			ret = CKR_KEY_FUNCTION_NOT_PERMITTED;
			break;
		}

		ret = check_hkdf_derive_mech_params(mech, derive_params);
		break;

	case CKM_ECDH1_DERIVE:
		if (base_key_type != CKK_EC) {
			ret = CKR_KEY_FUNCTION_NOT_PERMITTED;
			break;
		}

		ret = check_ecdh_derive_mech_params(mech, derive_params);
		break;

	case CKM_TLS12_KEY_AND_MAC_DERIVE:
	case CKM_TLS12_MASTER_KEY_DERIVE_DH:
	case CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH:
		if (base_key_type != CKK_GENERIC_SECRET) {
			ret = CKR_KEY_FUNCTION_NOT_PERMITTED;
			break;
		}

		ret = check_tls12_derive_mech_params(mech, derive_params);
		break;

	default:
		break;
	}

	return ret;
}

static CK_RV
set_kdf_derived_key_attr(CK_SESSION_HANDLE hsession,
			 struct libobj_key_derive_params *derive_params,
			 struct libattr_list *attrs)
{
	CK_RV ret = CKR_OK;

	CK_BBOOL base_key_always_sens = CK_FALSE;
	CK_BBOOL base_key_never_extr = CK_FALSE;

	CK_BBOOL derived_key_always_sens = CK_FALSE;
	CK_BBOOL derived_key_never_extr = CK_FALSE;
	CK_BBOOL derived_key_sensitive = CK_FALSE;
	CK_BBOOL derived_key_extractable = CK_FALSE;

	CK_OBJECT_HANDLE base_key = derive_params->base_key;
	struct libobj_obj *derived_key = derive_params->derived_key;
	unsigned int i = 0;

	CK_ATTRIBUTE base_key_attr[] = {
		{ CKA_ALWAYS_SENSITIVE, &base_key_always_sens,
		  sizeof(base_key_always_sens) },
		{ CKA_NEVER_EXTRACTABLE, &base_key_never_extr,
		  sizeof(base_key_never_extr) },
	};

	CK_ATTRIBUTE derived_key_attr[] = {
		{ CKA_SENSITIVE, &derived_key_sensitive,
		  sizeof(derived_key_sensitive) },
		{ CKA_EXTRACTABLE, &derived_key_extractable,
		  sizeof(derived_key_extractable) },
	};

	CK_ATTRIBUTE attr[] = {
		{ CKA_ALWAYS_SENSITIVE, &derived_key_always_sens,
		  sizeof(derived_key_always_sens) },
		{ CKA_NEVER_EXTRACTABLE, &derived_key_never_extr,
		  sizeof(derived_key_never_extr) }
	};

	ret = libobj_get_attribute(hsession, base_key, base_key_attr,
				   ARRAY_SIZE(base_key_attr));
	if (ret != CKR_OK)
		return ret;

	for (; i < ARRAY_SIZE(derived_key_attr); i++) {
		ret = attr_get_obj_value(&derived_key_attr[i], attr_key_secret,
					 ARRAY_SIZE(attr_key_secret),
					 get_key_from(derived_key));
		if (ret != CKR_OK)
			return ret;
	}

	if (derive_params->ctx && derive_params->ctx->extractable) {
		derived_key_always_sens = CK_FALSE;
		derived_key_never_extr = CK_FALSE;
		derived_key_extractable = CK_TRUE;
		ret = attr_set_value(get_key_from(derived_key),
				     &derived_key_attr[1],
				     &attr_key_secret[SECR_EXTRACTABLE], attrs,
				     NO_OVERWRITE);
		if (ret != CKR_OK)
			return ret;
	} else {
		derived_key_always_sens =
			(!base_key_always_sens ? base_key_always_sens :
						 derived_key_sensitive);
		derived_key_never_extr =
			(!base_key_never_extr ? base_key_never_extr :
						!derived_key_extractable);
	}

	/* Based on the base key attributes, set the derived key attributes. */
	ret = attr_set_value(get_key_from(derived_key), &attr[0],
			     &attr_key_secret[SECR_ALWAYS_SENSITIVE], attrs,
			     MUST_NOT);
	if (ret != CKR_OK)
		return ret;

	ret = attr_set_value(get_key_from(derived_key), &attr[1],
			     &attr_key_secret[SECR_NEVER_EXTRACTABLE], attrs,
			     MUST_NOT);

	return ret;
}

static CK_RV
set_derived_key_attr(CK_SESSION_HANDLE hsession,
		     struct libobj_key_derive_params *derive_params,
		     CK_MECHANISM_TYPE mech, struct libattr_list *attrs)
{
	CK_RV ret = CKR_FUNCTION_NOT_SUPPORTED;

	switch (mech) {
	case CKM_HKDF_DERIVE:
	case CKM_ECDH1_DERIVE:
	case CKM_TLS12_KEY_AND_MAC_DERIVE:
	case CKM_TLS12_MASTER_KEY_DERIVE_DH:
	case CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH:
		ret = set_kdf_derived_key_attr(hsession, derive_params, attrs);
		break;

	default:
		break;
	}

	return ret;
}

/**
 * destroy_context() - Destroy derive context
 * @ctx: Pointer to derive context
 *
 */
static void destroy_context(struct lib_derive_ctx *ctx)
{
	if (ctx) {
		if (ctx->peer_buffer)
			free(ctx->peer_buffer);

		free(ctx);
	}
}

CK_RV derive_key(CK_SESSION_HANDLE hsession, CK_MECHANISM_PTR mech,
		 CK_OBJECT_HANDLE base_key, struct libobj_obj *derived_key,
		 struct libattr_list *attrs)
{
	CK_RV ret = CKR_GENERAL_ERROR;
	CK_BYTE_PTR label = NULL;
	CK_KEY_TYPE key_type = 0;
	CK_KEY_TYPE base_key_type = 0;
	CK_MECHANISM find_mech = { 0 };
	struct lib_derive_ctx *ctx = NULL;
	struct libdevice *device = NULL;
	struct libobj_key_derive_params derive_params = { 0 };
	struct libmech_list *mech_list = NULL;
	/* ASCII: "finished", in hex for EBCDIC compatibility */
	static const char finishedlabel[] = "\x66\x69\x6E\x69\x73\x68\x65\x64";

	DBG_TRACE("Derive a secret key from base key object");

	if (!derived_key)
		goto end;

	ret = libsess_get_device(hsession, &device);
	if (ret != CKR_OK)
		goto end;

	switch (mech->mechanism) {
	case CKM_HKDF_DERIVE:
	case CKM_TLS12_MASTER_KEY_DERIVE_DH:
	case CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH:
	case CKM_TLS12_KEY_AND_MAC_DERIVE:
		/* Get the previous ECDH parameters */
		ret = libdev_find_opctx(device, CKF_DERIVE, &find_mech,
					(void **)&ctx);

		if (ret == CKR_OK && find_mech.mechanism == CKM_ECDH1_DERIVE) {
			derive_params.ctx = ctx;
			ctx->skipped = false;
			ctx->extractable = false;
			ctx->shared_buffer = NULL;
			ctx->shared_buffer_len = 0;
		}

		break;

	default:
		break;
	}

	base_key_type = get_key_type((struct libobj_obj *)base_key);

	ret = check_input_params(base_key_type, mech, &derive_params);
	if (ret != CKR_OK)
		goto end;

	ret = allocate_derived_key(derived_key, attrs);
	if (ret != CKR_OK)
		goto end;

	ret = key_secret_new(derived_key, attrs, true);
	if (ret != CKR_OK)
		goto end;

	mech_list = get_key_mech_list(derived_key);
	if (mech_list && mech_list->number) {
		switch (mech_list->mech[0]) {
		case CKM_TLS12_MASTER_KEY_DERIVE_DH:
		case CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH:
		case CKM_HKDF_DERIVE:
			if (mech->mechanism == CKM_ECDH1_DERIVE) {
				/* Remove previous operation context */
				ret = libdev_find_opctx(device, CKF_DERIVE,
							&find_mech,
							(void **)&ctx);
				if (ret == CKR_OK) {
					(void)libdev_remove_opctx(device,
								  CKF_DERIVE);
					destroy_context(ctx);
				}

				ctx = calloc(1, sizeof(*ctx));
				if (!ctx) {
					ret = CKR_HOST_MEMORY;
					goto end;
				}

				/* Set current operation context */
				ret = libdev_add_opctx(device, CKF_DERIVE, mech,
						       ctx);
				if (ret != CKR_OK)
					goto end;

				derive_params.ctx = ctx;
			}
			break;
		default:
			break;
		}
	}

	derive_params.hsession = hsession;
	derive_params.derived_key = derived_key;
	derive_params.base_key = base_key;

	key_type = get_key_type(derived_key);

	switch (key_type) {
	case CKK_AES:
	case CKK_DES:
	case CKK_DES3:
	case CKK_SM4:
		ret = key_cipher_derive(hsession, mech, &derive_params, attrs);
		break;

	case CKK_MD5_HMAC:
	case CKK_SHA_1_HMAC:
	case CKK_SHA224_HMAC:
	case CKK_SHA256_HMAC:
	case CKK_SHA384_HMAC:
	case CKK_SHA512_HMAC:
	case CKK_SHA3_224_HMAC:
	case CKK_SHA3_256_HMAC:
	case CKK_SHA3_384_HMAC:
	case CKK_SHA3_512_HMAC:
	case CKK_GENERIC_SECRET:
	case CKK_HKDF:
		ret = key_hmac_derive(hsession, mech, &derive_params, attrs);
		break;

	default:
		ret = CKR_KEY_TYPE_INCONSISTENT;
		break;
	}

	if (ret != CKR_OK)
		goto end;

	ret = set_derived_key_attr(hsession, &derive_params, mech->mechanism,
				   attrs);

end:
	if (ret != CKR_OK) {
		if (mech->mechanism == CKM_ECDH1_DERIVE && ctx) {
			(void)libdev_remove_opctx(device, CKF_DERIVE);
			destroy_context(ctx);
		}
	} else {
		switch (mech->mechanism) {
		case CKM_HKDF_DERIVE:
			if (!ctx)
				break;

			if (!derive_params.hkdf_params.info ||
			    derive_params.hkdf_params.info_len !=
				    TLS13_LABEL_OFFSET + sizeof(finishedlabel))
				break;

			label = &derive_params.hkdf_params
					 .info[TLS13_LABEL_OFFSET];
			if (strncmp((char *)label, finishedlabel,
				    sizeof(finishedlabel)))
				break;

			if (ctx->context)
				(void)libdev_cancel_operation(&ctx->context);

			(void)libdev_remove_opctx(device, CKF_DERIVE);
			destroy_context(ctx);
			break;

		case CKM_TLS12_KEY_AND_MAC_DERIVE:
			if (!ctx)
				break;

			(void)libdev_remove_opctx(device, CKF_DERIVE);
			destroy_context(ctx);
			break;

		default:
			break;
		}
	}

	DBG_TRACE("Derive secret Key object (%p) return %ld",
		  derive_params.derived_key, ret);
	return ret;
}

CK_BBOOL is_hkdf_extract_set(CK_MECHANISM_PTR mech)
{
	CK_BBOOL is_hkdf_extract_set = false;

	CK_HKDF_PARAMS_PTR hkdf_params = NULL_PTR;

	if (mech->mechanism == CKM_HKDF_DERIVE) {
		hkdf_params = (CK_HKDF_PARAMS_PTR)mech->pParameter;
		if (hkdf_params->bExtract && !hkdf_params->bExpand)
			is_hkdf_extract_set = true;
	}

	return is_hkdf_extract_set;
}

CK_BBOOL is_tls_hkdf(CK_SESSION_HANDLE hsession, CK_MECHANISM_PTR mech)
{
	CK_RV ret = CKR_OK;
	CK_BBOOL skip_tls_hkdf = false;
	CK_MECHANISM find_mech = { 0 };

	struct lib_derive_ctx *ctx = NULL;
	struct libdevice *device = NULL;

	if (mech->mechanism == CKM_ECDH1_DERIVE ||
	    mech->mechanism == CKM_HKDF_DERIVE) {
		ret = libsess_get_device(hsession, &device);
		if (ret == CKR_OK) {
			(void)libdev_find_opctx(device, CKF_DERIVE, &find_mech,
						(void **)&ctx);
			if (ctx)
				skip_tls_hkdf =
					ctx->skipped || ctx->shared_buffer;
		}
	}

	return skip_tls_hkdf;
}
