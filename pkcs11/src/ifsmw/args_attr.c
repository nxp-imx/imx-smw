// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2025 NXP
 */

#include "smw/attr.h"

#include "libobj_types.h"

#include "args_attr.h"

static void set_common_key_usage(smw_attr_usage_t *usage_flags,
				 struct libobj_obj *obj)
{
	if (is_copyable_obj(obj, storage))
		SMW_ATTR_USAGE_SET_COPY(*usage_flags);

	if (is_derive_key(obj))
		SMW_ATTR_USAGE_SET_DERIVE(*usage_flags);
}

static void get_common_key_usage(struct libobj_obj *obj,
				 smw_attr_usage_t usage_flags)

{
	if (SMW_ATTR_USAGE_IS_COPY(usage_flags))
		set_copyable_obj(obj, storage);

	if (SMW_ATTR_USAGE_IS_DERIVE(usage_flags))
		set_derive_key(obj);
}

static void set_public_key_usage(smw_attr_usage_t *usage_flags,
				 struct libobj_obj *obj)
{
	struct libobj_key_public *key = get_key_from(obj);

	if (key->encrypt)
		SMW_ATTR_USAGE_SET_ENCRYPT(*usage_flags);

	if (key->verify) {
		SMW_ATTR_USAGE_SET_VERIFY_MESSAGE(*usage_flags);
		SMW_ATTR_USAGE_SET_VERIFY_HASH(*usage_flags);
	}
}

static void get_public_key_usage(struct libobj_obj *obj,
				 smw_attr_usage_t usage_flags)
{
	struct libobj_key_public *key = get_key_from(obj);

	if (SMW_ATTR_USAGE_IS_ENCRYPT(usage_flags))
		key->encrypt = true;

	if (SMW_ATTR_USAGE_IS_VERIFY_MESSAGE(usage_flags) ||
	    SMW_ATTR_USAGE_IS_VERIFY_HASH(usage_flags))
		key->verify = true;
}

static void set_private_key_usage(smw_attr_usage_t *usage_flags,
				  struct libobj_obj *obj)
{
	struct libobj_key_private *key = get_key_from(obj);

	if (key->decrypt)
		SMW_ATTR_USAGE_SET_DECRYPT(*usage_flags);

	if (key->sign) {
		SMW_ATTR_USAGE_SET_SIGN_MESSAGE(*usage_flags);
		SMW_ATTR_USAGE_SET_SIGN_HASH(*usage_flags);
	}

	if (key->extractable && !key->sensitive)
		SMW_ATTR_USAGE_SET_EXPORT(*usage_flags);
}

static void get_private_key_usage(struct libobj_obj *obj,
				  smw_attr_usage_t usage_flags)

{
	struct libobj_key_private *key = get_key_from(obj);

	if (SMW_ATTR_USAGE_IS_DECRYPT(usage_flags))
		key->decrypt = true;

	if (SMW_ATTR_USAGE_IS_SIGN_MESSAGE(usage_flags) ||
	    SMW_ATTR_USAGE_IS_SIGN_HASH(usage_flags))
		key->sign = true;

	if (!key->sensitive && SMW_ATTR_USAGE_IS_EXPORT(usage_flags))
		key->extractable = true;
}

static void set_secret_key_usage(smw_attr_usage_t *usage_flags,
				 struct libobj_obj *obj)
{
	struct libobj_key_secret *key = get_key_from(obj);

	if (key->encrypt)
		SMW_ATTR_USAGE_SET_ENCRYPT(*usage_flags);

	if (key->decrypt)
		SMW_ATTR_USAGE_SET_DECRYPT(*usage_flags);

	if (key->sign)
		SMW_ATTR_USAGE_SET_SIGN_MESSAGE(*usage_flags);

	if (key->verify)
		SMW_ATTR_USAGE_SET_VERIFY_MESSAGE(*usage_flags);

	if (key->extractable && !key->sensitive)
		SMW_ATTR_USAGE_SET_EXPORT(*usage_flags);
}

static void get_secret_key_usage(struct libobj_obj *obj,
				 smw_attr_usage_t usage_flags)

{
	struct libobj_key_secret *key = get_key_from(obj);

	if (SMW_ATTR_USAGE_IS_ENCRYPT(usage_flags))
		key->encrypt = true;

	if (SMW_ATTR_USAGE_IS_DECRYPT(usage_flags))
		key->decrypt = true;

	if (SMW_ATTR_USAGE_IS_SIGN_MESSAGE(usage_flags))
		key->sign = true;

	if (SMW_ATTR_USAGE_IS_VERIFY_MESSAGE(usage_flags))
		key->verify = true;

	if (!key->sensitive && SMW_ATTR_USAGE_IS_EXPORT(usage_flags))
		key->extractable = true;
}

static void set_ec_key_usage(smw_attr_usage_t *usage_flags,
			     struct libobj_obj *obj)
{
	struct libobj_key_ec_pair *key = get_subkey_from(obj);

	switch (key->type) {
	case LIBOBJ_KEY_PUBLIC:
		set_public_key_usage(usage_flags, obj);
		break;

	case LIBOBJ_KEY_PRIVATE:
		set_private_key_usage(usage_flags, obj);
		break;

	default:
		set_private_key_usage(usage_flags, obj);

		if (key->pub_obj)
			set_public_key_usage(usage_flags, key->pub_obj);

		break;
	}
}

static void get_ec_key_usage(struct libobj_obj *obj,
			     smw_attr_usage_t usage_flags)

{
	struct libobj_key_ec_pair *key = get_subkey_from(obj);

	switch (key->type) {
	case LIBOBJ_KEY_PUBLIC:
		get_public_key_usage(obj, usage_flags);
		break;

	case LIBOBJ_KEY_PRIVATE:
		get_private_key_usage(obj, usage_flags);
		break;

	default:
		get_private_key_usage(obj, usage_flags);

		if (key->pub_obj)
			get_public_key_usage(key->pub_obj, usage_flags);

		break;
	}
}

static void set_rsa_key_usage(smw_attr_usage_t *usage_flags,
			      struct libobj_obj *obj)
{
	struct libobj_key_rsa_pair *key = get_subkey_from(obj);

	switch (key->type) {
	case LIBOBJ_KEY_PUBLIC:
		set_public_key_usage(usage_flags, obj);
		break;

	case LIBOBJ_KEY_PRIVATE:
		set_private_key_usage(usage_flags, obj);
		break;

	default:
		set_private_key_usage(usage_flags, obj);

		if (key->pub_obj)
			set_public_key_usage(usage_flags, key->pub_obj);

		break;
	}
}

static void get_rsa_key_usage(struct libobj_obj *obj,
			      smw_attr_usage_t usage_flags)

{
	struct libobj_key_rsa_pair *key = get_subkey_from(obj);

	switch (key->type) {
	case LIBOBJ_KEY_PUBLIC:
		get_public_key_usage(obj, usage_flags);
		break;

	case LIBOBJ_KEY_PRIVATE:
		get_private_key_usage(obj, usage_flags);
		break;

	default:
		get_private_key_usage(obj, usage_flags);

		if (key->pub_obj)
			get_public_key_usage(key->pub_obj, usage_flags);

		break;
	}
}

void args_attrs_key_usage(smw_attr_usage_t *usage_flags, struct libobj_obj *obj)
{
	switch (get_key_type(obj)) {
	case CKK_AES:
	case CKK_DES:
	case CKK_DES3:
	case CKK_SM4:
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
	case CKK_HKDF:
		set_secret_key_usage(usage_flags, obj);
		break;

	case CKK_EC:
		set_ec_key_usage(usage_flags, obj);
		break;

	case CKK_RSA:
		set_rsa_key_usage(usage_flags, obj);
		break;

	default:
		break;
	}

	set_common_key_usage(usage_flags, obj);
}

void args_attr_get_key_usage(struct libobj_obj *obj,
			     smw_attr_attributes_t usage_flags)
{
	switch (get_key_type(obj)) {
	case CKK_AES:
	case CKK_DES:
	case CKK_DES3:
	case CKK_SM4:
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
	case CKK_HKDF:
		get_secret_key_usage(obj, usage_flags);
		break;

	case CKK_EC:
		get_ec_key_usage(obj, usage_flags);
		break;

	case CKK_RSA:
		get_rsa_key_usage(obj, usage_flags);
		break;

	default:
		break;
	}

	get_common_key_usage(obj, usage_flags);
}

void args_attr_obj_storage(smw_attr_attributes_t *attr, struct libobj_obj *obj)
{
	if (is_token_obj(obj, storage))
		*attr = SMW_ATTR_SET_PERSISTENT(*attr);

	if (!is_modifiable_obj(obj, storage))
		*attr = SMW_ATTR_SET_READ_ONLY(*attr);
}

void args_attr_get_obj_storage(struct libobj_obj *obj,
			       smw_attr_attributes_t attr)
{
	if (SMW_ATTR_IS_PERSISTENT(attr) || SMW_ATTR_IS_PERMANENT(attr))
		set_token_obj(obj, storage);

	if (SMW_ATTR_IS_READ_ONLY(attr))
		set_non_modifiable_obj(obj, storage);
}
