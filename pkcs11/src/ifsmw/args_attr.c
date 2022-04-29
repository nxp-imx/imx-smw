// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2022 NXP
 */

#include "libobj_types.h"

#include "args_attr.h"
#include "tlv_encode.h"

#include "trace.h"

static CK_RV set_sign_usage(struct smw_tlv *policy,
			    struct smw_tlv *allowed_algos)
{
	CK_RV ret;

	ret = tlv_encode_concat_string(policy, SMW_ATTR_USAGE,
				       SMW_ATTR_USAGE_SIGN_MSG, allowed_algos);
	if (ret == CKR_OK)
		ret = tlv_encode_concat_string(policy, SMW_ATTR_USAGE,
					       SMW_ATTR_USAGE_SIGN_HASH,
					       allowed_algos);

	return ret;
}

static CK_RV set_verify_usage(struct smw_tlv *policy,
			      struct smw_tlv *allowed_algos)
{
	CK_RV ret;

	ret = tlv_encode_concat_string(policy, SMW_ATTR_USAGE,
				       SMW_ATTR_USAGE_VERIFY_MSG,
				       allowed_algos);
	if (ret == CKR_OK)
		ret = tlv_encode_concat_string(policy, SMW_ATTR_USAGE,
					       SMW_ATTR_USAGE_VERIFY_HASH,
					       allowed_algos);

	return ret;
}

static CK_RV set_common_key_usage(struct smw_tlv *policy,
				  struct libobj_obj *obj,
				  struct smw_tlv *allowed_algos)
{
	CK_RV ret = CKR_OK;

	if (is_copyable_obj(obj, storage))
		ret = tlv_encode_string(policy, SMW_ATTR_USAGE,
					SMW_ATTR_USAGE_COPY);

	if (ret == CKR_OK && is_derive_key(obj))
		ret = tlv_encode_concat_string(policy, SMW_ATTR_USAGE,
					       SMW_ATTR_USAGE_DERIVE,
					       allowed_algos);

	return ret;
}

static CK_RV set_public_key_usage(struct smw_tlv *policy,
				  struct libobj_obj *obj,
				  struct smw_tlv *allowed_algos)
{
	CK_RV ret = CKR_OK;
	struct libobj_key_public *key = get_key_from(obj);

	if (key->encrypt)
		ret = tlv_encode_concat_string(policy, SMW_ATTR_USAGE,
					       SMW_ATTR_USAGE_ENCRYPT,
					       allowed_algos);

	if (ret == CKR_OK && key->verify)
		ret = set_verify_usage(policy, allowed_algos);

	return ret;
}

static CK_RV set_private_key_usage(struct smw_tlv *policy,
				   struct libobj_obj *obj,
				   struct smw_tlv *allowed_algos)
{
	CK_RV ret = CKR_OK;
	struct libobj_key_private *key = get_key_from(obj);

	if (key->decrypt)
		ret = tlv_encode_concat_string(policy, SMW_ATTR_USAGE,
					       SMW_ATTR_USAGE_DECRYPT,
					       allowed_algos);

	if (ret == CKR_OK && key->sign)
		ret = set_sign_usage(policy, allowed_algos);

	if (ret == CKR_OK && key->extractable && !key->sensitive)
		ret = tlv_encode_string(policy, SMW_ATTR_USAGE,
					SMW_ATTR_USAGE_EXPORT);

	return ret;
}

static CK_RV set_secret_key_usage(struct smw_tlv *policy,
				  struct libobj_obj *obj,
				  struct smw_tlv *allowed_algos)
{
	CK_RV ret = CKR_OK;
	struct libobj_key_secret *key = get_key_from(obj);

	if (key->encrypt)
		ret = tlv_encode_concat_string(policy, SMW_ATTR_USAGE,
					       SMW_ATTR_USAGE_ENCRYPT,
					       allowed_algos);

	if (ret == CKR_OK && key->decrypt)
		ret = tlv_encode_concat_string(policy, SMW_ATTR_USAGE,
					       SMW_ATTR_USAGE_DECRYPT,
					       allowed_algos);

	if (ret == CKR_OK && key->sign)
		ret = set_sign_usage(policy, allowed_algos);

	if (ret == CKR_OK && key->verify)
		ret = set_verify_usage(policy, allowed_algos);

	if (ret == CKR_OK && key->extractable && !key->sensitive)
		ret = tlv_encode_concat_string(policy, SMW_ATTR_USAGE,
					       SMW_ATTR_USAGE_EXPORT,
					       allowed_algos);

	return ret;
}

static CK_RV set_ec_key_usage(struct smw_tlv *policy, struct libobj_obj *obj,
			      struct smw_tlv *allowed_algos)
{
	CK_RV ret;
	struct libobj_key_ec_pair *key = get_subkey_from(obj);

	switch (key->type) {
	case LIBOBJ_KEY_PUBLIC:
		ret = set_public_key_usage(policy, obj, allowed_algos);
		break;

	case LIBOBJ_KEY_PRIVATE:
		ret = set_private_key_usage(policy, obj, allowed_algos);
		break;

	default:
		ret = set_private_key_usage(policy, obj, allowed_algos);
		if (ret == CKR_OK && key->pub_obj)
			ret = set_public_key_usage(policy, key->pub_obj,
						   allowed_algos);
		break;
	}

	return ret;
}

static CK_RV set_rsa_key_usage(struct smw_tlv *policy, struct libobj_obj *obj,
			       struct smw_tlv *allowed_algos)
{
	CK_RV ret;
	struct libobj_key_rsa_pair *key = get_subkey_from(obj);

	switch (key->type) {
	case LIBOBJ_KEY_PUBLIC:
		ret = set_public_key_usage(policy, obj, allowed_algos);
		break;

	case LIBOBJ_KEY_PRIVATE:
		ret = set_private_key_usage(policy, obj, allowed_algos);
		break;

	default:
		ret = set_private_key_usage(policy, obj, allowed_algos);
		if (ret == CKR_OK && key->pub_obj)
			ret = set_public_key_usage(policy, key->pub_obj,
						   allowed_algos);
		break;
	}

	return ret;
}

static CK_RV rsa_key_attr(struct smw_tlv *attr, struct libobj_obj *obj)
{
	CK_RV ret = CKR_OK;
	struct libobj_key_rsa_pair *key = get_subkey_from(obj);

	/*
	 * The public exponent might be present and define
	 * the RSA public exponent attribute.
	 */
	if (key->pub_exp.value) {
		DBG_TRACE("Build RSA public exponent attribute");
		ret = tlv_encode_large_numeral(attr, "RSA_PUB_EXP",
					       &key->pub_exp);
	}

	return ret;
}

CK_RV args_attr_generate_key(struct smw_tlv *attr, struct libobj_obj *obj)
{
	CK_RV ret;

	if (is_token_obj(obj, storage)) {
		DBG_TRACE("Generate Persistent Key");
		ret = tlv_encode_boolean(attr, "PERSISTENT");
		if (ret != CKR_OK)
			return ret;
	}

	switch (get_key_type(obj)) {
	case CKK_RSA:
		ret = rsa_key_attr(attr, obj);
		break;

	default:
		ret = CKR_OK;
	}

	return ret;
}

CK_RV args_attr_import_key(struct smw_tlv *attr, struct libobj_obj *obj)
{
	CK_RV ret = CKR_OK;

	if (is_token_obj(obj, storage)) {
		DBG_TRACE("Import Persistent Key");
		ret = tlv_encode_boolean(attr, "PERSISTENT");
	}

	return ret;
}

CK_RV args_attr_sign_verify(struct smw_tlv *attr, const char *signature_type,
			    CK_ULONG salt_len)
{
	CK_RV ret = CKR_OK;

	if (signature_type) {
		ret = tlv_encode_enum(attr, "SIGNATURE_TYPE", signature_type);
		if (ret != CKR_OK)
			return ret;
	}

	if (salt_len)
		ret = tlv_encode_numeral(attr, "SALT_LEN", salt_len);

	return ret;
}

CK_RV args_attrs_key_policy(struct smw_tlv *attr, struct libobj_obj *obj,
			    struct smw_tlv *allowed_algos)
{
	CK_RV ret;
	struct smw_tlv policy = { 0 };

	switch (get_key_type(obj)) {
	case CKK_AES:
	case CKK_DES:
	case CKK_DES3:
		ret = set_secret_key_usage(&policy, obj, allowed_algos);
		break;

	case CKK_EC:
		ret = set_ec_key_usage(&policy, obj, allowed_algos);
		break;

	case CKK_RSA:
		ret = set_rsa_key_usage(&policy, obj, allowed_algos);
		break;

	default:
		ret = CKR_FUNCTION_FAILED;
	}

	if (ret == CKR_OK)
		ret = set_common_key_usage(&policy, obj, allowed_algos);

	if (ret == CKR_OK && policy.string)
		ret = tlv_encode_tlv(attr, SMW_ATTR_POLICY, &policy);

	tlv_encode_free(&policy);

	return ret;
}
