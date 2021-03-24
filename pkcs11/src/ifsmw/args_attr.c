// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021 NXP
 */

#include "libobj_types.h"

#include "args_attr.h"

#include "trace.h"

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
