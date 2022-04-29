/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021-2022 NXP
 */
#ifndef __ARGS_ATTR_H__
#define __ARGS_ATTR_H__

#include "pkcs11smw.h"
#include "types.h"

#include "tlv_encode.h"

/*
 * Definition of the SMW key policy TLV's attribute type
 */
#define SMW_ATTR_ALGO		   "ALGO"
#define SMW_ATTR_USAGE		   "USAGE"
#define SMW_ATTR_POLICY		   "POLICY"
#define SMW_ATTR_HASH		   "HASH"
#define SMW_ATTR_USAGE_COPY	   "COPY"
#define SMW_ATTR_USAGE_DERIVE	   "DERIVE"
#define SMW_ATTR_USAGE_ENCRYPT	   "ENCRYPT"
#define SMW_ATTR_USAGE_DECRYPT	   "DECRYPT"
#define SMW_ATTR_USAGE_SIGN_MSG	   "SIGN_MESSAGE"
#define SMW_ATTR_USAGE_SIGN_HASH   "SIGN_HASH"
#define SMW_ATTR_USAGE_VERIFY_MSG  "VERIFY_MESSAGE"
#define SMW_ATTR_USAGE_VERIFY_HASH "VERIFY_HASH"
#define SMW_ATTR_USAGE_EXPORT	   "EXPORT"

/**
 * args_attr_generate_key() - Build the key generate attribute list
 * @attr: Generate key attribute list
 * @obj: Key object
 *
 * Return:
 * CKR_HOST_MEMORY               - Out of memory
 * CKR_OK                        - Success
 */
CK_RV args_attr_generate_key(struct smw_tlv *attr, struct libobj_obj *obj);

/**
 * args_attr_import_key() - Build the key import attribute list
 * @attr: Import key attribute list
 * @obj: Key object
 *
 * Return:
 * CKR_HOST_MEMORY               - Out of memory
 * CKR_OK                        - Success
 */
CK_RV args_attr_import_key(struct smw_tlv *attr, struct libobj_obj *obj);

/**
 * args_attr_sign_verify() - Build the sign or verify attribute list
 * @attr: Sign or verify attribute list
 * @signature_type: Signature type attribute
 * @salt_len: Salt length attribute
 *
 * Return:
 * CKR_HOST_MEMORY               - Out of memory
 * CKR_OK                        - Success
 */
CK_RV args_attr_sign_verify(struct smw_tlv *attr, const char *signature_type,
			    CK_ULONG salt_len);

/**
 * args_attrs_key_policy() - Build the key policy attribute list
 * @attr: Attribute list
 * @obj: key object
 * @allowed_algos: Allowed key's algorithms
 *
 * Return:
 * CKR_FUNCTION_FAILED           - Operation failed
 * CKR_HOST_MEMORY               - Out of memory
 * CKR_OK                        - Success
 */
CK_RV args_attrs_key_policy(struct smw_tlv *attr, struct libobj_obj *obj,
			    struct smw_tlv *allowed_algos);

#endif /* __ARGS_ATTR_H__ */
