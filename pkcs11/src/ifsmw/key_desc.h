/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021 NXP
 */
#ifndef __KEY_DESC_H__
#define __KEY_DESC_H__

#include "smw_keymgr.h"
#include "pkcs11smw.h"

/**
 * key_desc_setup() - Setup the SMW key descriptor
 * @desc: SMW key descriptor
 * @obj: Key object
 *
 * Return:
 * CKR_CURVE_NOT_SUPPORTED       - Curve is not supported
 * CKR_ATTRIBUTE_TYPE_INVALID    - Attribute type is not valid
 * CKR_FUNCTION_FAILED           - Operation failed
 * CKR_OK                        - Success
 */
CK_RV key_desc_setup(struct smw_key_descriptor *desc, struct libobj_obj *obj);

/**
 * key_desc_copy_key_id() - Copy the SMW key descriptor id to key object
 * @desc: SMW key descriptor
 * @obj: Key object
 */
void key_desc_copy_key_id(struct libobj_obj *obj,
			  struct smw_key_descriptor *desc);
#endif /* __KEY_DESC_H__ */
