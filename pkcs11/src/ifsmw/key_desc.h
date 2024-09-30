/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021, 2024 NXP
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
 * key_desc_smw_to_pkcs11() - Convert a SMW key descriptor to PKCS
 * @obj: Key object
 * @attributes: SMW key attributes
 *
 * Return:
 * CKR_FUNCTION_FAILED           - Operation failed
 * CKR_OK                        - Success
 */

CK_RV key_desc_smw_to_pkcs11(struct libobj_obj *obj,
			     struct smw_get_key_attributes_args *attributes);

/**
 * key_desc_copy_key_id() - Copy the SMW key descriptor id to key object
 * @obj: Key object
 * @desc: SMW key descriptor
 *
 * Return:
 * None.
 */
void key_desc_copy_key_id(struct libobj_obj *obj,
			  struct smw_key_descriptor *desc);

/**
 * derived_key_desc_setup() - Setup the SMW derived key descriptor
 * @desc: SMW derived key descriptor
 * @obj: Key object
 *
 * Return:
 * CKR_ARGUMENTS_BAD             - Bad arguments
 * CKR_ATTRIBUTE_TYPE_INVALID    - Attribute type is not valid
 * CKR_FUNCTION_FAILED           - Operation failed
 * CKR_OK                        - Success
 */
CK_RV derived_key_desc_setup(struct smw_derived_key_descriptor *desc,
			     struct libobj_obj *obj);

/**
 * derived_key_desc_copy_key_id() - Copy SMW derived key desc id to key object
 * @obj: Key object
 * @desc: SMW derived key descriptor
 *
 * Return:
 * None.
 */
void derived_key_desc_copy_key_id(struct libobj_obj *obj,
				  struct smw_derived_key_descriptor *desc);

/**
 * base_key_desc_setup() - Set key ID/buffer in base key descr struct
 * @obj: Key object
 * @desc: SMW key descriptor
 * This function sets key ID or buffer in the base key descriptor structure,
 * depending on whether the base key object is a session or a token object.
 * For an already imported or generated token key or a generated session key,
 * @desc.id is set to key object ID.
 * For an imported session key, where the key object ID is set to 0,
 * @desc->buffer->gen->public_data points to key object buffer and the
 * @desc->type_name set to SMW_KEY_TYPE_NAME_RAW.
 *
 * Return:
 * CKR_OK                        - Success
 * CKR_ARGUMENTS_BAD             - Bad arguments
 */
int base_key_desc_setup(struct libobj_obj *obj,
			struct smw_key_descriptor *desc);

#endif /* __KEY_DESC_H__ */
