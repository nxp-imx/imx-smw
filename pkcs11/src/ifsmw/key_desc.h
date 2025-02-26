/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021, 2025 NXP
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
 * CKR_KEY_TYPE_INCONSISTENT     - Key type not supported
 * CKR_CURVE_NOT_SUPPORTED       - Curve is not supported
 * CKR_ATTRIBUTE_TYPE_INVALID    - Attribute type is not valid
 * CKR_FUNCTION_FAILED           - Operation failed
 * CKR_OK                        - Success
 */
CK_RV key_desc_setup(struct smw_key_descriptor *desc, struct libobj_obj *obj);

/**
 * key_desc_set_key_type() - Setup the key type in the SMW key descriptor
 * @desc: SMW key descriptor
 * @key_type: PKCS11 key type
 * @ec_params: PKCS11 EC ey parameters
 *
 * Return:
 * CKR_KEY_TYPE_INCONSISTENT     - Key type not supported
 * CKR_CURVE_NOT_SUPPORTED       - Curve is not supported
 * CKR_ATTRIBUTE_TYPE_INVALID    - Attribute type is not valid
 * CKR_FUNCTION_FAILED           - Operation failed
 * CKR_OK                        - Success
 */
CK_RV key_desc_set_key_type(struct smw_key_descriptor *desc,
			    CK_KEY_TYPE key_type, struct libbytes *ec_params);

/**
 * key_desc_smw_to_pkcs11() - Convert a SMW key descriptor to PKCS
 * @obj: Key object
 * @attributes: SMW key attributes
 *
 * Return:
 * CKR_KEY_TYPE_INCONSISTENT     - Key type not supported
 * CKR_FUNCTION_FAILED           - Operation failed
 * CKR_OK                        - Success
 */
CK_RV key_desc_smw_to_pkcs11(struct libobj_obj *obj,
			     struct smw_get_key_attributes_args *attributes);

/**
 * key_desc_smw_to_pkcs11() - Convert a SMW key descriptor to PKCS
 * @key_type: PKCS11 Key type
 * @desc: SMW key descriptor
 * @attributes: SMW key attributes
 *
 * Return:
 * CKR_KEY_TYPE_INCONSISTENT     - Key type not supported
 * CKR_FUNCTION_FAILED           - Operation failed
 * CKR_HOST_MEMORY               - Allocation error
 * CKR_OK                        - Success
 */
CK_RV key_desc_get_key_type(CK_KEY_TYPE *key_type,
			    struct smw_key_descriptor *desc,
			    struct smw_key_attributes *attributes);

/**
 * is_edwards_key_type() - Check if edwards key corresponds to given key type
 * @obj: PKCS11 key object
 * @key_type: SMW key type
 *
 * Return:
 * CK_TRUE if PKCS11 key is a SMW key type, CK_FALSE otherwise
 */
CK_BBOOL is_edwards_key_type(struct libobj_obj *obj, smw_key_type_t _key_type);

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
 * base_key_desc_setup() - Set key ID/buffer in base key descr struct
 * @obj: Key object
 * @desc: SMW key descriptor
 *
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
