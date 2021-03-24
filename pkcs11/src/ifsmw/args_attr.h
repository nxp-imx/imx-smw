/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021 NXP
 */
#ifndef __ARGS_ATTR_H__
#define __ARGS_ATTR_H__

#include "pkcs11smw.h"
#include "types.h"

#include "tlv_encode.h"

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

#endif /* __ARGS_ATTR_H__ */
