/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021-2025 NXP
 */
#ifndef __ARGS_ATTR_H__
#define __ARGS_ATTR_H__

#include "pkcs11smw.h"
#include "types.h"

/**
 * args_attrs_key_usage() - Build the key usage flags
 * @usage_flags: Usage flags
 * @obj: Key object
 *
 * Return:
 * None.
 */
void args_attrs_key_usage(smw_attr_usage_t *usage_flags,
			  struct libobj_obj *obj);

/**
 * args_attrs_get_key_usage() - Get the key usage flags
 * @obj: Key object
 * @usage_flags: Usage flags
 *
 * Return:
 * None.
 */
void args_attr_get_key_usage(struct libobj_obj *obj,
			     smw_attr_usage_t usage_flags);

/**
 * args_attr_obj_storage() - Set the object storage attributes
 * @attr: Attributes
 * @obj: Object
 *
 * Return:
 * None.
 */
void args_attr_obj_storage(smw_attr_attributes_t *attr, struct libobj_obj *obj);

/**
 * args_attr_get_obj_storage() - Get the object storage attributes
 * @obj: Object
 * @attr: Attributes
 *
 * Return:
 * None.
 */
void args_attr_get_obj_storage(struct libobj_obj *obj,
			       smw_attr_attributes_t attr);

/**
 * pkcs11_flag_to_smw_usage() - Convert PKCS#11 flags to SMW usage flags
 * @op_flag: PKCS#11 operation flags
 *
 * Return:
 * SMW usage flags.
 */
smw_attr_usage_t pkcs11_flag_to_smw_usage(CK_FLAGS op_flag);

#endif /* __ARGS_ATTR_H__ */
