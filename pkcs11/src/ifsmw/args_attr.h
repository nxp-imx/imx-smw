/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021-2024 NXP
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
 * args_attr_key_storage() - Set the key storage attributes
 * @attr: Attributes
 * @obj: Object
 *
 * Return:
 * None.
 */
void args_attr_key_storage(smw_attr_attributes_t *attr, struct libobj_obj *obj);

/**
 * args_attr_data_storage() - Set the data storage attributes
 * @attr: Attributes
 * @obj: Object
 *
 * Return:
 * None.
 */
void args_attr_data_storage(smw_attr_attributes_t *attr,
			    struct libobj_obj *obj);

#endif /* __ARGS_ATTR_H__ */
