/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021-2023 NXP
 */

#ifndef __UTIL_TLV_H__
#define __UTIL_TLV_H__

#include <json_object.h>

/**
 * util_tlv_read_attrs() - Read the attributes list encoded in TLV format.
 * @attr: attributes list TLV string result
 * @len: Length of the attributes list string
 * @params: Parameters json-c object
 *
 * Return:
 * PASSED                   - Success.
 * -INTERNAL_OUT_OF_MEMORY  - Memory allocation failed.
 * -BAD_ARGS                - One of the arguments is bad.
 * -FAILED                  - Error in definition file.
 * -BAD_PARAM_TYPE          - A parameter value is undefined.
 */
int util_tlv_read_attrs(unsigned char **attr, unsigned int *len,
			struct json_object *params);

/**
 * util_tlv_read_key_policy() - Read the key policy encoded in TLV format.
 * @attr: attributes list TLV string result
 * @len: Length of the attributes list string
 * @okey: Key json-c object
 *
 * Return:
 * PASSED                   - Success.
 * -INTERNAL_OUT_OF_MEMORY  - Memory allocation failed.
 * -BAD_ARGS                - One of the arguments is bad.
 * -FAILED                  - Error in definition file.
 * -BAD_PARAM_TYPE          - A parameter value is undefined.
 */
int util_tlv_read_key_policy(unsigned char **attr, unsigned int *len,
			     struct json_object *okey);

#endif /* __UTIL_TLV_H__ */
