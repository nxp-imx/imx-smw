/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021 NXP
 */

#ifndef __UTIL_TLV_H__
#define __UTIL_TLV_H__

#include <json_object.h>

/**
 * util_tlv_read_attrs() - Read the attributes list encoded in TLV format.
 * @attr: attributes list TLV string result
 * @len: Length of the attributes list string
 * @params: json-c object
 *
 * Return:
 * PASSED                   - Success.
 * -INTERNAL_OUT_OF_MEMORY  - Memory allocation failed.
 * -BAD_ARGS                - One of the arguments is bad.
 * -FAILED                  - Error in definition file
 */
int util_tlv_read_attrs(unsigned char **attr, unsigned int *len,
			json_object *params);

#endif /* __UTIL_TLV_H__ */
