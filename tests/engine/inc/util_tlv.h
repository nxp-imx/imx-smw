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

/**
 * util_tlv_check_key_policy() - Check the subtest's key name policy with
 *                               policy returned by SMW
 * @subtest: Subtest data.
 * @policy: Policy TLV variant list to check.
 * @policy_len: Length of @policy.
 *
 * The function checks if the policies returned by SMW are defined in the
 * key of the subtest.
 *
 * Return:
 * PASSED                   - Success.
 * -INTERNAL                - Internal test error.
 * -INTERNAL_OUT_OF_MEMORY  - Memory allocation failed.
 * -BAD_ARGS                - One of the arguments is bad.
 * -FAILED                  - Error in definition file.
 * -BAD_PARAM_TYPE          - A parameter value is undefined.
 */
int util_tlv_check_key_policy(struct subtest_data *subtest,
			      const unsigned char *policy,
			      unsigned int policy_len);

/**
 * util_tlv_check_lifecycle() - Check the lifecycle returned by SMW
 * @lifecycle: Lifecycle TLV variant list to check.
 * @lifecycle_len: Length of @lifecycle.
 *
 * The function checks if the lifecyle(s) returned by SMW is a correct
 * TLV variable-length list.
 *
 * Return:
 * PASSED                   - Success.
 * -BAD_ARGS                - One of the arguments is bad.
 * -FAILED                  - Error in definition file.
 */
int util_tlv_check_lifecycle(const unsigned char *lifecyle,
			     unsigned int lifecycle_len);

#endif /* __UTIL_TLV_H__ */
