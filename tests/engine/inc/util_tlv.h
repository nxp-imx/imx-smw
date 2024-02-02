/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021-2024 NXP
 */

#ifndef __UTIL_TLV_H__
#define __UTIL_TLV_H__

#include <json_object.h>

/**
 * util_tlv_read_attrs() - Read the attributes list encoded in TLV format.
 * @attr: [in/out] Attributes list TLV string result
 * @len: [in/out] Length of the attributes list string
 * @params: [in] Parameters json-c object
 *
 * The @attr is the concatenation of the input attributes list and the
 * attributes list.
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
 * @attr: [in/out] Attributes list TLV string result
 * @len: [in/out] Length of the attributes list string
 * @okey: [in] Key json-c object
 *
 * The @attr is the concatenation of the input attributes list and the
 * policy list.
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
 * util_tlv_read_lifecycle() - Read the lifecycles list encoded in TLV format.
 * @attr: [in/out] Attributes list TLV string result
 * @len: [in/out] Length of the attributes list string
 * @params: [in] Parameters json-c object
 *
 * The @attr is the concatenation of the input attributes list and the
 * lifecycles list.
 *
 * Return:
 * PASSED                   - Success.
 * -INTERNAL_OUT_OF_MEMORY  - Memory allocation failed.
 * -BAD_ARGS                - One of the arguments is bad.
 * -FAILED                  - Error in definition file.
 * -BAD_PARAM_TYPE          - A parameter value is undefined.
 */
int util_tlv_read_lifecycle(unsigned char **attr, unsigned int *len,
			    struct json_object *params);

/**
 * util_tlv_check_key_policy() - Check the subtest's key name policy with
 *                               policy returned by SMW
 * @subtest: [in] Subtest data.
 * @policy: [in] Policy TLV variant list to check.
 * @policy_len: [in] Length of @policy.
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
 * @lifecycle: [in] Lifecycle TLV variant list to check.
 * @lifecycle_len: [in] Length of @lifecycle.
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

/**
 * util_tlv_cmp_data_attrs() - Compare data attributes
 * @ref_attr: Reference data attributes list
 * @ref_attr_len: Length of the @ref_attr list
 * @attr: Retrieved data attributes list
 * @attr_len: Length of the @attr list
 * @persistence: Retrieved persistence name
 * @lc_attr: Retrieved lifecycle list
 * @lc_attr_len: Length of @lc_attr
 *
 * Compare the reference attributes list with retrieved attributes.
 *
 * Return:
 * PASSED                   - Success.
 * -BAD_ARGS                - One of the arguments is bad.
 * -INTERNAL                - Internal error.
 * -INTERNAL_OUT_OF_MEMORY  - Allocation error.
 * -FAILED                  - Failure.
 */
int util_tlv_cmp_data_attrs(unsigned char *ref_attr, unsigned int ref_attr_len,
			    unsigned char *attr, unsigned int attr_len,
			    const char *persistence, unsigned char *lc_attr,
			    unsigned int lc_attr_len);

#endif /* __UTIL_TLV_H__ */
