// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024 NXP
 */

#include "constants.h"
#include "debug.h"
#include "lifecycle.h"
#include "tlv.h"
#include "utils.h"

#define LIFECYCLE(_name)                                                       \
	{                                                                      \
		.lifecycle_str = LC_##_name##_STR,                             \
		.lifecycle = SMW_LIFECYCLE_##_name,                            \
	}

/**
 * struct - Lifecycle information
 * @lifecycle_str: Lifecycle name used for TLV encoding.
 * @lifecycle: Lifecycle id.
 */
static const struct lc_info {
	const char *lifecycle_str;
	unsigned long lifecycle;
} lifecycle_info[] = { LIFECYCLE(OPEN), LIFECYCLE(CLOSED),
		       LIFECYCLE(CLOSED_LOCKED), LIFECYCLE(CURRENT) };

static int get_lifecycle(unsigned char *name, unsigned long *lc_id)
{
	int status = SMW_STATUS_INVALID_LIFECYCLE;

	unsigned int i = 0;

	*lc_id = 0;

	for (; i < ARRAY_SIZE(lifecycle_info); i++) {
		if (!SMW_UTILS_STRCMP((const char *)name,
				      lifecycle_info[i].lifecycle_str)) {
			*lc_id = lifecycle_info[i].lifecycle;
			status = SMW_STATUS_OK;
			break;
		}
	}

	return status;
}

int smw_lifecycle_set_tlv(unsigned char **attrs, unsigned int *attrs_len,
			  unsigned long lc_flags)
{
	int status = SMW_STATUS_INVALID_PARAM;

	const struct lc_info *lc_info = lifecycle_info;

	unsigned int i = 0;
	unsigned int lc_len = 0;
	unsigned int tlv_flag_len = 0;
	size_t length = 0;
	unsigned char *tlv_flag = NULL;
	unsigned char *lc_attrs = NULL;
	unsigned char *p = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!attrs || !attrs_len)
		goto exit;

	if (!lc_flags) {
		status = SMW_STATUS_OK;
		goto exit;
	}

	/*
	 * First check for the first lifecycle and allocate the
	 * lifecycle attribute list.
	 */
	for (; lc_flags && i < ARRAY_SIZE(lifecycle_info); i++, lc_info++) {
		if (!(lc_info->lifecycle & lc_flags))
			continue;

		if (SMW_TLV_ELEMENT_LENGTH(lc_info->lifecycle_str, 0, length))
			goto exit;

		if (!lc_attrs) {
			if (SMW_TLV_ELEMENT_LENGTH(LIFECYCLE_STR, length,
						   lc_len))
				goto exit;

			lc_attrs = SMW_UTILS_CALLOC(1, lc_len);
			if (!lc_attrs)
				goto exit;

			p = lc_attrs;
			smw_tlv_set_type(&p, LIFECYCLE_STR);
		}

		if (!tlv_flag || length > tlv_flag_len) {
			if (tlv_flag)
				SMW_UTILS_FREE(tlv_flag);

			tlv_flag = SMW_UTILS_MALLOC(length);
			if (!tlv_flag) {
				status = SMW_STATUS_ALLOC_FAILURE;
				goto exit;
			}

			tlv_flag_len = length;
		}

		p = tlv_flag;
		smw_tlv_set_boolean(&p, lc_info->lifecycle_str);

		status = smw_tlv_append_var_len_list(&lc_attrs, &lc_len,
						     tlv_flag, length);
		if (status != SMW_STATUS_OK)
			goto exit;
	}

	if (lc_len && lc_attrs) {
		/*
		 * lc_len is exactly the length of the variable-length list to
		 * add to the input attributes list, no need to recalculate it.
		 */
		length = *attrs_len;
		if (INC_OVERFLOW(*attrs_len, lc_len)) {
			status = SMW_STATUS_OPERATION_FAILURE;
			goto exit;
		}

		*attrs = SMW_UTILS_REALLOC(*attrs, *attrs_len);
		if (!*attrs) {
			status = SMW_STATUS_ALLOC_FAILURE;
			goto exit;
		}

		p = *attrs;
		p += length;

		SMW_UTILS_MEMCPY(p, lc_attrs, lc_len);
	}

	status = SMW_STATUS_OK;

exit:
	SMW_DBG_PRINTF(DEBUG, "%s returned %d\n", __func__, status);

	if (tlv_flag)
		SMW_UTILS_FREE(tlv_flag);

	if (lc_attrs)
		SMW_UTILS_FREE(lc_attrs);

	return status;
}

int smw_lifecycle_get_tlv(unsigned long *lc_flags, unsigned char *attrs,
			  unsigned int attrs_len)
{
	int status = SMW_STATUS_INVALID_PARAM;

	const unsigned char *p = NULL;
	const unsigned char *p_end = NULL;
	unsigned char *type = NULL;
	unsigned char *value = NULL;
	unsigned int value_len = 0;
	unsigned long flags = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!lc_flags || !attrs || !attrs_len)
		goto exit;

	p = attrs;
	p_end = p + attrs_len;

	while (p < p_end) {
		status = smw_tlv_read_element(&p, p_end, &type, &value,
					      &value_len);
		if (status != SMW_STATUS_OK) {
			SMW_DBG_PRINTF(ERROR, "%s: Parsing lifecycle failed\n",
				       __func__);
			goto exit;
		}

		status = get_lifecycle(type, &flags);
		if (status != SMW_STATUS_OK)
			goto exit;

		*lc_flags |= flags;
	}

	status = SMW_STATUS_OK;

exit:
	SMW_DBG_PRINTF(DEBUG, "%s returned %d\n", __func__, status);
	return status;
}
