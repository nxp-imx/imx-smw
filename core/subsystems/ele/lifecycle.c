// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include "debug.h"
#include "tlv.h"
#include "utils.h"

#include "common.h"

#define LIFECYCLE(_lifecycle)                                                  \
	{                                                                      \
		.str = LC_##_lifecycle##_STR,                                  \
		.smw = SMW_LIFECYCLE_##_lifecycle,                             \
		.ele = HSM_KEY_LIFECYCLE_##_lifecycle                          \
	}

static const struct lifecycle {
	const char *str;
	unsigned long smw;
	hsm_key_lifecycle_t ele;
} lifecycles[] = { LIFECYCLE(OPEN), LIFECYCLE(CLOSED),
		   LIFECYCLE(CLOSED_LOCKED) };

static size_t lifecycle_to_string(unsigned char **str, size_t str_length,
				  hsm_key_lifecycle_t lifecycle)
{
	size_t out_len = 0;
	size_t i = 0;

	if (lifecycle) {
		for (; i < ARRAY_SIZE(lifecycles); i++) {
			if (!(lifecycle & lifecycles[i].ele))
				continue;

			SMW_DBG_PRINTF(DEBUG, "%s(%d) %s\n", __func__, __LINE__,
				       lifecycles[i].str);

			if (ADD_OVERFLOW(SMW_UTILS_STRLEN(lifecycles[i].str), 1,
					 &out_len)) {
				out_len = SIZE_MAX;
				break;
			}

			if (*str) {
				if (str_length >= out_len) {
					SMW_UTILS_MEMCPY(*str,
							 lifecycles[i].str,
							 out_len);
					*str += out_len;
				} else {
					out_len = SIZE_MAX;
					break;
				}
			}
		}
	}

	return out_len;
}

int ele_get_lifecycle(unsigned char **lifecycle, unsigned int *lifecycle_len,
		      hsm_key_lifecycle_t ele_lifecycle)
{
	int status = SMW_STATUS_INVALID_PARAM;

	size_t lc_str_len = 0;
	unsigned char *p = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!lifecycle || !lifecycle_len)
		goto exit;

	/* Get the expected lifecycle(s) string length */
	lc_str_len = lifecycle_to_string(&p, lc_str_len, ele_lifecycle);
	if (lc_str_len == SIZE_MAX || lc_str_len > UINT32_MAX) {
		status = SMW_STATUS_OPERATION_FAILURE;
		goto exit;
	}

	/* Calculate lifecyle length and allocate the lifecycle string */
	if (SMW_TLV_ELEMENT_LENGTH(LIFECYCLE_STR, lc_str_len, *lifecycle_len)) {
		status = SMW_STATUS_INVALID_PARAM;
		goto exit;
	}

	*lifecycle = SMW_UTILS_CALLOC(1, *lifecycle_len);
	if (!*lifecycle) {
		status = SMW_STATUS_ALLOC_FAILURE;
		goto exit;
	}

	p = *lifecycle;
	smw_tlv_set_type(&p, LIFECYCLE_STR);

	/* Get the expected lifecycle(s) string */
	lc_str_len = lifecycle_to_string(&p, lc_str_len, ele_lifecycle);
	if (lc_str_len == SIZE_MAX) {
		status = SMW_STATUS_OPERATION_FAILURE;
	} else {
		smw_tlv_set_length(*lifecycle, p);
		status = SMW_STATUS_OK;
	}

exit:
	if (status != SMW_STATUS_OK) {
		if (lifecycle && *lifecycle) {
			SMW_UTILS_FREE(*lifecycle);

			*lifecycle = NULL;
		}

		if (lifecycle_len)
			*lifecycle_len = 0;
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

void ele_set_lifecycle_flags(unsigned long smw_flags, uint16_t *ele_flags)
{
	unsigned int i = 0;

	*ele_flags = 0;

	for (; i < ARRAY_SIZE(lifecycles); i++) {
		if (smw_flags & lifecycles[i].smw)
			*ele_flags |= lifecycles[i].ele;
	}
}
