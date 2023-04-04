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
		.ele = HSM_KEY_LIFECYCLE_##_lifecycle                          \
	}

static const struct lifecycle {
	const char *str;
	hsm_key_lifecycle_t ele;
} lifecycles[] = { LIFECYCLE(OPEN), LIFECYCLE(CLOSED),
		   LIFECYCLE(CLOSED_LOCKED) };

static int lifecycle_to_string(unsigned char **str, int str_length,
			       hsm_key_lifecycle_t lifecycle)
{
	int out_len = 0;
	size_t i = 0;

	if (lifecycle) {
		for (; i < ARRAY_SIZE(lifecycles); i++) {
			if (!(lifecycle & lifecycles[i].ele))
				continue;

			SMW_DBG_PRINTF(DEBUG, "%s(%d) %s\n", __func__, __LINE__,
				       lifecycles[i].str);

			out_len = SMW_UTILS_STRLEN(lifecycles[i].str) + 1;

			if (*str) {
				if (str_length >= out_len) {
					SMW_UTILS_MEMCPY(*str,
							 lifecycles[i].str,
							 out_len);
					*str += out_len;
				} else {
					out_len = -1;
				}
			}

			break;
		}
	}

	return out_len;
}

int ele_get_lifecycle(unsigned char **lifecycle, unsigned int *lifecycle_len,
		      hsm_key_lifecycle_t ele_lifecycle)
{
	int status = SMW_STATUS_INVALID_PARAM;

	int lc_str_len = 0;
	unsigned char *p = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!lifecycle || !lifecycle_len)
		goto exit;

	/* Get the expected lifecycle(s) string length */
	lc_str_len = lifecycle_to_string(&p, lc_str_len, ele_lifecycle);
	if (lc_str_len == -1) {
		status = SMW_STATUS_OPERATION_FAILURE;
		goto exit;
	}

	/* Calculate lifecyle length and allocate the lifecycle string */
	*lifecycle_len = SMW_TLV_ELEMENT_LENGTH(LIFECYCLE_STR, lc_str_len);

	*lifecycle = SMW_UTILS_CALLOC(1, *lifecycle_len);
	if (!*lifecycle) {
		status = SMW_STATUS_ALLOC_FAILURE;
		goto exit;
	}

	p = *lifecycle;
	smw_tlv_set_type(&p, LIFECYCLE_STR);

	/* Get the expected lifecycle(s) string */
	lc_str_len = lifecycle_to_string(&p, lc_str_len, ele_lifecycle);
	if (lc_str_len == -1) {
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
