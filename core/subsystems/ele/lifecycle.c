// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2024 NXP
 */

#include "debug.h"
#include "tlv.h"
#include "utils.h"

#include "common.h"

#define LIFECYCLE(_lifecycle)                                                  \
	{                                                                      \
		.smw = SMW_LIFECYCLE_##_lifecycle,                             \
		.ele = HSM_KEY_LIFECYCLE_##_lifecycle                          \
	}

static const struct lifecycle {
	unsigned int smw;
	hsm_key_lifecycle_t ele;
} lifecycles[] = { LIFECYCLE(OPEN), LIFECYCLE(CLOSED),
		   LIFECYCLE(CLOSED_LOCKED) };

static int get_current_lifecycle(struct subsystem_context *ele_ctx,
				 uint16_t *lifecycle)
{
	int status = SMW_STATUS_OK;

	struct ele_info *info = &ele_ctx->info;

	status = ele_get_device_info(ele_ctx);
	if (status != SMW_STATUS_OK)
		goto end;

	*lifecycle = info->lifecycle;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

unsigned int ele_get_key_lifecycles(hsm_key_lifecycle_t ele_lifecycles)
{
	unsigned int i = 0;
	unsigned int lc_flags = 0;

	for (; ele_lifecycles && i < ARRAY_SIZE(lifecycles); i++) {
		if (ele_lifecycles & lifecycles[i].ele)
			lc_flags |= lifecycles[i].smw;
	}

	return lc_flags;
}

int ele_set_lifecycle_flags(struct subsystem_context *ele_ctx,
			    unsigned long smw_flags, uint16_t *ele_flags)
{
	int status = SMW_STATUS_OK;

	unsigned int i = 0;
	uint16_t lifecycle = 0;

	*ele_flags = 0;

	if (smw_flags & SMW_LIFECYCLE_CURRENT) {
		status = get_current_lifecycle(ele_ctx, &lifecycle);
		if (status != SMW_STATUS_OK)
			goto end;

		*ele_flags |= lifecycle;
	}

	for (; i < ARRAY_SIZE(lifecycles); i++) {
		if (smw_flags & lifecycles[i].smw)
			*ele_flags |= lifecycles[i].ele;
	}

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int ele_get_device_lifecycle_id(struct subsystem_context *ele_ctx,
				unsigned int *lifecycle)
{
	int status = SMW_STATUS_OK;

	unsigned int i = 0;
	uint16_t lc = 0;

	status = get_current_lifecycle(ele_ctx, &lc);
	if (status != SMW_STATUS_OK)
		goto end;

	for (; i < ARRAY_SIZE(lifecycles); i++) {
		if (lc == lifecycles[i].ele) {
			*lifecycle = lifecycles[i].smw;
			status = SMW_STATUS_OK;
			break;
		}
	}

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}
