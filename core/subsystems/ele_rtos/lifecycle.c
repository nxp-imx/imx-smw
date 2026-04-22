// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include "debug.h"
#include "lifecycle.h"
#include "utils.h"

#include "common.h"

#define LIFECYCLE(_smw, _ele)                                                  \
	{                                                                      \
		.smw = SMW_LIFECYCLE_ID_##_smw, .ele = KEYLIFECYCLE_##_ele     \
	}

static const struct lifecycle {
	enum smw_lifecycle_id smw;
	key_lifecycle_t ele;
} lifecycles[] = { LIFECYCLE(OPEN, OPEN), LIFECYCLE(CLOSED, CLOSED),
		   LIFECYCLE(CLOSED_LOCKED, CLOSED_LOCKED) };

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

void ele_get_key_lifecycles(key_lifecycle_t ele_lifecycles,
			    smw_attr_attributes_t *attributes)
{
	if (ele_lifecycles & KEYLIFECYCLE_OPEN)
		*attributes = SMW_ATTR_SET_LC_OPEN(*attributes);
	if (ele_lifecycles & KEYLIFECYCLE_CLOSED)
		*attributes = SMW_ATTR_SET_LC_CLOSED(*attributes);
	if (ele_lifecycles & KEYLIFECYCLE_CLOSED_LOCKED)
		*attributes = SMW_ATTR_SET_LC_CLOSED_LOCKED(*attributes);
}

int ele_set_lifecycle_flags(struct subsystem_context *ele_ctx,
			    smw_attr_attributes_t attributes,
			    uint16_t *ele_flags)
{
	int status = SMW_STATUS_OK;

	uint16_t lifecycle = 0;

	*ele_flags = 0;

	if (SMW_ATTR_IS_LC_CURRENT(attributes)) {
		status = get_current_lifecycle(ele_ctx, &lifecycle);
		if (status != SMW_STATUS_OK)
			goto end;

		*ele_flags |= lifecycle;
	}

	if (SMW_ATTR_IS_LC_OPEN(attributes))
		*ele_flags |= KEYLIFECYCLE_OPEN;

	if (SMW_ATTR_IS_LC_CLOSED(attributes))
		*ele_flags |= KEYLIFECYCLE_CLOSED;

	if (SMW_ATTR_IS_LC_CLOSED_LOCKED(attributes))
		*ele_flags |= KEYLIFECYCLE_CLOSED_LOCKED;

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
