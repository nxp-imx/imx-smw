// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include "constants.h"
#include "internal.h"

LOG_MODULE_DECLARE(smw_osal);

/* Simple in-memory database implementation */
/* For production, consider using NVS or other persistent storage */

int osal_zephyr_get_obj_info(struct smw_osal_object *descriptor)
{
	(void)descriptor;
	return -1;
}

int osal_zephyr_add_obj_info(struct smw_osal_object *descriptor)
{
	if (!descriptor || !descriptor->obj_desc)
		return -1;

	descriptor->obj_desc->id = INVALID_OBJ_ID;

	return 0;
}

int osal_zephyr_update_obj_info(struct smw_osal_object *descriptor)
{
	(void)descriptor;
	return 0;
}

int osal_zephyr_delete_obj_info(struct smw_osal_object *descriptor)
{
	(void)descriptor;
	return 0;
}

int osal_zephyr_find_obj_init(void **find_ctx,
			      struct smw_osal_object *descriptor)
{
	(void)find_ctx;
	(void)descriptor;
	return -1;
}

int osal_zephyr_find_obj_next(void *find_ctx,
			      struct smw_osal_object *descriptor)
{
	(void)find_ctx;
	(void)descriptor;
	return -1;
}

int osal_zephyr_find_obj_final(void *find_ctx)
{
	(void)find_ctx;
	return 0;
}
