// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include "smw_status.h"
#include "internal.h"

LOG_MODULE_DECLARE(smw_osal);

static int get_ele_info(struct se_info *info)
{
	int ret = -1;

	struct osal_ctx *ctx = get_osal_ctx();

	/*
	 * Copy the Storage Nonce configuration if value set
	 * in the library instance
	 */
	if (ctx && ctx->config.config_flags & CONFIG_ELE) {
		*info = ctx->config.se_ele_info;
		ret = 0;
	}

	return ret;
}

int osal_zephyr_get_subsystem_info(smw_subsystem_t subsystem_name, void *info)
{
	TRACE_FUNCTION_CALL;

	if (!info || subsystem_name >= SMW_SUBSYSTEM_NAME_NB)
		return -1;

	if (subsystem_name == SMW_SUBSYSTEM_NAME_ELE)
		return get_ele_info(info);

	LOG_DBG("%s unknown %d subsystem\n", __func__, subsystem_name);

	return -1;
}
