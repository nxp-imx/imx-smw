// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2019-2021 NXP
 */

#include "smw_status.h"

#include "global.h"
#include "debug.h"
#include "utils.h"
#include "operations.h"
#include "subsystems.h"
#include "config.h"

struct smw_ctx g_smw_ctx = { .ops = { 0 }, .start_count = 0 };

static int check_ops(const struct smw_ops *ops)
{
	if (!ops)
		return -1;

	if ((bool)!ops->critical_section_start !=
	    (bool)!ops->critical_section_stop)
		return -1;

	if ((ops->mutex_init || ops->mutex_destroy || ops->mutex_lock ||
	     ops->mutex_unlock) &&
	    !(ops->mutex_init && ops->mutex_destroy && ops->mutex_lock &&
	      ops->mutex_unlock))
		return -1;

	if (!ops->thread_create || !ops->thread_cancel)
		return -1;

	return 0;
}

enum smw_status_code smw_init(const struct smw_ops *ops)
{
	enum smw_status_code status = SMW_STATUS_OK;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (check_ops(ops)) {
		status = SMW_STATUS_OPS_INVALID;
		goto end;
	}

	if (ops->critical_section_start)
		ops->critical_section_start();

	if (!g_smw_ctx.start_count) {
		g_smw_ctx.ops = *ops;
		status = smw_config_init();
	}

	if (status == SMW_STATUS_OK)
		g_smw_ctx.start_count++;

	SMW_DBG_PRINTF(VERBOSE, "%s - Start count: %d\n", __func__,
		       g_smw_ctx.start_count);

	if (ops->critical_section_stop)
		ops->critical_section_stop();

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

enum smw_status_code smw_deinit(void)
{
	enum smw_status_code status = SMW_STATUS_OK;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_UTILS_CRITICAL_SECTION_START;

	if (g_smw_ctx.start_count == 1) {
		status = smw_config_deinit();
		if (status != SMW_STATUS_OK)
			goto end;
	}

	if (g_smw_ctx.start_count >= 1)
		g_smw_ctx.start_count--;

	SMW_DBG_PRINTF(VERBOSE, "%s - Start count: %d\n", __func__,
		       g_smw_ctx.start_count);

end:
	SMW_UTILS_CRITICAL_SECTION_STOP;

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}
