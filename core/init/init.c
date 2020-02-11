// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2019-2020 NXP
 */

#include "utils.h"

struct smw_ctx g_smw_ctx = { .start_count = 0,
			     .dgb_lvl = SMW_UTILS_DBG_LEVEL_DEFAULT };

static int smw_check_ops(const struct smw_ops *ops)
{
	if (!ops)
		return -1;

	if ((bool)!ops->critical_section_start !=
	    (bool)!ops->critical_section_stop)
		return -1;

	return 0;
}

int smw_start(const struct smw_ops *ops, unsigned char dbg_lvl)
{
	int status = 0;

	SMW_UTILS_TRACE_FUNCTION_CALL;

	status = smw_check_ops(ops);
	if (status)
		goto end;

	if (ops->critical_section_start)
		ops->critical_section_start();

	if (!g_smw_ctx.start_count) {
		g_smw_ctx.ops = *ops;
		g_smw_ctx.dgb_lvl = dbg_lvl;
	}

	if (!status)
		g_smw_ctx.start_count++;

	SMW_UTILS_DBG_PRINTF(VERBOSE, "%s - Start count: %d\n", __func__,
			     g_smw_ctx.start_count);

	if (ops->critical_section_stop)
		ops->critical_section_stop();

end:
	SMW_UTILS_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int smw_stop(void)
{
	int status = 0;

	SMW_UTILS_TRACE_FUNCTION_CALL;

	SMW_UTILS_CRITICAL_SECTION_START;

	g_smw_ctx.start_count--;

	SMW_UTILS_DBG_PRINTF(VERBOSE, "%s - Start count: %d\n", __func__,
			     g_smw_ctx.start_count);

	SMW_UTILS_CRITICAL_SECTION_STOP;

	SMW_UTILS_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}
