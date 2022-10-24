// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2019-2022 NXP
 */

#include "smw_status.h"

#include "global.h"
#include "debug.h"
#include "utils.h"
#include "operations.h"
#include "subsystems.h"
#include "config.h"

static struct smw_ctx *smw_ctx;

inline struct smw_ctx *get_smw_ctx(void)
{
	return smw_ctx;
}

inline struct smw_ops *get_smw_ops(void)
{
	struct smw_ctx *ctx = get_smw_ctx();

	return ctx ? &ctx->ops : NULL;
}

static int check_ops(const struct smw_ops *ops)
{
	if (!ops)
		return -1;

	if ((bool)!ops->critical_section_start !=
	    (bool)!ops->critical_section_stop)
		return -1;

	if (!ops->mutex_init || !ops->mutex_destroy || !ops->mutex_lock ||
	    !ops->mutex_unlock)
		return -1;

	if (!ops->thread_create || !ops->thread_cancel)
		return -1;

	if (!ops->get_subsystem_info)
		return -1;

	if (!ops->is_lib_initialized)
		return -1;

	if (!ops->get_key_info || !ops->add_key_info || !ops->update_key_info ||
	    !ops->delete_key_info)
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

	if (!smw_ctx) {
		smw_ctx = SMW_UTILS_CALLOC(1, sizeof(struct smw_ctx));
		if (!smw_ctx) {
			status = SMW_STATUS_ALLOC_FAILURE;
			if (ops->critical_section_stop)
				ops->critical_section_stop();
			goto end;
		}

		SMW_DBG_PRINTF(DEBUG, "SMW context allocation\n");
	}

	if (!smw_ctx->start_count) {
		smw_ctx->ops = *ops;

		status = smw_config_init();
	}

	if (status == SMW_STATUS_OK)
		smw_ctx->start_count++;

	SMW_DBG_PRINTF(VERBOSE, "%s - Start count: %d\n", __func__,
		       smw_ctx->start_count);

	if (ops->critical_section_stop)
		ops->critical_section_stop();

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

enum smw_status_code smw_deinit(void)
{
	enum smw_status_code status = SMW_STATUS_OK;

	struct smw_ctx *ctx;

	SMW_DBG_TRACE_FUNCTION_CALL;

	ctx = get_smw_ctx();

	if (!ctx)
		return SMW_STATUS_INVALID_LIBRARY_CONTEXT;

	SMW_UTILS_CRITICAL_SECTION_START;

	if (ctx->start_count == 1) {
		status = smw_config_deinit();
		if (status != SMW_STATUS_OK)
			goto end;
	}

	if (ctx->start_count >= 1)
		ctx->start_count--;

	SMW_DBG_PRINTF(VERBOSE, "%s - Start count: %d\n", __func__,
		       ctx->start_count);

	if (ctx->start_count == 0) {
		SMW_DBG_PRINTF(DEBUG, "SMW context free\n");
		SMW_UTILS_FREE(smw_ctx);
		smw_ctx = NULL;
	}

end:
	SMW_UTILS_CRITICAL_SECTION_STOP;

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}
