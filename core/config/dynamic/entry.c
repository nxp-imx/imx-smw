// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include "smw_status.h"

#include "compiler.h"
#include "global.h"
#include "debug.h"
#include "utils.h"
#include "operations.h"
#include "subsystems.h"

#include "database.h"

__export enum smw_status_code smw_config_load(char *buffer, unsigned int size,
					      unsigned int *offset)
{
	enum smw_status_code status = SMW_STATUS_OK;
	enum smw_status_code status_mutex = SMW_STATUS_OK;

	struct smw_ctx *ctx = get_smw_ctx();

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!ctx)
		return SMW_STATUS_INVALID_LIBRARY_CONTEXT;

	if (smw_utils_mutex_lock(ctx->config_mutex)) {
		status_mutex = SMW_STATUS_MUTEX_LOCK_FAILURE;
		goto end;
	}

	status = SMW_STATUS_CONFIG_ALREADY_LOADED;

	if (!ctx->config_loaded) {
		if (!size || !buffer) {
			status = SMW_STATUS_INVALID_BUFFER;
			goto end;
		}

		status = parse(buffer, size, offset);
		if (status != SMW_STATUS_OK)
			goto end;

		print_database();

		ctx->config_loaded = true;
	}

end:
	if (status_mutex == SMW_STATUS_OK)
		if (smw_utils_mutex_unlock(ctx->config_mutex))
			status_mutex = SMW_STATUS_MUTEX_UNLOCK_FAILURE;
	if (status == SMW_STATUS_OK)
		status = status_mutex;

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}
