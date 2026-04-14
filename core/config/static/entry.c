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

#include "supported_operations.h"

__export enum smw_status_code smw_config_load(char *buffer, unsigned int size,
					      unsigned int *offset)
{
	(void)buffer;
	(void)size;
	(void)offset;

	enum smw_status_code status = SMW_STATUS_OK;
	enum smw_status_code status_mutex = SMW_STATUS_OK;

	struct smw_ctx *ctx = get_smw_ctx();
	size_t i = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!ctx)
		return SMW_STATUS_INVALID_LIBRARY_CONTEXT;

	if (smw_utils_mutex_lock(ctx->config_mutex)) {
		status_mutex = SMW_STATUS_MUTEX_LOCK_FAILURE;
		goto end;
	}

	status = SMW_STATUS_CONFIG_ALREADY_LOADED;

	if (!ctx->config_loaded) {
		status = set_subsystem_load_method(SUBSYSTEM_ID_ELE,
						   LOAD_METHOD_ID_DEFAULT);
		if (status != SMW_STATUS_OK)
			goto end;

		for (; i < ARRAY_SIZE(supported_operations); i++) {
			status = store_operation(supported_operations[i],
						 SUBSYSTEM_ID_ELE);
			if (status != SMW_STATUS_OK)
				goto end;
		}

		set_subsystem_configured(SUBSYSTEM_ID_ELE);

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
