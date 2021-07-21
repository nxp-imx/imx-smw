// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2021 NXP
 */

#include "smw_status.h"

#include "compiler.h"
#include "smw_osal.h"
#include "global.h"
#include "debug.h"
#include "utils.h"
#include "operations.h"
#include "subsystems.h"

#include "common.h"

struct ctx ctx = { .mutex = NULL, .config_loaded = false };

int smw_config_init(void)
{
	int status = SMW_STATUS_OK;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (smw_utils_mutex_init(&ctx.mutex))
		status = SMW_STATUS_MUTEX_INIT_FAILURE;
	else
		init_database(false);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int smw_config_deinit(void)
{
	int status = SMW_STATUS_OK;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (smw_utils_mutex_destroy(&ctx.mutex))
		status = SMW_STATUS_MUTEX_DESTROY_FAILURE;

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

__export enum smw_status_code smw_config_load(char *buffer, unsigned int size,
					      unsigned int *offset)
{
	enum smw_status_code status = SMW_STATUS_CONFIG_ALREADY_LOADED;

	SMW_DBG_TRACE_FUNCTION_CALL;

	smw_utils_mutex_lock(ctx.mutex);

	if (!ctx.config_loaded) {
		if (!size || !buffer) {
			status = SMW_STATUS_INVALID_BUFFER;
			goto end;
		}

		status = parse(buffer, size, offset);
		if (status != SMW_STATUS_OK)
			goto end;

		print_database();

		load_subsystems();

		ctx.config_loaded = true;
	}

end:
	smw_utils_mutex_unlock(ctx.mutex);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

__export enum smw_status_code smw_config_unload(void)
{
	enum smw_status_code status = SMW_STATUS_NO_CONFIG_LOADED;

	SMW_DBG_TRACE_FUNCTION_CALL;

	smw_utils_mutex_lock(ctx.mutex);

	if (!ctx.config_loaded)
		goto end;

	unload_subsystems();

	init_database(true);

	print_database();

	ctx.config_loaded = false;

	status = SMW_STATUS_OK;

end:
	smw_utils_mutex_unlock(ctx.mutex);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}
