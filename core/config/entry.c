// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2021 NXP
 */

#include "smw_status.h"

#include "smw_osal.h"
#include "global.h"
#include "debug.h"
#include "utils.h"
#include "operations.h"
#include "subsystems.h"

#include "common.h"

struct ctx ctx = { .mutex = NULL, .load_count = 0 };

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

enum smw_status_code smw_config_load(char *buffer, unsigned int size)
{
	enum smw_status_code status = SMW_STATUS_OK;

	SMW_DBG_TRACE_FUNCTION_CALL;

	smw_utils_mutex_lock(ctx.mutex);

	if (!ctx.load_count) {
		if (!size || !buffer) {
			status = SMW_STATUS_INVALID_BUFFER;
			goto end;
		}

		status = parse(buffer, size);
		if (status != SMW_STATUS_OK)
			goto end;

		print_database();

		load_subsystems();
	}

	ctx.load_count++;

	SMW_DBG_PRINTF(VERBOSE, "%s - Load count: %d\n", __func__,
		       ctx.load_count);

end:
	smw_utils_mutex_unlock(ctx.mutex);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

void smw_config_unload(void)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	smw_utils_mutex_lock(ctx.mutex);

	if (ctx.load_count == 1) {
		unload_subsystems();

		init_database(true);

		print_database();
	}

	if (ctx.load_count >= 1)
		ctx.load_count--;

	smw_utils_mutex_unlock(ctx.mutex);

	SMW_DBG_PRINTF(VERBOSE, "%s - Load count: %d\n", __func__,
		       ctx.load_count);
}
