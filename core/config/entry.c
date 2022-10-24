// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2022 NXP
 */

#include "smw_status.h"

#include "compiler.h"
#include "global.h"
#include "debug.h"
#include "utils.h"
#include "operations.h"
#include "subsystems.h"

#include "common.h"
#include "database.h"

int smw_config_init(void)
{
	int status = SMW_STATUS_OK;

	struct smw_ctx *ctx;

	SMW_DBG_TRACE_FUNCTION_CALL;

	ctx = get_smw_ctx();

	SMW_DBG_ASSERT(ctx);

	if (!ctx) {
		status = SMW_STATUS_INVALID_LIBRARY_CONTEXT;
		goto end;
	}

	if (smw_utils_mutex_init(&ctx->config_mutex)) {
		status = SMW_STATUS_MUTEX_INIT_FAILURE;
		goto end;
	}

	if (smw_utils_mutex_lock(ctx->config_mutex)) {
		status = SMW_STATUS_MUTEX_LOCK_FAILURE;
		goto end;
	}

	SMW_DBG_ASSERT(!ctx->config_db);
	SMW_DBG_PRINTF(DEBUG, "Configuration database allocation\n");
	ctx->config_db = SMW_UTILS_CALLOC(1, sizeof(struct database));
	if (!ctx->config_db) {
		status = SMW_STATUS_ALLOC_FAILURE;
		(void)smw_utils_mutex_unlock(ctx->config_mutex);
		goto end;
	}

	init_database(false);

	if (smw_utils_mutex_unlock(ctx->config_mutex))
		status = SMW_STATUS_MUTEX_UNLOCK_FAILURE;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int smw_config_deinit(void)
{
	int status = SMW_STATUS_OK;

	struct smw_ctx *ctx;

	SMW_DBG_TRACE_FUNCTION_CALL;

	ctx = get_smw_ctx();

	SMW_DBG_ASSERT(ctx);

	if (!ctx)
		return SMW_STATUS_INVALID_LIBRARY_CONTEXT;

	if (smw_utils_mutex_lock(ctx->config_mutex)) {
		status = SMW_STATUS_MUTEX_LOCK_FAILURE;
		goto end;
	}

	SMW_DBG_ASSERT(ctx->config_db);
	SMW_DBG_PRINTF(DEBUG, "Configuration database free\n");
	SMW_UTILS_FREE(ctx->config_db);
	ctx->config_db = NULL;

	if (smw_utils_mutex_unlock(ctx->config_mutex)) {
		status = SMW_STATUS_MUTEX_UNLOCK_FAILURE;
		goto end;
	}

	if (smw_utils_mutex_destroy(&ctx->config_mutex))
		status = SMW_STATUS_MUTEX_DESTROY_FAILURE;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

__export enum smw_status_code smw_config_load(char *buffer, unsigned int size,
					      unsigned int *offset)
{
	enum smw_status_code status = SMW_STATUS_OK;
	enum smw_status_code status_mutex = SMW_STATUS_OK;

	struct smw_ctx *ctx;

	SMW_DBG_TRACE_FUNCTION_CALL;

	ctx = get_smw_ctx();

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

__export enum smw_status_code smw_config_unload(void)
{
	enum smw_status_code status = SMW_STATUS_OK;
	enum smw_status_code status_mutex = SMW_STATUS_OK;

	struct smw_ctx *ctx;

	SMW_DBG_TRACE_FUNCTION_CALL;

	ctx = get_smw_ctx();

	if (!ctx)
		return SMW_STATUS_INVALID_LIBRARY_CONTEXT;

	if (smw_utils_mutex_lock(ctx->config_mutex)) {
		status_mutex = SMW_STATUS_MUTEX_LOCK_FAILURE;
		goto end;
	}

	status = SMW_STATUS_NO_CONFIG_LOADED;

	if (!ctx->config_loaded)
		goto end;

	unload_subsystems();

	init_database(true);

	print_database();

	ctx->config_loaded = false;

	status = SMW_STATUS_OK;

end:
	if (status_mutex == SMW_STATUS_OK)
		if (smw_utils_mutex_unlock(ctx->config_mutex))
			status_mutex = SMW_STATUS_MUTEX_UNLOCK_FAILURE;
	if (status == SMW_STATUS_OK)
		status = status_mutex;

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}
