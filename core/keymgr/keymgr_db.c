// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022 NXP
 */

#include "smw_status.h"

#include "debug.h"
#include "global.h"
#include "keymgr_db.h"

static void prepare_osal_key(struct smw_keymgr_identifier *identifier,
			     struct osal_key *key)
{
	key->persistent = identifier->persistent;
	key->info = identifier;
	key->info_size = sizeof(*identifier);

	key->range.min = 1;
	key->range.max = -1;
}

int smw_keymgr_db_create(unsigned int *id,
			 struct smw_keymgr_identifier *identifier)
{
	int ret = SMW_STATUS_KEY_DB_CREATE;
	struct osal_key key = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!id || !identifier)
		return SMW_STATUS_INVALID_PARAM;

	if (!g_smw_ctx.ops.add_key_info)
		return SMW_STATUS_OPS_INVALID;

	prepare_osal_key(identifier, &key);

	if (!g_smw_ctx.ops.add_key_info(&key) && key.id != INVALID_KEY_ID) {
		*id = key.id;
		ret = SMW_STATUS_OK;
	}

	return ret;
}

int smw_keymgr_db_update(unsigned int id,
			 struct smw_keymgr_identifier *identifier)
{
	int ret = SMW_STATUS_KEY_DB_UPDATE;
	struct osal_key key = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!identifier)
		return SMW_STATUS_INVALID_PARAM;

	if (!g_smw_ctx.ops.update_key_info)
		return SMW_STATUS_OPS_INVALID;

	prepare_osal_key(identifier, &key);
	key.id = id;

	if (!g_smw_ctx.ops.update_key_info(&key))
		ret = SMW_STATUS_OK;

	return ret;
}

int smw_keymgr_db_delete(unsigned int id,
			 struct smw_keymgr_identifier *identifier)

{
	int ret = SMW_STATUS_KEY_DB_DELETE;
	struct osal_key key = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!g_smw_ctx.ops.delete_key_info)
		return SMW_STATUS_OPS_INVALID;

	prepare_osal_key(identifier, &key);
	key.id = id;

	if (!g_smw_ctx.ops.delete_key_info(&key))
		ret = SMW_STATUS_OK;

	return ret;
}

int smw_keymgr_db_get_info(unsigned int id,
			   struct smw_keymgr_identifier *identifier)
{
	int ret = SMW_STATUS_KEY_DB_GET_INFO;
	struct osal_key key = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!identifier)
		return SMW_STATUS_INVALID_PARAM;

	if (!g_smw_ctx.ops.get_key_info)
		return SMW_STATUS_OPS_INVALID;

	prepare_osal_key(identifier, &key);
	key.id = id;

	if (!g_smw_ctx.ops.get_key_info(&key))
		ret = SMW_STATUS_OK;
	else if (key.id == INVALID_KEY_ID)
		ret = SMW_STATUS_UNKNOWN_ID;

	return ret;
}
