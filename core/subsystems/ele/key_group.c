// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include "utils.h"

#include "key_group.h"

struct key_group {
	bool persistent;
	bool full;
};

static int append_key_group(struct smw_utils_list *key_grp_list,
			    unsigned int grp, bool persistent, bool full)
{
	int status = SMW_STATUS_ALLOC_FAILURE;
	struct key_group *key_grp = NULL;

	key_grp = SMW_UTILS_MALLOC(sizeof(*key_grp));
	if (key_grp) {
		key_grp->persistent = persistent;
		key_grp->full = full;
		if (!smw_utils_list_append_data(key_grp_list, key_grp, grp,
						NULL)) {
			SMW_UTILS_FREE(key_grp);
			status = SMW_STATUS_ALLOC_FAILURE;
		} else {
			status = SMW_STATUS_OK;
		}
	}

	return status;
}

int ele_get_key_group(struct subsystem_context *ele_ctx, bool persistent,
		      unsigned int *out_grp)
{
	int status = SMW_STATUS_OPERATION_FAILURE;
	int status_mutex = SMW_STATUS_OK;

	struct node *node = NULL;
	struct key_group *key_grp = NULL;
	unsigned int grp = 0;
	unsigned int first_grp = *out_grp;
	unsigned int last_grp = ELE_LAST_TRANSIENT_KEY_GROUP;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (smw_utils_mutex_lock(ele_ctx->key_grp_mutex)) {
		status_mutex = SMW_STATUS_MUTEX_LOCK_FAILURE;
		goto end;
	}

	if (persistent)
		last_grp = ELE_LAST_PERSISTENT_KEY_GROUP;

	for (grp = first_grp; grp <= last_grp; grp++) {
		node = smw_utils_list_find_first(&ele_ctx->key_grp_list, &grp);
		if (node) {
			key_grp = smw_utils_list_get_data(node);
			if (!key_grp)
				break;

			if (key_grp->persistent == persistent &&
			    !key_grp->full) {
				*out_grp = grp;
				status = SMW_STATUS_OK;
				break;
			}
		} else {
			/* Create a new node entry in the list */
			status = append_key_group(&ele_ctx->key_grp_list, grp,
						  persistent, false);
			break;
		}
	}

	if (smw_utils_mutex_unlock(ele_ctx->key_grp_mutex))
		status_mutex = SMW_STATUS_MUTEX_UNLOCK_FAILURE;

end:
	if (status == SMW_STATUS_OK)
		status = status_mutex;

	SMW_DBG_PRINTF(VERBOSE, "%s key group #%d returned %d\n", __func__,
		       *out_grp, status);
	return status;
}

int ele_set_key_group_state(struct subsystem_context *ele_ctx, unsigned int grp,
			    bool persistent, bool full)
{
	int status = SMW_STATUS_OK;
	int status_mutex = SMW_STATUS_OK;

	struct node *node = NULL;
	struct key_group *key_grp = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (smw_utils_mutex_lock(ele_ctx->key_grp_mutex)) {
		status_mutex = SMW_STATUS_MUTEX_LOCK_FAILURE;
		goto end;
	}

	node = smw_utils_list_find_first(&ele_ctx->key_grp_list, &grp);
	if (node) {
		key_grp = smw_utils_list_get_data(node);
		if (key_grp && key_grp->persistent == persistent) {
			key_grp->full = full;
		} else {
			SMW_DBG_PRINTF(ERROR,
				       "%s: key group %u list data error (%p)\n",
				       __func__, grp, key_grp);
			status = SMW_STATUS_OPERATION_FAILURE;
		}

	} else {
		/* Create a new node entry in the list */
		status = append_key_group(&ele_ctx->key_grp_list, grp,
					  persistent, full);
	}

	if (smw_utils_mutex_unlock(ele_ctx->key_grp_mutex))
		status_mutex = SMW_STATUS_MUTEX_UNLOCK_FAILURE;

end:
	if (status == SMW_STATUS_OK)
		status = status_mutex;

	SMW_DBG_PRINTF(VERBOSE, "%s key group #%d returned %d\n", __func__, grp,
		       status);
	return status;
}
