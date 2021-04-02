// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021 NXP
 */

#include <stdlib.h>
#include <string.h>

#include "lib_mutex.h"
#include "lib_session.h"
#include "lib_opctx.h"

#include "trace.h"

CK_RV libopctx_add(struct libopctx_list *list, struct libopctx *opctx)
{
	CK_MECHANISM_PTR mech;
	struct libopctx *new;

	if (!opctx)
		return CKR_ARGUMENTS_BAD;

	mech = &opctx->mech;

	if ((!mech->pParameter && mech->ulParameterLen) ||
	    (mech->pParameter && !mech->ulParameterLen))
		return CKR_ARGUMENTS_BAD;

	new = malloc(sizeof(*new));
	if (!new)
		return CKR_HOST_MEMORY;

	new->op_flag = opctx->op_flag;
	new->mech.mechanism = mech->mechanism;
	if (mech->pParameter && mech->ulParameterLen) {
		new->mech.ulParameterLen = mech->ulParameterLen;
		new->mech.pParameter = malloc(mech->ulParameterLen);
		if (!new->mech.pParameter) {
			free(new);
			return CKR_HOST_MEMORY;
		}

		memcpy(new->mech.pParameter, mech->pParameter,
		       new->mech.ulParameterLen);
	} else {
		new->mech.ulParameterLen = 0;
		new->mech.pParameter = NULL;
	}
	new->ctx = opctx->ctx;
	new->prev = NULL;
	new->next = NULL;

	DBG_TRACE("Allocated a new operation context (%p)", new);

	LIST_INSERT_TAIL(list, new);

	return CKR_OK;
}

CK_RV libopctx_find(struct libopctx_list *list, CK_FLAGS op_flag,
		    struct libopctx **opctx)
{
	struct libopctx *elem;

	*opctx = NULL;
	for (elem = LIST_FIRST(list); elem; elem = LIST_NEXT(elem)) {
		if (elem->op_flag == op_flag) {
			*opctx = elem;
			break;
		}
	}

	return CKR_OK;
}

CK_RV libopctx_destroy(struct libopctx_list *list, struct libopctx *opctx)
{
	LIST_REMOVE(list, opctx);

	if (opctx->mech.pParameter)
		free(opctx->mech.pParameter);

	if (opctx->ctx)
		free(opctx->ctx);

	DBG_TRACE("Destroy operation context (%p)", opctx);

	free(opctx);

	return CKR_OK;
}

CK_RV libopctx_list_destroy(struct libopctx_list *list)
{
	CK_RV ret;
	struct libopctx *opctx;
	struct libopctx *next;

	DBG_TRACE("Destroy all operations contexts from list %p", list);

	if (!list)
		return CKR_GENERAL_ERROR;

	/* Lock the list until the end of the destruction */
	ret = LLIST_LOCK(list);
	if (ret != CKR_OK)
		return ret;

	opctx = LLIST_FIRST(list);
	while (opctx) {
		next = LLIST_NEXT(opctx);

		if (opctx->mech.pParameter)
			free(opctx->mech.pParameter);

		if (opctx->ctx)
			free(opctx->ctx);

		free(opctx);

		opctx = next;
	}

	/* Close the list and destroy the list mutex */
	LLIST_CLOSE(list);

	return ret;
}
