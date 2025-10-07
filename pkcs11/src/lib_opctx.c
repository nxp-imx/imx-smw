// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021, 2023-2025 NXP
 */

#include <stdlib.h>
#include <string.h>

#include "lib_mutex.h"
#include "lib_session.h"
#include "lib_opctx.h"
#include "lib_device.h"

#include "lib_cipher.h"
#include "lib_digest.h"
#include "lib_sign_verify.h"

#include "trace.h"

CK_RV libopctx_add(struct libopctx_list *list, struct libopctx *opctx)
{
	CK_MECHANISM_PTR mech = NULL_PTR;
	struct libopctx *new = NULL;

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
	struct libopctx *elem = NULL;

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

	DBG_TRACE("Destroy operation context (%p)", opctx);

	free(opctx);

	return CKR_OK;
}

CK_RV libopctx_list_destroy(struct libopctx_list *list)
{
	CK_RV ret = CKR_GENERAL_ERROR;
	struct libopctx *opctx = NULL;
	struct libopctx *next = NULL;

	DBG_TRACE("Destroy all operations contexts from list %p", list);

	if (!list)
		return ret;

	/* Lock the list until the end of the destruction */
	ret = LLIST_LOCK(list);
	if (ret != CKR_OK)
		return ret;

	opctx = LLIST_FIRST(list);
	while (opctx) {
		next = LLIST_NEXT(opctx);

		if (opctx->mech.pParameter)
			free(opctx->mech.pParameter);

		free(opctx);

		opctx = next;
	}

	/* Close the list and destroy the list mutex */
	LLIST_CLOSE(list);

	return ret;
}

CK_RV libopctx_cancel(struct libopctx_list *list, struct libopctx *opctx,
		      void **context)
{
	CK_RV ret = CKR_OK;

	ret = libdev_cancel_operation(context);
	if (ret != CKR_OK)
		return ret;

	ret = libopctx_destroy(list, opctx);
	return ret;
}

CK_RV libopctx_check_next_state(enum op_state current_state,
				enum op_state next_state, CK_BBOOL *terminate)
{
	CK_RV ret = CKR_OK;

	switch (current_state) {
	case OP_INIT:
		if (next_state != OP_BEGIN && next_state != OP_UPDATE &&
		    next_state != OP_FINAL && next_state != OP_ONE_SHOT) {
			*terminate = CK_FALSE;
			ret = CKR_ARGUMENTS_BAD;
		}
		break;

	case OP_ONE_SHOT:
		if (next_state != OP_ONE_SHOT) {
			*terminate = CK_TRUE;
			ret = CKR_OPERATION_NOT_INITIALIZED;
		}

		break;

	case OP_BEGIN:
		if (next_state != OP_NEXT && next_state != OP_END) {
			*terminate = CK_TRUE;
			ret = CKR_OPERATION_NOT_INITIALIZED;
		}

		break;

	case OP_NEXT:
		if (next_state != OP_END && next_state != OP_NEXT &&
		    next_state != OP_FINAL) {
			*terminate = CK_FALSE;
			ret = CKR_OPERATION_NOT_INITIALIZED;
		}
		break;

	case OP_UPDATE:
		if (next_state != OP_UPDATE && next_state != OP_FINAL) {
			*terminate = CK_FALSE;
			ret = CKR_OPERATION_NOT_INITIALIZED;
		}
		break;

	case OP_END:
		if (next_state != OP_END && next_state != OP_BEGIN &&
		    next_state != OP_ONE_SHOT) {
			*terminate = CK_TRUE;
			ret = CKR_OPERATION_NOT_INITIALIZED;
		}

		break;

	case OP_FINAL:
		if (next_state != OP_FINAL) {
			*terminate = CK_TRUE;
			ret = CKR_OPERATION_NOT_INITIALIZED;
		}

		break;

	default:
		*terminate = CK_TRUE;
		ret = CKR_OPERATION_NOT_INITIALIZED;
		break;
	}

	DBG_TRACE("Operation state: %d -> %d, ret = 0x%lx, terminate = %d",
		  current_state, next_state, ret, *terminate);

	return ret;
}

CK_RV libopctx_copy(struct libopctx *src, struct libopctx *dst)
{
	CK_RV ret = CKR_OK;

	if (!src || !src->ctx)
		return CKR_GENERAL_ERROR;

	memset(&dst->mech, 0, sizeof(dst->mech));

	if (src->mech.pParameter) {
		dst->mech.pParameter = calloc(1, src->mech.ulParameterLen);
		if (!dst->mech.pParameter)
			return CKR_HOST_MEMORY;

		memcpy(dst->mech.pParameter, src->mech.pParameter,
		       dst->mech.ulParameterLen);
	}

	dst->mech.mechanism = src->mech.mechanism;
	dst->mech.ulParameterLen = src->mech.ulParameterLen;

	dst->op_flag = src->op_flag;

	switch (src->op_flag) {
	case CKF_ENCRYPT:
	case CKF_DECRYPT:
	case CKF_MESSAGE_ENCRYPT:
	case CKF_MESSAGE_DECRYPT:
		ret = lib_cipher_copy_operation((void *)src->ctx,
						(void **)&dst->ctx);
		break;

	case CKF_SIGN:
	case CKF_VERIFY:
	case CKF_MESSAGE_SIGN:
	case CKF_MESSAGE_VERIFY:
		ret = lib_sign_verify_copy_operation((void *)src->ctx,
						     (void **)&dst->ctx);
		break;

	case CKF_DIGEST:
		ret = lib_digest_copy_operation((void *)src->ctx,
						(void **)&dst->ctx);
		break;

	default:
		ret = CKR_GENERAL_ERROR;
		break;
	}

	if (ret != CKR_OK) {
		if (dst->mech.pParameter) {
			free(dst->mech.pParameter);
			dst->mech.pParameter = NULL;
		}
	}

	return ret;
}
