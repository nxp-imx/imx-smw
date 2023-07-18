// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020, 2023 NXP
 */

#include "lib_context.h"
#include "lib_mutex.h"

CK_RV libmutex_create(CK_VOID_PTR_PTR mutex)
{
	CK_RV ret = CKR_OK;
	struct libmutex *ops = NULL;

	*mutex = NULL;

	ops = libctx_get_mutex();
	if (!ops)
		return CKR_GENERAL_ERROR;

	if (ops->create)
		ret = ops->create(mutex);

	return ret;
}

CK_RV libmutex_destroy(CK_VOID_PTR_PTR mutex)
{
	CK_RV ret = CKR_OK;
	struct libmutex *ops = NULL;

	ops = libctx_get_mutex();
	if (!ops)
		return CKR_GENERAL_ERROR;

	if (ops->destroy) {
		ret = ops->destroy(*mutex);
		if (ret == CKR_OK)
			*mutex = NULL;
	}

	return ret;
}

CK_RV libmutex_lock(CK_VOID_PTR mutex)
{
	CK_RV ret = CKR_OK;
	struct libmutex *ops = NULL;

	ops = libctx_get_mutex();
	if (!ops)
		return CKR_GENERAL_ERROR;

	if (ops->lock)
		ret = ops->lock(mutex);

	return ret;
}

void libmutex_unlock(CK_VOID_PTR mutex)
{
	struct libmutex *ops = NULL;

	ops = libctx_get_mutex();
	if (ops && ops->unlock)
		(void)ops->unlock(mutex);
}
