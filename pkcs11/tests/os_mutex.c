// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021 NXP
 */

#include <stdlib.h>
#include <pthread.h>

#include "local.h"
#include "os_mutex.h"

CK_RV mutex_create_empty(CK_VOID_PTR_PTR mutex)
{
	int *mutex_cnt;

	TEST_OUT("Create Empty mutex\n");
	mutex_cnt = calloc(1, sizeof(*mutex_cnt));
	if (!mutex_cnt)
		return CKR_HOST_MEMORY;

	TEST_OUT("Create Empty mutex (%p)\n", mutex_cnt);
	*mutex = mutex_cnt;

	return CKR_OK;
}

CK_RV mutex_destroy_empty(CK_VOID_PTR mutex)
{
	int *cnt = mutex;

	TEST_OUT("Destroy Empty mutex (%p)\n", mutex);
	if (!mutex)
		return CKR_MUTEX_BAD;

	TEST_OUT("Destroy (%p)=%d\n", mutex, *cnt);
	if (*cnt)
		return CKR_GENERAL_ERROR;

	free(mutex);

	return CKR_OK;
}

CK_RV mutex_lock_empty(CK_VOID_PTR mutex)
{
	int *cnt = mutex;

	TEST_OUT("Lock Empty mutex (%p)\n", mutex);
	if (!mutex)
		return CKR_MUTEX_BAD;

	(*cnt)++;
	TEST_OUT("Lock (%p)=%d\n", mutex, *cnt);

	return CKR_OK;
}

CK_RV mutex_unlock_empty(CK_VOID_PTR mutex)
{
	int *cnt = mutex;

	TEST_OUT("Unlock Empty mutex (%p)\n", mutex);
	if (!mutex)
		return CKR_MUTEX_BAD;

	TEST_OUT("Unlock (%p)=%d\n", mutex, *cnt);
	if (!*cnt)
		return CKR_MUTEX_NOT_LOCKED;

	(*cnt)--;

	return CKR_OK;
}

CK_RV mutex_create(CK_VOID_PTR_PTR mutex)
{
	void *mutex_new;

	TEST_OUT("Create mutex\n");
	mutex_new = calloc(1, sizeof(pthread_mutex_t));
	if (!mutex_new)
		return CKR_HOST_MEMORY;

	TEST_OUT("Create mutex (%p)\n", mutex_new);

	if (pthread_mutex_init(mutex_new, PTHREAD_MUTEX_NORMAL)) {
		free(mutex_new);
		return CKR_GENERAL_ERROR;
	}

	*mutex = mutex_new;
	return CKR_OK;
}

CK_RV mutex_destroy(CK_VOID_PTR mutex)
{
	TEST_OUT("Destroy mutex (%p)\n", mutex);
	if (!mutex)
		return CKR_MUTEX_BAD;

	if (pthread_mutex_destroy(mutex))
		return CKR_GENERAL_ERROR;

	free(mutex);

	return CKR_OK;
}

CK_RV mutex_lock(CK_VOID_PTR mutex)
{
	TEST_OUT("Lock mutex (%p)\n", mutex);
	if (!mutex)
		return CKR_MUTEX_BAD;

	if (pthread_mutex_lock(mutex))
		return CKR_MUTEX_BAD;

	TEST_OUT("Locked mutex (%p)\n", mutex);

	return CKR_OK;
}

CK_RV mutex_unlock(CK_VOID_PTR mutex)
{
	TEST_OUT("Unlock mutex (%p)\n", mutex);
	if (!mutex)
		return CKR_MUTEX_BAD;

	if (pthread_mutex_unlock(mutex))
		return CKR_MUTEX_NOT_LOCKED;

	TEST_OUT("Unlocked mutex (%p)\n", mutex);

	return CKR_OK;
}
