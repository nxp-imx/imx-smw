// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <zephyr/kernel.h>
#include <stdlib.h>

#include "internal.h"

int osal_zephyr_mutex_init(void **mutex)
{
	struct k_mutex *mtx;

	if (!mutex)
		return -1;

	if (*mutex)
		return -1;

	mtx = k_malloc(sizeof(struct k_mutex));
	if (!mtx)
		return -1;

	k_mutex_init(mtx);
	*mutex = mtx;

	return 0;
}

int osal_zephyr_mutex_destroy(void **mutex)
{
	if (!mutex || !*mutex)
		return -1;

	k_free(*mutex);
	*mutex = NULL;

	return 0;
}

int osal_zephyr_mutex_lock(void *mutex)
{
	struct k_mutex *mtx = (struct k_mutex *)mutex;

	if (!mtx)
		return -1;

	if (k_mutex_lock(mtx, K_FOREVER) != 0)
		return -1;

	return 0;
}

int osal_zephyr_mutex_unlock(void *mutex)
{
	struct k_mutex *mtx = (struct k_mutex *)mutex;

	if (!mtx)
		return -1;

	if (k_mutex_unlock(mtx) != 0)
		return -1;

	return 0;
}
