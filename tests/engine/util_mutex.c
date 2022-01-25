// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022 NXP
 */

#include <pthread.h>
#include <stdlib.h>

#include "util.h"
#include "util_mutex.h"

void *util_mutex_create(void)
{
	void *mutex = NULL;

	mutex = calloc(1, sizeof(pthread_mutex_t));
	if (mutex) {
		if (pthread_mutex_init(mutex, NULL)) {
			free(mutex);
			mutex = NULL;
		}
	}

	return mutex;
}

int util_mutex_destroy(void **mutex)
{
	if (!mutex)
		return ERR_CODE(BAD_ARGS);

	/* Warning: don't use the DBG_PRINT_XXX macro */
	if (*mutex) {
		/* Wait the mutex to be available */
		pthread_mutex_lock(*mutex);
		pthread_mutex_unlock(*mutex);

		if (pthread_mutex_destroy(*mutex))
			return ERR_CODE(MUTEX_DESTROY);

		free(*mutex);

		*mutex = NULL;
	}

	return ERR_CODE(PASSED);
}

void util_mutex_lock(void *mutex)
{
	/* Warning: don't use the DBG_PRINT_XXX macro */
	if (mutex)
		pthread_mutex_lock(mutex);
}

void util_mutex_unlock(void *mutex)
{
	/* Warning: don't use the DBG_PRINT_XXX macro */
	if (mutex)
		pthread_mutex_unlock(mutex);
}
