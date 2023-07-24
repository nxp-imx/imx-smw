// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
 */

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>

#include "util.h"
#include "util_cond.h"
#include "util_mutex.h"

void *util_cond_create(void)
{
	void *cond = NULL;

	cond = calloc(1, sizeof(pthread_cond_t));
	if (cond) {
		if (pthread_cond_init(cond, NULL)) {
			free(cond);
			cond = NULL;
		}
	}

	return cond;
}

int util_cond_destroy(void **cond)
{
	if (!cond)
		return ERR_CODE(BAD_ARGS);

	if (*cond) {
		if (pthread_cond_destroy(*cond))
			return ERR_CODE(COND_DESTROY);

		free(*cond);

		*cond = NULL;
	}

	return ERR_CODE(PASSED);
}

int util_cond_signal(void *cond)
{
	if (!cond) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	if (pthread_cond_signal(cond)) {
		DBG_PRINT("Signal (%p) failed: %s", cond, util_get_strerr());
		return ERR_CODE(FAILED);
	}

	return ERR_CODE(PASSED);
}

int util_cond_wait(void *cond, void *mutex, unsigned int timeout)
{
	int res = ERR_CODE(FAILED);
	int err = 0;
	struct timespec ts = { 0 };

	if (!cond || !mutex || !timeout) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	util_mutex_lock(mutex);

	if (clock_gettime(CLOCK_REALTIME, &ts)) {
		DBG_PRINT("Clock gettime: %s", util_get_strerr());
		res = ERR_CODE(INTERNAL);
		goto exit;
	}

	ts.tv_sec += timeout;

	err = pthread_cond_timedwait(cond, mutex, &ts);
	if (err) {
		if (err == ETIMEDOUT) {
			DBG_PRINT("Wait (%p) failed: Timeout", cond);
			res = ERR_CODE(TIMEOUT);
		} else {
			DBG_PRINT("Wait (%p) failed %d", cond, err);
		}
	} else {
		res = ERR_CODE(PASSED);
	}

exit:
	util_mutex_unlock(mutex);

	return res;
}
