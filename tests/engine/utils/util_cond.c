// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
 */

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <time.h>

#include "util.h"
#include "util_cond.h"
#include "util_mutex.h"

/**
 * struct thr_cond - Thread waiting condition
 * @active: True if thread waiting condition still active
 * @cond: System thread condition variable
 */
struct thr_cond {
	int active;
	pthread_cond_t wait_cond;
};

void *util_cond_create(void)
{
	struct thr_cond *thr_cond = NULL;

	thr_cond = calloc(1, sizeof(*thr_cond));
	if (thr_cond) {
		if (pthread_cond_init(&thr_cond->wait_cond, NULL)) {
			free(thr_cond);
			thr_cond = NULL;
		}
	}

	return thr_cond;
}

int util_cond_destroy(void **cond)
{
	struct thr_cond *thr_cond = NULL;

	if (!cond)
		return ERR_CODE(BAD_ARGS);

	thr_cond = *cond;

	if (thr_cond) {
		thr_cond->active = false;

		if (pthread_cond_destroy(&thr_cond->wait_cond))
			return ERR_CODE(COND_DESTROY);

		free(thr_cond);

		*cond = NULL;
	}

	return ERR_CODE(PASSED);
}

int util_cond_signal(void *cond)
{
	struct thr_cond *thr_cond = cond;

	if (!thr_cond) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	thr_cond->active = false;
	if (pthread_cond_signal(&thr_cond->wait_cond)) {
		DBG_PRINT("Signal (%p) failed: %s", thr_cond->wait_cond,
			  util_get_strerr());
		return ERR_CODE(FAILED);
	}

	return ERR_CODE(PASSED);
}

int util_cond_wait(void *cond, void *mutex, unsigned int timeout)
{
	int res = ERR_CODE(BAD_ARGS);
	int err = 0;
	struct timespec ts = { 0 };
	struct thr_cond *thr_cond = cond;

	if (!thr_cond || !mutex || !timeout) {
		DBG_PRINT_BAD_ARGS();
		return res;
	}

	util_mutex_lock(mutex);

	if (clock_gettime(CLOCK_REALTIME, &ts)) {
		DBG_PRINT("Clock gettime: %s", util_get_strerr());
		res = ERR_CODE(INTERNAL);
		goto exit;
	}

	ts.tv_sec += timeout;

	thr_cond->active = true;

	while (thr_cond->active) {
		err = pthread_cond_timedwait(&thr_cond->wait_cond, mutex, &ts);
		if (err) {
			if (err == ETIMEDOUT) {
				DBG_PRINT("Wait (%p) failed: Timeout",
					  thr_cond->wait_cond);
				res = ERR_CODE(TIMEOUT);
			} else {
				DBG_PRINT("Wait (%p) failed %d",
					  thr_cond->wait_cond, err);
				res = ERR_CODE(FAILED);
			}

			goto exit;
		}
	}

	res = ERR_CODE(PASSED);
exit:
	util_mutex_unlock(mutex);

	return res;
}
