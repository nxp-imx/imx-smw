// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
 */

#include <stdarg.h>
#include <string.h>

#include "util.h"
#include "util_mutex.h"

void util_log(struct test_data *test, const char *fmt, ...)
{
	int nb_char = 0;
	va_list args = { 0 };

	if (!test) {
		DBG_PRINT_BAD_ARGS();
		return;
	}

	va_start(args, fmt);

	util_mutex_lock(test->lock_log);

	nb_char = vfprintf(test->log, fmt, args);
	if (nb_char < 0) {
		DBG_PRINT("Log error %s", util_get_strerr());
		goto exit;
	}

	nb_char = fprintf(test->log, "\n");
	if (nb_char < 0)
		DBG_PRINT("Log error %s", util_get_strerr());

exit:
	if (fflush(test->log))
		DBG_PRINT("Log error %s", util_get_strerr());

	util_mutex_unlock(test->lock_log);

	va_end(args);
}

void util_log_status(struct test_data *test, const char *fmt, ...)
{
	int nb_char = 0;
	va_list args = { 0 };

	if (!test) {
		DBG_PRINT_BAD_ARGS();
		return;
	}

	va_start(args, fmt);

	/* Lock and print status on stdout */
	util_mutex_lock(test->lock_dbg);
	(void)vprintf(fmt, args);
	util_mutex_unlock(test->lock_dbg);

	util_mutex_lock(test->lock_log);
	nb_char = vfprintf(test->log, fmt, args);
	if (nb_char < 0)
		DBG_PRINT("Log error %s", util_get_strerr());

	if (fflush(test->log))
		DBG_PRINT("Log error %s", util_get_strerr());

	util_mutex_unlock(test->lock_log);

	va_end(args);
}
