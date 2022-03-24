// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022 NXP
 */

#include <stdarg.h>
#include <string.h>

#include "util.h"
#include "util_mutex.h"

void util_log(struct app_data *app, const char *fmt, ...)
{
	int nb_char;
	va_list args;

	va_start(args, fmt);

	util_mutex_lock(app->lock_log);

	nb_char = vfprintf(app->log, fmt, args);
	if (nb_char < 0) {
		DBG_PRINT("Log error %s", util_get_strerr());
		goto exit;
	}

	nb_char = fprintf(app->log, "\n");
	if (nb_char < 0)
		DBG_PRINT("Log error %s", util_get_strerr());

exit:
	if (fflush(app->log))
		DBG_PRINT("Log error %s", util_get_strerr());

	util_mutex_unlock(app->lock_log);

	va_end(args);
}

void util_log_status(struct app_data *app, const char *fmt, ...)
{
	int nb_char;
	va_list args;

	va_start(args, fmt);

	/* Lock and print status on stdout */
	util_mutex_lock(app->lock_dbg);
	(void)vprintf(fmt, args);
	util_mutex_unlock(app->lock_dbg);

	util_mutex_lock(app->lock_log);
	nb_char = vfprintf(app->log, fmt, args);
	if (nb_char < 0)
		DBG_PRINT("Log error %s", util_get_strerr());

	if (fflush(app->log))
		DBG_PRINT("Log error %s", util_get_strerr());

	util_mutex_unlock(app->lock_log);

	va_end(args);
}
