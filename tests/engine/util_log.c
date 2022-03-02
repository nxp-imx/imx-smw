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

int util_log_find(struct app_data *app, const char *str)
{
	int res = ERR_CODE(INTERNAL);
	int found = 0;
	long fsave_pos = 0;
	char buf[256] = { 0 };
	char *nl;

	util_mutex_lock(app->lock_log);

	/* Backup current status file position */
	fsave_pos = ftell(app->log);
	if (fsave_pos == -1) {
		DBG_PRINT("Log error %s", util_get_strerr());
		goto exit;
	}

	/* Set status file position to beginning */
	if (fseek(app->log, 0, SEEK_SET)) {
		DBG_PRINT("Log error %s", util_get_strerr());
		goto exit;
	}

	while (fgets(buf, sizeof(buf), app->log)) {
		nl = strchr(buf, '\n');
		if (nl)
			*nl = '\0';

		if (strlen(buf) && !strncmp(buf, str, strlen(buf))) {
			found = 1;
			break;
		}
	};

	if (found)
		res = ERR_CODE(PASSED);
	else
		res = ERR_CODE(FAILED);

exit:
	/* Restore status file position */
	if (fsave_pos >= 0) {
		if (fseek(app->log, fsave_pos, SEEK_SET)) {
			DBG_PRINT("Log error %s", util_get_strerr());
			res = ERR_CODE(INTERNAL);
		}
	}

	util_mutex_unlock(app->lock_log);

	return res;
}
