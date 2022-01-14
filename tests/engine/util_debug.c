// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022 NXP
 */

#include <stdarg.h>
#include <stdio.h>

#include "util.h"
#include "util_debug.h"
#include "util_mutex.h"
#include "util_thread.h"

void util_dbg_printf(const char *function, int line, const char *fmt, ...)
{
	struct app_data *app;
	const char *thr_name = NULL;
	va_list args;

	va_start(args, fmt);

	app = util_get_app();
	if (app)
		util_mutex_lock(app->lock_dbg);

	(void)util_get_thread_name(app, &thr_name);

	if (thr_name)
		printf("(%s) [%s:%d] ", thr_name, function, line);
	else
		printf("[%s:%d] ", function, line);

	vprintf(fmt, args);
	printf("\n");

	if (app)
		util_mutex_unlock(app->lock_dbg);

	va_end(args);
}

void util_dbg_dumphex(const char *function, int line, char *msg, void *buf,
		      size_t len)
{
	struct app_data *app;
	const char *thr_name = NULL;
	size_t idx;
	char out[256];
	int off = 0;

	app = util_get_app();
	if (app)
		util_mutex_lock(app->lock_dbg);

	(void)util_get_thread_name(app, &thr_name);

	if (thr_name)
		printf("(%s) [%s:%d] %s (%p-%zu)\n", thr_name, function, line,
		       msg, buf, len);
	else
		printf("[%s:%d] %s (%p-%zu)\n", function, line, msg, buf, len);

	for (idx = 0; idx < len; idx++) {
		if (((idx % 16) == 0) && idx > 0) {
			printf("%s\n", out);
			off = 0;
		}
		off += snprintf(out + off, (sizeof(out) - off), "%02X ",
				((char *)buf)[idx]);
	}

	if (off > 0)
		printf("%s\n", out);

	(void)fflush(stdout);

	if (app)
		util_mutex_unlock(app->lock_dbg);
}
