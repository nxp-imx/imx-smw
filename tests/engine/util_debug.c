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

static void dbg_func_printf(const char *function, int line, const char *app,
			    const char *thr)
{
	if (app)
		printf("(%s) ", app);

	if (thr)
		printf("(%s) [%s:%d] ", thr, function, line);
	else
		printf("[%s:%d] ", function, line);
}

void util_dbg_printf(const char *function, int line, const char *fmt, ...)
{
	struct test_data *test = NULL;
	struct app_data *app;
	const char *thr_name = NULL;
	const char *app_name = NULL;
	va_list args;

	va_start(args, fmt);

	app = util_app_get_active_data();

	if (app)
		test = app->test;

	if (test) {
		if (test->is_multi_apps)
			app_name = app->name;

		util_mutex_lock(test->lock_dbg);
	}

	(void)util_get_thread_name(app, &thr_name);

	dbg_func_printf(function, line, app_name, thr_name);

	vprintf(fmt, args);
	printf("\n");

	if (test)
		util_mutex_unlock(test->lock_dbg);

	va_end(args);
}

void util_dbg_dumphex(const char *function, int line, char *msg, void *buf,
		      size_t len)
{
	struct test_data *test = NULL;
	struct app_data *app;
	const char *thr_name = NULL;
	const char *app_name = NULL;
	size_t idx;
	char out[256];
	int off = 0;

	app = util_app_get_active_data();

	if (app)
		test = app->test;

	if (test) {
		if (test->is_multi_apps)
			app_name = app->name;

		util_mutex_lock(test->lock_dbg);
	}

	(void)util_get_thread_name(app, &thr_name);

	dbg_func_printf(function, line, app_name, thr_name);
	printf(" %s (%p-%zu)\n", msg, buf, len);

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

	if (test)
		util_mutex_unlock(test->lock_dbg);
}
