// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
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
		printf("[%s] [%s:%d] ", thr, function, line);
	else
		printf("[%s:%d] ", function, line);
}

void util_dbg_printf(const char *function, int line, const char *fmt, ...)
{
	struct test_data *test = NULL;
	struct app_data *app = NULL;
	const char *thr_name = NULL;
	const char *app_name = NULL;
	va_list args = { 0 };

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
	struct app_data *app = NULL;
	const char *thr_name = NULL;
	const char *app_name = NULL;
	size_t idx = 0;
	char out[256] = { 0 };
	int off = 0;
	int nb_char = 0;

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

	if (buf) {
		for (idx = 0; idx < len; idx++) {
			if ((!(idx % 16) && idx > 0) ||
			    off == (sizeof(out) - 1)) {
				printf("%s\n", out);
				off = 0;
			}

			nb_char = snprintf(out + off, (sizeof(out) - off),
					   "%02X ", ((char *)buf)[idx]);
			if (nb_char < 0)
				break;

			off += nb_char;
		}

		if (off > 0)
			printf("%s\n", out);
	}

	(void)fflush(stdout);

	if (test)
		util_mutex_unlock(test->lock_dbg);
}
