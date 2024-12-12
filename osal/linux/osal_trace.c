// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2024 NXP
 */

#include <errno.h>
#include <sys/file.h>

#include "local.h"

static unsigned int log_level = TRACE_LEVEL;
static FILE *stddebug;

char *get_strerr(void)
{
	int *err = __errno_location();

	if (err)
		return strerror(*err);

	return "Unknown error";
}

void set_log_file(void)
{
	FILE *f = NULL;
	const char *file_name = getenv("SMW_LOG_FILE");

	stddebug = stdout;

	if (file_name) {
		f = fopen(file_name, "w");
		if (f)
			stddebug = f;
	}
}

void set_log_level(void)
{
	char level[128] = { 0 };
	char *endPtr = NULL;
	const char *tmpPtr = NULL;
	unsigned long value = 0;

	tmpPtr = getenv("SMW_LOG_LEVEL");

	if (tmpPtr) {
		(void)strncpy(level, tmpPtr, sizeof(level) - 1);
		value = strtoul(level, &endPtr, 0);
		if (!value && endPtr == level)
			return;

		if (SET_OVERFLOW(value, log_level))
			log_level = DBG_LEVEL_NONE;
	}
}

void log_printf(unsigned int level, const char *fmt, va_list args)
{
	if (level <= log_level) {
		(void)vfprintf(stddebug, fmt, args);

		(void)fflush(stddebug);
	}
}
