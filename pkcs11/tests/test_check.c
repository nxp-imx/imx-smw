// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021 NXP
 */

#include <stdarg.h>

#include "local.h"

static const char *get_ckrv_name(CK_RV val)
{
	const struct ckr_enum *entry = ckr_enum;

	for (; entry->name; entry++) {
		if (entry->val == val)
			return entry->name;
	}

	return "<unknown value>";
}

int check_ckrv(CK_RV got, CK_RV exp, const char *func, int line,
	       const char *const str)
{
	TEST_OUT("[%s line %d] ", func, line);

	if (got == exp) {
		TEST_OUT("%s OK (returned %s)\n", str, get_ckrv_name(got));
		return 0;
	}

	TEST_OUT("%s FAILED (returned %s expected %s)\n", str,
		 get_ckrv_name(got), get_ckrv_name(exp));

	return 1;
}

int check_expected(const bool exp, const char *func, int line,
		   const char *format, ...)
{
	char buf[256];
	va_list args;

	if (!exp) {
		va_start(args, format);

		(void)vsnprintf(buf, sizeof(buf), format, args);

		(void)fprintf(stderr, "[%s line %d] ", func, line);
		(void)fprintf(stderr, "%s\n", buf);

		va_end(args);
		return 1;
	}

	return 0;
}
