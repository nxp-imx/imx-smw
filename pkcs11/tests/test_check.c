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
	int ret = 1;
	int nb;
	char buf[256];

	nb = snprintf(buf, sizeof(buf), "[%s line %d] ", func, line);

	if (got == exp) {
		if (nb > 0)
			(void)snprintf(&buf[nb], sizeof(buf) - nb,
				       "%s OK (returned %s)\n", str,
				       get_ckrv_name(got));

		ret = 0;
	} else {
		if (nb > 0)
			(void)snprintf(&buf[nb], sizeof(buf) - nb,
				       "%s FAILED (returned %s expected %s)\n",
				       str, get_ckrv_name(got),
				       get_ckrv_name(exp));
	}

	TEST_OUT("%s", buf);

	return ret;
}

int check_expected(const bool exp, const char *func, int line,
		   const char *format, ...)
{
	int nb;
	char buf[256];
	va_list args;

	if (!exp) {
		va_start(args, format);

		nb = snprintf(buf, sizeof(buf), "[%s line %d] ", func, line);
		if (nb > 0)
			(void)vsnprintf(&buf[nb], sizeof(buf) - nb - 1, format,
					args);

		TEST_OUT("%s\n", buf);

		va_end(args);
		return 1;
	}

	return 0;
}

void test_printf(const char *format, ...)
{
	va_list args;
	int nb = 0;
	char buf[256];

	if (tests_data.trace_pid)
		nb = snprintf(buf, sizeof(buf), "{pid #%d} ",
			      tests_data.trace_pid);

	if (nb >= 0) {
		va_start(args, format);
		(void)vsnprintf(&buf[nb], sizeof(buf) - nb, format, args);
		va_end(args);
	}

	(void)fprintf(stdout, "%s", buf);
}
