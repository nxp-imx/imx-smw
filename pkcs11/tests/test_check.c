// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021, 2023 NXP
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
	int nb = 0;
	char buf[256] = { 0 };
	size_t max_len = 0;

	max_len = sizeof(buf);
	nb = snprintf(buf, max_len, "[%s line %d] ", func, line);

	if (nb > 0 && !DEC_OVERFLOW(max_len, nb)) {
		if (got == exp) {
			(void)snprintf(&buf[nb], max_len,
				       "%s OK (returned %s)\n", str,
				       get_ckrv_name(got));

			ret = 0;
		} else {
			(void)snprintf(&buf[nb], max_len,
				       "%s FAILED (returned %s expected %s)\n",
				       str, get_ckrv_name(got),
				       get_ckrv_name(exp));
		}
	}

	TEST_OUT("%s", buf);

	return ret;
}

void print_failure(const char *func, int line, const char *format, ...)
{
	int nb = 0;
	char buf[256] = { 0 };
	va_list args = { 0 };
	size_t max_len = 0;

	va_start(args, format);

	max_len = sizeof(buf);
	nb = snprintf(buf, max_len, "[%s line %d] ", func, line);
	if (nb > 0 && !DEC_OVERFLOW(max_len, nb))
		(void)vsnprintf(&buf[nb], max_len - 1, format, args);

	TEST_OUT("%s\n", buf);

	va_end(args);
}

void test_printf(const char *format, ...)
{
	va_list args = { 0 };
	int nb = 0;
	char buf[256] = { 0 };
	size_t max_len = 0;

	max_len = sizeof(buf);

	if (tests_data.trace_pid)
		nb = snprintf(buf, max_len, "{pid #%d} ", tests_data.trace_pid);

	if (nb >= 0 && !DEC_OVERFLOW(max_len, nb)) {
		va_start(args, format);

		(void)vsnprintf(&buf[nb], max_len, format, args);
		va_end(args);
	}

	(void)fprintf(stdout, "%s", buf);
}
