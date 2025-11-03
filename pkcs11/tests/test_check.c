// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021, 2023-2025 NXP
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

const char *test_status_string(int status)
{
	const char *string = "FAILED";

	switch (status) {
	case TEST_PASS:
		string = "PASSED";
		break;

	case TEST_SKIP:
		string = "SKIPPED";
		break;

	default:
		break;
	}

	return string;
}

int check_ckrv(CK_RV got, CK_RV exp, const char *func, int line,
	       const char *const str, int *status)
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

			if (got == CKR_FUNCTION_NOT_SUPPORTED)
				*status = TEST_SKIP;
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

	nb = snprintf(buf, max_len, "[TEST] ");

	if (nb >= 0 && !DEC_OVERFLOW(max_len, nb)) {
		if (tests_data.trace_pid)
			nb = snprintf(buf, max_len, "{pid #%d} ",
				      tests_data.trace_pid);
	}

	if (nb >= 0 && !DEC_OVERFLOW(max_len, nb)) {
		va_start(args, format);

		(void)vsnprintf(&buf[nb], max_len, format, args);
		va_end(args);
	}

	(void)fprintf(stdout, "%s", buf);
}

void test_dump_hex(char *msg, void *buf, size_t len)
{
	size_t idx = 0;
	char out[256] = { 0 };
	int off = 0;
	int nb_char = 0;

	test_printf(" %s (%p-%zu)\n", msg, buf, len);

	if (buf) {
		for (idx = 0; idx < len; idx++) {
			if ((!(idx % 16) && idx > 0) ||
			    off == (sizeof(out) - 1)) {
				test_printf("%s\n", out);
				off = 0;
			}

			nb_char =
				snprintf(out + off, (sizeof(out) - off),
					 "%02X ", ((unsigned char *)buf)[idx]);
			if (nb_char < 0)
				break;

			off += nb_char;
		}

		if (off > 0)
			test_printf("%s\n", out);
	}
}
