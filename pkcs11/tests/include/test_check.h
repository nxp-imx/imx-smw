/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021 NXP
 */
#ifndef __TEST_CHECK_H__
#define __TEST_CHECK_H__

#include <stdio.h>
#include <pkcs11smw.h>

#include "compiler.h"

struct tests_result {
	int count;
	int count_fail;
	int count_pass;
};

struct tests_data {
	struct tests_result result;
	int trace_pid;
};

extern struct tests_data tests_data;

int check_ckrv(CK_RV got, CK_RV exp, const char *func, int line,
	       const char *const str);
int check_expected(const bool exp, const char *func, int line,
		   const char *format, ...);
void test_printf(const char *format, ...) __printf(1, 2);

#define TEST_FAIL 0xBAD
#define TEST_PASS 0xCAFE

#define TEST_OUT(format, ...) test_printf(format, ##__VA_ARGS__)

#define TEST_STATUS(_status) (((_status) == TEST_PASS) ? "PASSED" : "FAILED")

#define CHECK_EXPECTED(exp, ...)                                               \
	check_expected(exp, __func__, __LINE__, __VA_ARGS__)

#define CHECK_CK_RV(val, str) check_ckrv(ret, val, __func__, __LINE__, str)

#define TEST_START(_status)                                                    \
	do {                                                                   \
		_status = TEST_FAIL;                                           \
		TEST_OUT("========================\n");                        \
		TEST_OUT("== TEST %s\n", __func__);                            \
		TEST_OUT("\n");                                                \
		tests_data.result.count++;                                     \
	} while (0)

#define TEST_END(_status)                                                      \
	do {                                                                   \
		__typeof__(_status) __status = (_status);                      \
		TEST_OUT("\n");                                                \
		TEST_OUT("TEST %s %s\n", __func__, TEST_STATUS(__status));     \
		TEST_OUT("========================\n");                        \
		if (__status != TEST_PASS)                                     \
			tests_data.result.count_fail++;                        \
		else                                                           \
			tests_data.result.count_pass++;                        \
	} while (0)

#define SUBTEST_START(_status)                                                 \
	do {                                                                   \
		_status = TEST_FAIL;                                           \
		TEST_OUT("\n");                                                \
		TEST_OUT("************\n");                                    \
		TEST_OUT("* Start SubTest %s\n", __func__);                    \
		TEST_OUT("\n");                                                \
	} while (0)

#define SUBTEST_END(_status)                                                   \
	do {                                                                   \
		TEST_OUT("\n");                                                \
		TEST_OUT("* End SubTest %s - %s\n", __func__,                  \
			 TEST_STATUS(_status));                                \
		TEST_OUT("************\n");                                    \
	} while (0)

#endif /* __TEST_CHECK_H__ */
