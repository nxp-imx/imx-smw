/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2022 NXP
 */

#ifndef __UTIL_LOG_H__
#define __UTIL_LOG_H__

#include "types.h"

#define FPRINT_MESSAGE(app, ...) util_log((app)->test, __VA_ARGS__)

/**
 * util_log() - Log message in opened test log file
 * @test: Test overall data
 * @fmt: Print format
 * @...: Optional print argument specified by @fmt
 */
void util_log(struct test_data *test, const char *fmt, ...);

/**
 * util_log_status() - Log a status message in opened test log file
 * @test: Test overall data
 * @fmt: Print format
 * @...: Optional print argument specified by @fmt
 *
 * Function writes the status message into the application log file and
 * print the same to the stdout.
 * Function doesn't add the new line termination.
 */
void util_log_status(struct test_data *test, const char *fmt, ...);

#endif /* __UTIL_LOG_H__ */
