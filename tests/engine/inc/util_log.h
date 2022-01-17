/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2022 NXP
 */

#ifndef __UTIL_LOG_H__
#define __UTIL_LOG_H__

#include "types.h"

#define FPRINT_TEST_INTERNAL_FAILURE(app, test_name)                           \
	util_log(app, "%s: %s (%s)\n", test_name, ERR_STATUS(FAILED),          \
		 ERR_STATUS(INTERNAL))

#define FPRINT_TEST_STATUS(app, test_name, status)                             \
	util_log(app, "%s: %s\n", (test_name), (status))

#define FPRINT_MESSAGE(app, ...) util_log(app, __VA_ARGS__)

/**
 * util_log() - Log message in opened application log file
 * @app: Application data
 * @fmt: Print format
 * @...: Optional print argument specified by @fmt
 */
void util_log(struct app_data *app, const char *fmt, ...);

/**
 * util_log_status() - Log a status message in opened application log file
 * @app: Application data
 * @fmt: Print format
 * @...: Optional print argument specified by @fmt
 *
 * Function writes the status message into the application log file and
 * print the same to the stdout.
 * Function doesn't add the new line termination.
 */
void util_log_status(struct app_data *app, const char *fmt, ...);

/**
 * util_log_find() - Find a string in opened application log file
 * @app: Application data
 * @str: String to find
 *
 * Return:
 * PASSED          - Message found
 * -FAILED         - Message not found
 * -INTERNAL       - Internal error when accessing the log
 */
int util_log_find(struct app_data *app, const char *str);

#endif /* __UTIL_LOG_H__ */
