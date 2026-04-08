/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2026 NXP
 */

#ifndef CLI_LOGGER_H
#define CLI_LOGGER_H

#include <psa/crypto.h>
#include <smw_crypto.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>

/* Environment variable name for log file override */
#define SMW_LOG_ENV_VAR "SMW_LOG_FILE"

/* Default log file location (used if env var not set) */
#define SMW_DEFAULT_LOG_FILE "smw_cli.log"

/* Log destinations */
enum log_dest {
	LOG_DEST_NONE = 0, /* No logging */
	LOG_DEST_STDERR,   /* Log to stderr */
	LOG_DEST_FILE	   /* Log to file */
};

/* Initialize logger */
void logger_init(enum log_dest dest, const char *log_file);

/* Cleanup logger */
void logger_cleanup(void);

/* Internal logging functions */
void logger_log_error(const char *fmt, ...);
void logger_log_info(const char *fmt, ...);

/* Logging macros */
#define LOG_ERROR(fmt, ...) logger_log_error(fmt, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...)  logger_log_info(fmt, ##__VA_ARGS__)

#endif /* CLI_LOGGER_H */
