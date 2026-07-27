/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2026 NXP
 */

#ifndef CLI_LOGGER_H
#define CLI_LOGGER_H

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

/* Log sources */
enum log_src {
	LOG_SRC_CLI = 0, /* CLI layer */
	LOG_SRC_SMW,	 /* SMW backend */
	LOG_SRC_PSA	 /* PSA backend */
};

/* Log levels - messages above active level are filtered out */
enum log_level {
	LOG_LEVEL_ERROR = 0, /* Errors only */
	LOG_LEVEL_INFO,	     /* Informational messages */
	LOG_LEVEL_VERBOSE    /* Verbose/debug messages */
};

/* Log tags */
enum log_tag {
	LOG_TAG_INFO = 0, /* Informational */
	LOG_TAG_SUCCESS,  /* Success */
	LOG_TAG_VERBOSE,  /* Verbose */
	LOG_TAG_ERROR,	  /* Error */
};

void logger_init(enum log_dest dest, const char *log_filename,
		 enum log_level level);
void logger_cleanup(void);
void logger_log(enum log_src src, enum log_level level, enum log_tag tag,
		const char *fmt, ...);
void logger_log_error(enum log_src src, const char *fmt, ...);
void logger_log_desc(enum log_src src, const char *fmt, ...);

/* -------------------------------------------------------------------------
 * CLI convenience macros
 * -------------------------------------------------------------------------
 */
#define LOG_INFO(fmt, ...)                                                     \
	logger_log(LOG_SRC_CLI, LOG_LEVEL_INFO, LOG_TAG_INFO, fmt,             \
		   ##__VA_ARGS__)

#define LOG_SUCCESS(fmt, ...)                                                  \
	logger_log(LOG_SRC_CLI, LOG_LEVEL_INFO, LOG_TAG_SUCCESS, fmt,          \
		   ##__VA_ARGS__)

#define LOG_VERBOSE(fmt, ...)                                                  \
	logger_log(LOG_SRC_CLI, LOG_LEVEL_VERBOSE, LOG_TAG_VERBOSE, fmt,       \
		   ##__VA_ARGS__)

#define LOG_DESC(fmt, ...) logger_log_desc(LOG_SRC_CLI, fmt, ##__VA_ARGS__)

#define LOG_ERROR(fmt, ...) logger_log_error(LOG_SRC_CLI, fmt, ##__VA_ARGS__)

/* -------------------------------------------------------------------------
 * SMW convenience macros
 * -------------------------------------------------------------------------
 */
#define LOG_SMW_INFO(fmt, ...)                                                 \
	logger_log(LOG_SRC_SMW, LOG_LEVEL_INFO, LOG_TAG_INFO, fmt,             \
		   ##__VA_ARGS__)

#define LOG_SMW_SUCCESS(fmt, ...)                                              \
	logger_log(LOG_SRC_SMW, LOG_LEVEL_INFO, LOG_TAG_SUCCESS, fmt,          \
		   ##__VA_ARGS__)

#define LOG_SMW_VERBOSE(fmt, ...)                                              \
	logger_log(LOG_SRC_SMW, LOG_LEVEL_VERBOSE, LOG_TAG_VERBOSE, fmt,       \
		   ##__VA_ARGS__)

#define LOG_SMW_DESC(fmt, ...) logger_log_desc(LOG_SRC_SMW, fmt, ##__VA_ARGS__)

#define LOG_SMW_ERROR(fmt, ...)                                                \
	logger_log_error(LOG_SRC_SMW, fmt, ##__VA_ARGS__)

/* -------------------------------------------------------------------------
 * PSA convenience macros
 * -------------------------------------------------------------------------
 */
#define LOG_PSA_INFO(fmt, ...)                                                 \
	logger_log(LOG_SRC_PSA, LOG_LEVEL_INFO, LOG_TAG_INFO, fmt,             \
		   ##__VA_ARGS__)

#define LOG_PSA_SUCCESS(fmt, ...)                                              \
	logger_log(LOG_SRC_PSA, LOG_LEVEL_INFO, LOG_TAG_SUCCESS, fmt,          \
		   ##__VA_ARGS__)

#define LOG_PSA_VERBOSE(fmt, ...)                                              \
	logger_log(LOG_SRC_PSA, LOG_LEVEL_VERBOSE, LOG_TAG_VERBOSE, fmt,       \
		   ##__VA_ARGS__)

#define LOG_PSA_DESC(fmt, ...) logger_log_desc(LOG_SRC_PSA, fmt, ##__VA_ARGS__)

#define LOG_PSA_ERROR(fmt, ...)                                                \
	logger_log_error(LOG_SRC_PSA, fmt, ##__VA_ARGS__)

#endif /* CLI_LOGGER_H */
