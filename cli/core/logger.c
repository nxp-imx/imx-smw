// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */
#define _TIME_BITS		  64
#define _FILE_OFFSET_BITS	  64
#define MIN_TIMESTAMP_BUFFER_SIZE 32

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include "cli_print.h"
#include "helper.h"
#include "logger.h"

/* Active log level - messages above this are filtered out */
static enum log_level active_log_level = LOG_LEVEL_INFO;

/* User-specified logging (via -L option) */
static enum log_dest log_dest = LOG_DEST_NONE;
static FILE *log_file;
static bool log_enabled;

/* Automatic logging (via SMW_LOG_FILE environment variable) */
static FILE *env_log_file;
static bool env_log_enabled;

/* -------------------------------------------------------------------------
 * Internal helpers
 * -------------------------------------------------------------------------
 */

static const char *src_to_tag(enum log_src src)
{
	switch (src) {
	case LOG_SRC_SMW:
		return "SMW";
	case LOG_SRC_PSA:
		return "PSA";
	case LOG_SRC_CLI:
	default:
		return "CLI";
	}
}

static const char *tag_to_str(enum log_tag tag)
{
	switch (tag) {
	case LOG_TAG_SUCCESS:
		return "SUCCESS";
	case LOG_TAG_VERBOSE:
		return "VERBOSE";
	case LOG_TAG_ERROR:
		return "ERROR";
	case LOG_TAG_INFO:
	default:
		return "INFO";
	}
}

static void get_timestamp(char *buffer, size_t size)
{
	time_t now = 0;
	struct tm *tm_info = NULL;

	now = time(NULL);
	if (now == (time_t)-1) {
		SNPRINTF(buffer, size, "TIME_ERROR");
		return;
	}

	tm_info = localtime(&now);
	if (!tm_info) {
		SNPRINTF(buffer, size, "TIME_ERROR");
		return;
	}

	if (!strftime(buffer, size, "%Y-%m-%d %H:%M:%S", tm_info))
		SNPRINTF(buffer, size, "TIME_ERROR");
}

/**
 * @brief Write a formatted log line to a FILE stream.
 *
 * Format: [timestamp] [SRC] [TAG] message
 *
 * @param stream  Destination FILE stream
 * @param src     Log source tag
 * @param tag     Log tag
 * @param fmt     printf-style format string
 * @param args    va_list of format arguments
 */
static void write_log_line(FILE *stream, enum log_src src, enum log_tag tag,
			   const char *fmt, va_list args)
{
	char timestamp[MIN_TIMESTAMP_BUFFER_SIZE] = { 0 };
	va_list args_copy;

	get_timestamp(timestamp, sizeof(timestamp));

	FPRINTF(stream, "[%s] [%s] [%s] ", timestamp, src_to_tag(src),
		tag_to_str(tag));

	va_copy(args_copy, args);
	VFPRINTF(stream, fmt, args_copy);
	va_end(args_copy);

	FPRINTF(stream, "\n");
	FFLUSH(stream);
}

/* -------------------------------------------------------------------------
 * Public API
 * -------------------------------------------------------------------------
 */

/**
 * @brief Log a message at the given source, level and tag.
 *
 * Messages with level > active_log_level are silently dropped.
 * Writes to both the environment log file and the user-specified destination.
 *
 * @param src   Which layer is emitting the message (CLI, SMW, PSA)
 * @param level Verbosity level of this message
 * @param tag   Tag to print in the log line (INFO, SUCCESS, VERBOSE)
 * @param fmt   printf-style format string
 * @param ...   Format arguments
 */
void logger_log(enum log_src src, enum log_level level, enum log_tag tag,
		const char *fmt, ...)
{
	va_list args;

	/* Filter by active log level */
	if (level > active_log_level)
		return;

	va_start(args, fmt);

	/* write_log_line uses va_copy internally so args is safe to reuse */
	if (env_log_enabled && env_log_file)
		write_log_line(env_log_file, src, tag, fmt, args);

	if (log_enabled) {
		if (log_dest == LOG_DEST_FILE && log_file) {
			write_log_line(log_file, src, tag, fmt, args);
		} else if (log_dest == LOG_DEST_STDERR) {
			FPRINTF(stderr, "[%s] [%s] ", src_to_tag(src),
				tag_to_str(tag));
			VFPRINTF(stderr, fmt, args);
			FPRINTF(stderr, "\n");
		}
	}

	va_end(args);
}

/**
 * @brief Log an error message.
 *
 * Errors are never filtered by log level — they always appear.
 * Always printed to stderr and written to any open log files.
 *
 * @param src  Which layer is emitting the error (CLI, SMW, PSA)
 * @param fmt  printf-style format string
 * @param ...  Format arguments
 */
void logger_log_error(enum log_src src, const char *fmt, ...)
{
	char timestamp[MIN_TIMESTAMP_BUFFER_SIZE] = { 0 };
	const char *src_tag = src_to_tag(src);
	va_list args;
	va_list args_copy;

	va_start(args, fmt);

	/* Always print to stderr with ERROR macro style (color + newlines) */
	FPRINTF(stderr, "\n%s[%s] [ERROR] ", IS_TTY_STDERR ? COLOR_RED : "",
		src_tag);
	va_copy(args_copy, args);
	VFPRINTF(stderr, fmt, args_copy);
	va_end(args_copy);
	FPRINTF(stderr, "%s\n", IS_TTY_STDERR ? COLOR_RESET : "");

	/* Write to env log file - with timestamp */
	if (env_log_enabled && env_log_file) {
		get_timestamp(timestamp, sizeof(timestamp));
		FPRINTF(env_log_file, "[%s] [%s] [ERROR] ", timestamp, src_tag);
		va_copy(args_copy, args);
		VFPRINTF(env_log_file, fmt, args_copy);
		va_end(args_copy);
		FPRINTF(env_log_file, "\n");
		FFLUSH(env_log_file);
	}

	/* Write to user log file - with timestamp */
	if (log_enabled && log_dest == LOG_DEST_FILE && log_file) {
		if (!timestamp[0])
			get_timestamp(timestamp, sizeof(timestamp));
		FPRINTF(log_file, "[%s] [%s] [ERROR] ", timestamp, src_tag);
		va_copy(args_copy, args);
		VFPRINTF(log_file, fmt, args_copy);
		va_end(args_copy);
		FPRINTF(log_file, "\n");
		FFLUSH(log_file);
	}

	va_end(args);
}

/**
 * @brief Log a description line attached below the previous error.
 *
 * On stderr: printed in red, no timestamp, indented below the error line.
 * In log files: printed with timestamp and [DESCRIPTION] tag.
 *
 * @param src  Which layer is emitting the description (CLI, SMW, PSA)
 * @param fmt  printf-style format string
 * @param ...  Format arguments
 */
void logger_log_desc(enum log_src src, const char *fmt, ...)
{
	char timestamp[MIN_TIMESTAMP_BUFFER_SIZE] = { 0 };
	const char *src_tag = src_to_tag(src);
	va_list args;
	va_list args_copy;

	va_start(args, fmt);

	/* stderr: red, no timestamp, no src tag, visually attached below the error */
	FPRINTF(stderr, "%s[DESCRIPTION] ", IS_TTY_STDERR ? COLOR_RED : "");
	va_copy(args_copy, args);
	VFPRINTF(stderr, fmt, args_copy);
	va_end(args_copy);
	FPRINTF(stderr, "%s\n\n", IS_TTY_STDERR ? COLOR_RESET : "");

	/* Write to env log file - with timestamp and src tag */
	if (env_log_enabled && env_log_file) {
		get_timestamp(timestamp, sizeof(timestamp));
		FPRINTF(env_log_file, "[%s] [%s] [DESCRIPTION] ", timestamp,
			src_tag);
		va_copy(args_copy, args);
		VFPRINTF(env_log_file, fmt, args_copy);
		va_end(args_copy);
		FPRINTF(env_log_file, "\n");
		FFLUSH(env_log_file);
	}

	/* Write to user log file - with timestamp and src tag */
	if (log_enabled && log_dest == LOG_DEST_FILE && log_file) {
		if (!timestamp[0])
			get_timestamp(timestamp, sizeof(timestamp));
		FPRINTF(log_file, "[%s] [%s] [DESCRIPTION] ", timestamp,
			src_tag);
		va_copy(args_copy, args);
		VFPRINTF(log_file, fmt, args_copy);
		va_end(args_copy);
		FPRINTF(log_file, "\n");
		FFLUSH(log_file);
	}

	va_end(args);
}

/**
 * @brief Initialize the logging subsystem.
 *
 * Sets up both the automatic (SMW_LOG_FILE env var) and user-specified
 * (-L option) log destinations, and configures the active log level.
 *
 * @param dest          User-specified log destination
 * @param log_filename  Log file path (required if dest is LOG_DEST_FILE)
 * @param level         Maximum log level to emit (INFO or VERBOSE)
 */
void logger_init(enum log_dest dest, const char *log_filename,
		 enum log_level level)
{
	const char *log_path = NULL;
	char timestamp[MIN_TIMESTAMP_BUFFER_SIZE] = { 0 };
	const char *env_log_path = getenv(SMW_LOG_ENV_VAR);

	active_log_level = level;

	/* Determine automatic log file path from environment */
	if (env_log_path) {
		if (!strlen(env_log_path) ||
		    !strcasecmp(env_log_path, "none") ||
		    !strcasecmp(env_log_path, "off")) {
			log_path = NULL;
		} else {
			log_path = env_log_path;
		}
	} else {
		log_path = SMW_DEFAULT_LOG_FILE;
	}

	/* Open automatic log file */
	if (log_path) {
		env_log_file = fopen(log_path, "a");
		if (env_log_file) {
			env_log_enabled = true;
			get_timestamp(timestamp, sizeof(timestamp));
			FPRINTF(env_log_file,
				"\n[%s] [CLI] [INFO] ===== New logging session",
				timestamp);
			FPRINTF(env_log_file, " (level=%s) =====\n",
				tag_to_str(LOG_TAG_INFO));
			FFLUSH(env_log_file);
		} else {
			WARNING("Automatic logging disabled - cannot open SMW_LOG_FILE='%s': %s\n",
				log_path, strerror(errno));
			env_log_enabled = false;
		}
	}

	/* User-specified destination */
	if (dest == LOG_DEST_NONE) {
		log_enabled = false;
		return;
	}

	log_enabled = true;
	log_dest = dest;

	if (dest == LOG_DEST_FILE) {
		if (!log_filename || !strlen(log_filename)) {
			ERROR("Log file destination specified but no filename provided");
			log_enabled = false;
			return;
		}

		log_file = fopen(log_filename, "a");
		if (!log_file) {
			ERROR("Failed to open log file: %s", log_filename);
			log_enabled = false;
			return;
		}

		get_timestamp(timestamp, sizeof(timestamp));
		FPRINTF(log_file,
			"\n[%s] [CLI] [INFO] ===== New logging session",
			timestamp);
		FPRINTF(log_file, " (level=%s) =====\n",
			tag_to_str(LOG_TAG_INFO));
		FFLUSH(log_file);
	}
}

/**
 * @brief Clean up and close all logging resources.
 */
void logger_cleanup(void)
{
	char timestamp[MIN_TIMESTAMP_BUFFER_SIZE] = { 0 };

	get_timestamp(timestamp, sizeof(timestamp));

	if (log_file) {
		FPRINTF(log_file,
			"[%s] [CLI] [INFO] ===== End logging session =====\n\n",
			timestamp);
		FCLOSE(log_file);
		log_file = NULL;
	}
	log_enabled = false;
	log_dest = LOG_DEST_NONE;

	if (env_log_file) {
		FPRINTF(env_log_file,
			"[%s] [CLI] [INFO] ===== End logging session =====\n\n",
			timestamp);
		FCLOSE(env_log_file);
		env_log_file = NULL;
	}
	env_log_enabled = false;
}
