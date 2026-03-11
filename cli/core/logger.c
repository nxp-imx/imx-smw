// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */
#define _TIME_BITS		  64
#define _FILE_OFFSET_BITS	  64
#define MIN_TIMESTAMP_BUFFER_SIZE 32

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include "helper.h"
#include "logger.h"

/* Log levels */
enum log_level { LOG_LEVEL_ERROR, LOG_LEVEL_INFO };

/* User-specified logging (via -L option) */
static enum log_dest log_dest = LOG_DEST_NONE;
static FILE *log_file;
static bool log_enabled;

/* Automatic logging (via SMW_LOG_FILE environment variable) */
static FILE *env_log_file;
static bool env_log_enabled;

/**
 * @brief Get log level string
 *
 * @param level of the log (ERROR or INFO)
 */
static const char *log_level_string(enum log_level level)
{
	switch (level) {
	case LOG_LEVEL_ERROR:
		return "[ERROR]";
	case LOG_LEVEL_INFO:
		return "[CLI]";
	default:
		return "[UNKNOWN]";
	}
}

/**
 * @brief Gets current timestamp as formatted string.
 *
 * @param buffer: Destination buffer for timestamp string
 * @param size: Size of destination buffer in bytes
 */
static void logger_get_timestamp(char *buffer, size_t size)
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
 * @brief Internal logging function
 *
 * Writes log messages to both environment-based and user-specified log destinations.
 * Handles dual logging output with timestamps and log level prefixes.
 *
 * @param level The log level for the message (ERROR, INFO, etc.)
 * @param fmt Format string for the message (printf-style)
 * @param args Variable argument list containing format arguments
 */
static void logger_log_message_va(enum log_level level, const char *fmt,
				  va_list args)
{
	va_list args_copy;
	char timestamp[MIN_TIMESTAMP_BUFFER_SIZE] = { 0 };
	const char *level_str = log_level_string(level);

	/* Environment variable logging */
	if (env_log_enabled && env_log_file) {
		logger_get_timestamp(timestamp, sizeof(timestamp));
		FPRINTF(env_log_file, "[%s] %s ", timestamp, level_str);
		va_copy(args_copy, args);
		VFPRINTF(env_log_file, fmt, args_copy);
		va_end(args_copy);
		FPRINTF(env_log_file, "\n");
		FFLUSH(env_log_file);
	}

	/* User-specified logging (-L option) */
	if (log_enabled) {
		if (log_dest == LOG_DEST_FILE && log_file) {
			logger_get_timestamp(timestamp, sizeof(timestamp));
			FPRINTF(log_file, "[%s] %s ", timestamp, level_str);
			va_copy(args_copy, args);
			VFPRINTF(log_file, fmt, args_copy);
			va_end(args_copy);
			FPRINTF(log_file, "\n");
			FFLUSH(log_file);
		} else if (log_dest == LOG_DEST_STDERR) {
			FPRINTF(stderr, "%s ", level_str);
			va_copy(args_copy, args);
			VFPRINTF(stderr, fmt, args_copy);
			va_end(args_copy);
			FPRINTF(stderr, "\n");
		}
	}
}

/**
 * @brief Log error message
 *
 * @param fmt Format string for the error message (printf-style)
 * @param ... Variable arguments for format string
 */
void logger_log_error(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	logger_log_message_va(LOG_LEVEL_ERROR, fmt, args);
	va_end(args);

	/* Also print to stderr (unless already logging to stderr) */
	if (!log_enabled || log_dest != LOG_DEST_STDERR) {
		va_start(args, fmt);
		FPRINTF(stderr, "Error: ");
		VFPRINTF(stderr, fmt, args);
		FPRINTF(stderr, "\n");
		va_end(args);
	}
}

/**
 * @brief Log info message
 *
 * @param fmt Format string for the info message (printf-style)
 * @param ... Variable arguments for format string
 */
void logger_log_info(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	logger_log_message_va(LOG_LEVEL_INFO, fmt, args);
	va_end(args);
}

/**
 * @brief Initializes the logging subsystem.
 *
 * @param dest: User-specified log destination (LOG_DEST_NONE/STDERR/FILE)
 * @param log_file: Log file path (required if dest is LOG_DEST_FILE)
 */
void logger_init(enum log_dest dest, const char *log_filename)
{
	const char *log_path = NULL;
	char timestamp[MIN_TIMESTAMP_BUFFER_SIZE] = { 0 };

	/* Determine automatic log file path */
	const char *env_log_path = getenv(SMW_LOG_ENV_VAR);

	if (env_log_path) {
		/* Environment variable is set */
		if (!strlen(env_log_path) ||
		    !strcasecmp(env_log_path, "none") ||
		    !strcasecmp(env_log_path, "off")) {
			/* User explicitly disabled automatic logging */
			log_path = NULL;
		} else {
			/* Use custom path from environment */
			log_path = env_log_path;
		}
	} else {
		/* No environment variable - use default location (current directory) */
		log_path = SMW_DEFAULT_LOG_FILE;
	}

	/* Open automatic log file if path is set */
	if (log_path) {
		env_log_file = fopen(log_path, "a");
		if (env_log_file) {
			env_log_enabled = true;

			logger_get_timestamp(timestamp, sizeof(timestamp));
			FPRINTF(env_log_file,
				"\n[%s] [CLI] ========== New logging session ==========\n",
				timestamp);
			FFLUSH(env_log_file);
		} else {
			FPRINTF(stderr,
				"Warning: Automatic logging disabled - cannot open SMW_LOG_FILE='%s': %s\n",
				log_path, strerror(errno));
			env_log_enabled = false;
		}
	}

	/* Only enable logging if user specified a destination */
	if (dest == LOG_DEST_NONE) {
		log_enabled = false;
		return;
	}

	log_enabled = true;
	log_dest = dest;

	/* If destination is file, open it */
	if (dest == LOG_DEST_FILE) {
		if (!log_filename || !strlen(log_filename)) {
			FPRINTF(stderr,
				"Error: Log file destination specified but no filename provided\n");
			log_enabled = false;
			return;
		}

		log_file = fopen(log_filename, "a");
		if (!log_file) {
			FPRINTF(stderr, "Error: Failed to open log file: %s\n",
				log_filename);
			log_enabled = false;
			return;
		}

		/* Log session start */
		char timestamp[32] = { 0 };

		logger_get_timestamp(timestamp, sizeof(timestamp));
		FPRINTF(log_file,
			"\n[%s] [CLI] ========== New logging session ==========\n",
			timestamp);
		FFLUSH(log_file);
	}
}

/**
 * @brief cleans up and closes all logging resources
 */
void logger_cleanup(void)
{
	char timestamp[MIN_TIMESTAMP_BUFFER_SIZE] = { 0 };

	if (log_file) {
		logger_get_timestamp(timestamp, sizeof(timestamp));
		FPRINTF(log_file,
			"[%s] [CLI] ========== End logging session ==========\n\n",
			timestamp);

		FCLOSE(log_file);
		log_file = NULL;
	}
	log_enabled = false;
	log_dest = LOG_DEST_NONE;

	/* Cleanup environment variable log file */
	if (env_log_file) {
		logger_get_timestamp(timestamp, sizeof(timestamp));
		FPRINTF(env_log_file,
			"[%s] [CLI] ========== End logging session ==========\n\n",
			timestamp);

		FCLOSE(env_log_file);
		env_log_file = NULL;
	}
	env_log_enabled = false;
}
