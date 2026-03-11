/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2026 NXP
 */

#ifndef CLI_HELPER_H
#define CLI_HELPER_H

#include <stdio.h>
#include <errno.h>
#include <string.h>

/**
 * ARRAY_SIZE - Get the number of elements in an array
 * @arr: Array to get size of
 *
 * Returns: Number of elements (not bytes) in the array
 */
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

/**
 * FCLOSE - Close file and report errors
 * @fp: FILE pointer to close
 *
 * Always checks return value. Reports to stderr on failure.
 */
#define FCLOSE(fp)                                                             \
	do {                                                                   \
		FILE *_tmp_fp = (fp);                                          \
		if (_tmp_fp && fclose(_tmp_fp) != 0) {                         \
			(void)fprintf(stderr,                                  \
				      "Error: fclose failed at %s:%d: %s\n",   \
				      __FILE__, __LINE__, strerror(errno));    \
		}                                                              \
	} while (0)

/**
 * FFLUSH - Flush file and report errors
 * @fp: FILE pointer to flush
 *
 * Always checks return value. Reports to stderr on failure.
 */
#define FFLUSH(fp)                                                             \
	do {                                                                   \
		FILE *_tmp_fp = (fp);                                          \
		if (_tmp_fp && fflush(_tmp_fp) != 0) {                         \
			(void)fprintf(stderr,                                  \
				      "Error: fflush failed at %s:%d: %s\n",   \
				      __FILE__, __LINE__, strerror(errno));    \
		}                                                              \
	} while (0)

/**
 * FPRINTF - fprintf with error checking
 * @stream: FILE stream
 * @...: format string and arguments
 *
 * Checks return value. For stderr failures, attempts stdout.
 */
#define FPRINTF(stream, ...)                                                          \
	do {                                                                          \
		FILE *_tmp_stream = (stream);                                         \
		if (fprintf(_tmp_stream, __VA_ARGS__) < 0) {                          \
			if (_tmp_stream == stderr) {                                  \
				(void)printf(                                         \
					"Error: fprintf to stderr failed at %s:%d\n", \
					__FILE__, __LINE__);                          \
			} else if (_tmp_stream == stdout) {                           \
				(void)fprintf(                                        \
					stderr,                                       \
					"Error: fprintf to stdout failed at %s:%d\n", \
					__FILE__, __LINE__);                          \
			} else {                                                      \
				(void)fprintf(                                        \
					stderr,                                       \
					"Error: fprintf failed at %s:%d: %s\n",       \
					__FILE__, __LINE__, strerror(errno));         \
			}                                                             \
		}                                                                     \
	} while (0)

/**
 * VFPRINTF - vfprintf with mandatory error checking
 * @stream: FILE stream
 * @fmt: format string
 * @args: va_list arguments
 *
 * Checks return value. Reports errors to stderr.
 */
#define VFPRINTF(stream, fmt, args)                                            \
	do {                                                                   \
		FILE *_tmp_stream = (stream);                                  \
		if (vfprintf(_tmp_stream, fmt, args) < 0) {                    \
			(void)fprintf(stderr,                                  \
				      "Error: vfprintf failed at %s:%d: %s\n", \
				      __FILE__, __LINE__, strerror(errno));    \
		}                                                              \
	} while (0)

/**
 * PRINTF - printf with mandatory error checking
 * @...: format string and arguments
 *
 * Checks return value. Reports to stderr on failure.
 */
#define PRINTF(...)                                                            \
	do {                                                                   \
		if (printf(__VA_ARGS__) < 0) {                                 \
			(void)fprintf(stderr,                                  \
				      "Error: printf failed at %s:%d: %s\n",   \
				      __FILE__, __LINE__, strerror(errno));    \
		}                                                              \
	} while (0)

/**
 * FWRITE - fwrite with mandatory error checking
 * @ptr: pointer to data
 * @size: size of each element
 * @nmemb: number of elements
 * @stream: FILE stream
 *
 * Checks return value. Reports to stderr on failure.
 */
#define FWRITE(ptr, size, nmemb, stream)                                       \
	do {                                                                   \
		size_t _tmp_nmemb = (nmemb);                                   \
		FILE *_tmp_stream = (stream);                                  \
		if (fwrite(ptr, size, _tmp_nmemb, _tmp_stream) !=              \
		    _tmp_nmemb) {                                              \
			(void)fprintf(stderr,                                  \
				      "Error: fwrite failed at %s:%d: %s\n",   \
				      __FILE__, __LINE__, strerror(errno));    \
		}                                                              \
	} while (0)

/**
 * SNPRINTF - snprintf with mandatory return value checking
 * @dest: destination buffer
 * @size: size of destination buffer
 * @...: format string and arguments
 *
 * Checks for errors and truncation. Reports to stderr on failure.
 */
#define SNPRINTF(dest, size, ...)                                                     \
	do {                                                                          \
		char *_tmp_dest = (dest);                                             \
		size_t _tmp_size = (size);                                            \
		int _ret = snprintf(_tmp_dest, _tmp_size, __VA_ARGS__);               \
		if (_ret < 0) {                                                       \
			(void)fprintf(stderr,                                         \
				      "Error: snprintf failed at %s:%d\n",            \
				      __FILE__, __LINE__);                            \
			_tmp_dest[0] = '\0';                                          \
		} else if ((size_t)_ret >= _tmp_size) {                               \
			(void)fprintf(                                                \
				stderr,                                               \
				"Error: String truncated at %s:%d (max %zu chars)\n", \
				__FILE__, __LINE__, (size_t)_tmp_size - 1);           \
		}                                                                     \
	} while (0)

#endif /* CLI_HELPER_H */
