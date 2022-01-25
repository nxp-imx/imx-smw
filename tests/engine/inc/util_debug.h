/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2022 NXP
 */

#ifndef __UTIL_DEBUG_H__
#define __UTIL_DEBUG_H__

/**
 * util_dbg_printf() - Print trace
 * @function: Function caller name
 * @fmt: Print format
 * @...: Optional print argument specified by @fmt
 */
void util_dbg_printf(const char *function, int line, const char *fmt, ...);

/**
 * util_dbg_dumphex() - Dump and hexadecimal buffer
 * @function: Function caller name
 * @line: Line number in the caller source file
 * @msg: Message header to print before dump
 * @buf: Buffer to dump
 * @len: Number of bytes of the buffer
 */
void util_dbg_dumphex(const char *function, int line, char *msg, void *buf,
		      size_t len);

#define DBG_PRINT_ALLOC_FAILURE()                                              \
	util_dbg_printf(__func__, __LINE__, "Memory allocation failed")

#define DBG_PRINT_BAD_ARGS()                                                   \
	util_dbg_printf(__func__, __LINE__, "Bad arguments")

#define DBG_PRINT_BAD_PARAM(param)                                             \
	util_dbg_printf(__func__, __LINE__,                                    \
			"'%s' parameter isn't properly set", param)

#define DBG_PRINT_VALUE_NOTFOUND(param)                                        \
	util_dbg_printf(__func__, __LINE__, "'%s' value not found", param)

#define DBG_PRINT_MISS_PARAM(param)                                            \
	util_dbg_printf(__func__, __LINE__,                                    \
			"'%s' mandatory parameter is missing", param)

#define DBG_PRINT(...) util_dbg_printf(__func__, __LINE__, __VA_ARGS__)

#define DBG_DHEX(msg, buf, len)                                                \
	util_dbg_dumphex(__func__, __LINE__, msg, buf, len)

#endif /* __UTIL_DEBUG_H__ */
