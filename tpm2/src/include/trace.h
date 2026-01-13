/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2026 NXP
 */
#ifndef __TRACE_H__
#define __TRACE_H__

#ifdef ENABLE_DEBUG
#include <stdint.h>

#include "compiler.h"

/**
 * trace_print() - debug trace function.
 * @function:   Function name to trace
 * @line:       Line number in the function
 * @format:     String format of the debug trace
 * @...:        List of parameters
 */
void trace_print(const char *function, int line, const char *format, ...)
	__format_printf(3, 4);

/**
 * print_buffer_hex() - print buffer in hexadecimal format
 * @buf:        Buffer to print
 * @len:        Length of buffer
 */
void print_buffer_hex(const uint8_t *buf, size_t len);

#define DBG_TRACE(...) trace_print(__func__, __LINE__, __VA_ARGS__)
#define DBG_TRACE_COND(cond, ...)                                              \
	do {                                                                   \
		if (cond)                                                      \
			DBG_TRACE(__VA_ARGS__);                                \
	} while (0)
#define DBG_BUF_HEX(buf, len) print_buffer_hex(buf, len)
#else
#define DBG_TRACE(...)
#define DBG_TRACE_COND(cond, ...)
#define DBG_BUF_HEX(buf, len)
#endif

#endif /* __TRACE_H__ */
