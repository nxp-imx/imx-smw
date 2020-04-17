/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020 NXP
 */
#ifndef __TRACE_H__
#define __TRACE_H__

#ifdef ENABLE_DEBUG

/**
 * trace_print() - debug trace function.
 * @function:   Function name to trace
 * @line:       Line number in the function
 * @format:     String format of the debug trace
 * @...:        List of parameters
 */
void trace_print(const char *function, int line, const char *format, ...)
	__attribute__((__format__(__printf__, 3, 4)));

#define DBG_TRACE(...) trace_print(__func__, __LINE__, __VA_ARGS__)
#else
#define DBG_TRACE(...)
#endif

#endif /* __TRACE_H__ */
