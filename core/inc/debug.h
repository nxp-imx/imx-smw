/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2024 NXP
 */

#ifndef __DEBUG_H__
#define __DEBUG_H__

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include "global.h"

/* Debug levels */
#define SMW_DBG_LEVEL_NONE    0 /* No trace */
#define SMW_DBG_LEVEL_ERROR   1 /* Failures of which the user must be aware */
#define SMW_DBG_LEVEL_INFO    2 /* Traces which could interest the user */
#define SMW_DBG_LEVEL_DEBUG   3 /* First level of debugging information */
#define SMW_DBG_LEVEL_VERBOSE 4 /* Second level of debugging information */
#define SMW_DBG_LEVEL_EXTRA   5 /* Maximum level of debugging information  */

#if defined(ENABLE_TRACE)

static inline void dbg_printf(unsigned int level, const char *fmt, ...)
{
	struct smw_ops *ops = get_smw_ops();
	va_list args;

	if (ops && ops->vprint) {
		va_start(args, fmt);

		ops->vprint(level, fmt, args);

		va_end(args);
	}
}

#define SMW_PRINTF(level, ...) dbg_printf(level, __VA_ARGS__)

#define SMW_DBG_TRACE_API_CALL                                                 \
	do {                                                                   \
		SMW_PRINTF(SMW_DBG_LEVEL_VERBOSE, "Executing %s\n", __func__); \
	} while (0)

#define SMW_DBG_TRACE_FUNCTION_CALL                                            \
	do {                                                                   \
		SMW_PRINTF(SMW_DBG_LEVEL_EXTRA, "Executing %s\n", __func__);   \
	} while (0)

#define SMW_DBG_PRINTF(level, ...)                                             \
	do {                                                                   \
		SMW_PRINTF(SMW_DBG_LEVEL_##level, __VA_ARGS__);                \
	} while (0)

#define SMW_DBG_PRINTF_COND(level, cond, ...)                                  \
	do {                                                                   \
		if (cond)                                                      \
			SMW_PRINTF(SMW_DBG_LEVEL_##level, __VA_ARGS__);        \
	} while (0)

static inline void dbg_hex_dump(unsigned int level, const unsigned char *addr,
				unsigned int size, unsigned int align)
{
	struct smw_ops *ops = get_smw_ops();

	if (ops && ops->hex_dump)
		ops->hex_dump(level, addr, size, align);
}

#define SMW_DBG_HEX_DUMP(level, addr, size, align)                             \
	do {                                                                   \
		dbg_hex_dump(SMW_DBG_LEVEL_##level, addr, size, align);        \
	} while (0)

#else /* ENABLE_TRACE */

#define SMW_PRINTF(...)
#define SMW_DBG_TRACE_API_CALL
#define SMW_DBG_TRACE_FUNCTION_CALL
#define SMW_DBG_PRINTF(level, ...)
#define SMW_DBG_PRINTF_COND(level, cond, ...)
#define SMW_DBG_HEX_DUMP(level, addr, size, align)

#endif /* ENABLE_TRACE */

#define SMW_DBG_ASSERT(exp)                                                    \
	do {                                                                   \
		if ((exp))                                                     \
			break;                                                 \
		SMW_PRINTF(SMW_DBG_LEVEL_ERROR,                                \
			   "Assertion \"%s\" failed: file \"%s\","             \
			   "line %d\n",                                        \
			   #exp, __FILE__, __LINE__);                          \
		/* Exit in error properly flushing/closing streams */          \
		exit(EXIT_FAILURE);                                            \
	} while (0)

#endif /* __DEBUG_H__ */
