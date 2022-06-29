/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2022 NXP
 */

#ifndef __DEBUG_H__
#define __DEBUG_H__

#include <stdio.h>
#include <stdlib.h>

#include "global.h"

/* Debug levels */
#define SMW_DBG_LEVEL_NONE    0 /* No trace */
#define SMW_DBG_LEVEL_ERROR   1 /* Failures of which the user must be aware */
#define SMW_DBG_LEVEL_INFO    2 /* Traces which could interest the user */
#define SMW_DBG_LEVEL_DEBUG   3 /* First level of debugging information */
#define SMW_DBG_LEVEL_VERBOSE 4 /* Maximum level of debugging information */

#if defined(ENABLE_DEBUG)

#define SMW_ABORT abort

#else /* ENABLE_DEBUG */

#define SMW_ABORT(...)

#endif /* ENABLE_DEBUG */

#if defined(ENABLE_TRACE)

#define SMW_DBG_LEVEL TRACE_LEVEL

#define SMW_PRINTF(...)                                                        \
	do {                                                                   \
		if (g_smw_ctx.ops.thread_self)                                 \
			printf("(%lx) ", g_smw_ctx.ops.thread_self());         \
		printf(__VA_ARGS__);                                           \
	} while (0)

#define SMW_DBG_TRACE_FUNCTION_CALL                                            \
	do {                                                                   \
		if (SMW_DBG_LEVEL_VERBOSE <= SMW_DBG_LEVEL)                    \
			SMW_PRINTF("Executing %s\n", __func__);                \
	} while (0)

#define SMW_DBG_PRINTF(level, ...)                                             \
	do {                                                                   \
		if (SMW_DBG_LEVEL_##level <= SMW_DBG_LEVEL)                    \
			SMW_PRINTF(__VA_ARGS__);                               \
	} while (0)

#define SMW_DBG_PRINTF_COND(level, cond, ...)                                  \
	do {                                                                   \
		if (SMW_DBG_LEVEL_##level <= SMW_DBG_LEVEL)                    \
			if (cond)                                              \
				SMW_PRINTF(__VA_ARGS__);                       \
	} while (0)

#define SMW_DBG_HEX_DUMP(level, addr, size, align)                             \
	do {                                                                   \
		if (SMW_DBG_LEVEL_##level > SMW_DBG_LEVEL)                     \
			break;                                                 \
		__typeof__(size) i;                                            \
		const unsigned char *_addr = addr;                             \
		__typeof__(size) _size = (size);                               \
		__typeof__(align) _align = (align);                            \
		_size--;                                                       \
		if (_align > 4)                                                \
			_align = 4;                                            \
		if (_align)                                                    \
			_align = 1 << _align;                                  \
		if (g_smw_ctx.ops.thread_self)                                 \
			printf("(%lx)\n", g_smw_ctx.ops.thread_self());        \
		if (!_addr) {                                                  \
			printf("buffer address is NULL");                      \
			break;                                                 \
		}                                                              \
		for (i = 0; i < _size; i++) {                                  \
			printf("%.2x%s", (_addr)[i],                           \
			       (i + 1) & (_align - 1) ? " " : "\n");           \
		}                                                              \
		printf("%.2x\n", (_addr)[_size]);                              \
	} while (0)

#else /* ENABLE_TRACE */

#define SMW_PRINTF(...)
#define SMW_DBG_TRACE_FUNCTION_CALL
#define SMW_DBG_PRINTF(level, ...)
#define SMW_DBG_PRINTF_COND(level, cond, ...)
#define SMW_DBG_HEX_DUMP(level, addr, size, align)

#endif /* ENABLE_TRACE */

#define SMW_DBG_ASSERT(exp)                                                    \
	do {                                                                   \
		if ((exp))                                                     \
			break;                                                 \
		SMW_PRINTF("Assertion \"%s\" failed: file \"%s\","             \
			   "line %d\n",                                        \
			   #exp, __FILE__, __LINE__);                          \
		SMW_ABORT();                                                   \
	} while (0)

#endif /* __DEBUG_H__ */
