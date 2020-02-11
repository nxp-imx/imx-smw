/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2019-2020 NXP
 */

#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>

#include <smw_osal.h>
#include <smw_debug.h>

extern struct smw_ctx g_smw_ctx;

#define SMW_UTILS_DBG_LEVEL_DEFAULT SMW_DBG_LEVEL_NONE

/* SMW globals */
/**
 * struct smw_ctx - SMW context
 * @ops: Structure containing the OSAL primitives
 * @start_count: Number of threads/applications that started the SMW library
 * @dbg_lvl: Current debug level
 *
 */
struct smw_ctx {
	struct smw_ops ops;
	int start_count;
	unsigned char dgb_lvl;
};

#define SMW_UTILS_PRINTF(...)                                                  \
	do {                                                                   \
		if (g_smw_ctx.ops.thread_self)                                 \
			printf("(%lx) ", g_smw_ctx.ops.thread_self());         \
		printf(__VA_ARGS__);                                           \
	} while (0)

#if defined(ENABLE_DEBUG)
#define SMW_UTILS_TRACE_FUNCTION_CALL                                          \
	do {                                                                   \
		if (g_smw_ctx.dgb_lvl >= SMW_DBG_LEVEL_VERBOSE)                \
			SMW_UTILS_PRINTF("Executing %s\n", __func__);          \
	} while (0)

#define SMW_UTILS_DBG_PRINTF(level, ...)                                       \
	do {                                                                   \
		if (g_smw_ctx.dgb_lvl >= SMW_DBG_LEVEL_##level)                \
			SMW_UTILS_PRINTF(__VA_ARGS__);                         \
	} while (0)

#else
#define SMW_UTILS_TRACE_FUNCTION_CALL
#define SMW_UTILS_DBG_PRINTF(level, ...)
#endif /* ENABLE_DEBUG */

#define SMW_UTILS_CRITICAL_SECTION_START                                       \
	do {                                                                   \
		if (g_smw_ctx.ops.critical_section_start)                      \
			g_smw_ctx.ops.critical_section_start();                \
	} while (0)

#define SMW_UTILS_CRITICAL_SECTION_STOP                                        \
	do {                                                                   \
		if (g_smw_ctx.ops.critical_section_stop)                       \
			g_smw_ctx.ops.critical_section_stop();                 \
	} while (0)
