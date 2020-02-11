// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2019-2020 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include "smw_debug.h"
#include "smw_osal.h"

#include "osal_debug.h"

#define OSAL_DBG_LEVEL_DEFAULT OSAL_DBG_LEVEL_NONE

__attribute__((constructor)) void smw_constructor(void);
__attribute__((destructor)) void smw_destructor(void);

/* OSAL globals */
/**
 * struct osal_ctx - OSAL context
 * @dbg_lvl: Current debug level
 *
 */
static struct osal_ctx {
	unsigned char dbg_lvl;
} g_osal_ctx = {
	.dbg_lvl = 0,
};

static unsigned long osal_thread_self(void)
{
	return (unsigned long)pthread_self();
}

#if defined(ENABLE_DEBUG)
static int osal_printf(const char *fmt, ...)
{
	va_list args;

	printf("(%lx) ", pthread_self());

	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);

	return 0;
}

#define OSAL_PRINTF osal_printf

#define OSAL_DBG_PRINTF(level, ...)                                            \
	do {                                                                   \
		if (OSAL_DBG_LEVEL_##level <= g_osal_ctx.dbg_lvl)              \
			OSAL_PRINTF(__VA_ARGS__);                              \
	} while (0)

#define OSAL_TRACE_FUNCTION_CALL                                               \
	OSAL_DBG_PRINTF(VERBOSE, "Executing %s\n", __func__)

#else
#define OSAL_DBG_PRINTF(level, ...)
#define OSAL_TRACE_FUNCTION_CALL
#endif /* ENABLE_DEBUG */

static int smw_osal_start(unsigned char osal_dbg_lvl, unsigned char smw_dbg_lvl)
{
	int status = 0;

	struct smw_ops ops;

	OSAL_TRACE_FUNCTION_CALL;

	if (g_osal_ctx.dbg_lvl == OSAL_DBG_LEVEL_DEFAULT)
		g_osal_ctx.dbg_lvl = osal_dbg_lvl;

	memset(&ops, 0, sizeof(ops));
	ops.thread_self = osal_thread_self;

	status = smw_start(&ops, smw_dbg_lvl);
	if (status)
		OSAL_DBG_PRINTF(ERROR, "SMW start failure: %d\n", status);

	OSAL_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int smw_osal_stop(void)
{
	int status = 0;

	OSAL_TRACE_FUNCTION_CALL;

	status = smw_stop();
	if (status)
		OSAL_DBG_PRINTF(ERROR, "SMW stop failure: %d\n", status);

	OSAL_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

void smw_constructor(void)
{
	smw_osal_start(OSAL_DBG_LEVEL_VERBOSE, SMW_DBG_LEVEL_VERBOSE);
}

void smw_destructor(void)
{
	smw_osal_stop();
}
