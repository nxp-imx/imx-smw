/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2019-2020 NXP
 */

#ifndef __UTILS_H__
#define __UTILS_H__

#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>

#include "global.h"

#define SMW_ALL_ONES (-1)

#define BIT_MASK(length) ((1ULL << (length)) - 1)

#if !defined ARRAY_SIZE
#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))
#endif

#define SMW_UTILS_MALLOC  malloc
#define SMW_UTILS_FREE	  free
#define SMW_UTILS_MEMCPY  memcpy
#define SMW_UTILS_STRLEN  strlen
#define SMW_UTILS_STRCMP  strcmp
#define SMW_UTILS_STRNCMP strncmp

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

static inline int smw_utils_mutex_init(void **mutex)
{
	int err = 0;

	SMW_DBG_ASSERT(mutex);
	if (g_smw_ctx.ops.mutex_init)
		err = g_smw_ctx.ops.mutex_init(mutex);

	return err;
}

static inline int smw_utils_mutex_destroy(void **mutex)
{
	int err = 0;

	SMW_DBG_ASSERT(mutex);
	if (g_smw_ctx.ops.mutex_destroy)
		err = g_smw_ctx.ops.mutex_destroy(mutex);

	return err;
}

static inline void smw_utils_mutex_lock(void *mutex)
{
	if (g_smw_ctx.ops.mutex_lock)
		SMW_DBG_ASSERT(!g_smw_ctx.ops.mutex_lock(mutex));
}

static inline void smw_utils_mutex_unlock(void *mutex)
{
	if (g_smw_ctx.ops.mutex_unlock)
		SMW_DBG_ASSERT(!g_smw_ctx.ops.mutex_unlock(mutex));
}

static inline int smw_utils_thread_create(unsigned long *thread,
					  void *(*start_routine)(void *arg),
					  void *arg)
{
	int err = 0;

	if (g_smw_ctx.ops.thread_create)
		err = g_smw_ctx.ops.thread_create(thread, start_routine, arg);

	return err;
}

static inline int smw_utils_thread_cancel(unsigned long thread)
{
	int err = 0;

	if (g_smw_ctx.ops.thread_cancel)
		err = g_smw_ctx.ops.thread_cancel(thread);

	return err;
}

#endif /* __UTILS_H__ */
