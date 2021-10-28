/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2019-2021 NXP
 */

#ifndef __UTILS_H__
#define __UTILS_H__

#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <time.h>

#include "global.h"

#define SMW_ALL_ONES (-1)

#define BIT_MASK(length) ((1ULL << (length)) - 1)

#if !defined ARRAY_SIZE
#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))
#endif

#define BITS_TO_BYTES_SIZE(security_size) (((security_size) + 7) / 8)

#define SET_CLEAR_MASK(val, set, clear) (((val) & ~(clear)) | (set))

#define SMW_UTILS_MALLOC  malloc
#define SMW_UTILS_CALLOC  calloc
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

static inline void
smw_utils_register_active_subsystem(const char *subsystem_name)
{
	if (g_smw_ctx.ops.register_active_subsystem)
		g_smw_ctx.ops.register_active_subsystem(subsystem_name);
}

static inline unsigned long smw_utils_time(unsigned long ref)
{
	time_t t = time(NULL);

	if (t)
		return (unsigned long)difftime(t, ref);

	return 0;
}

#endif /* __UTILS_H__ */
