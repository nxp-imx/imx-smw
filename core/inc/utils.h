/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2019-2023 NXP
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

#define BIT(n)		 (1 << (n))
#define BIT_MASK(length) ((1ULL << (length)) - 1)

#if !defined ARRAY_SIZE
#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))
#endif

#ifndef MIN
#define MIN(a, b)                                                              \
	({                                                                     \
		__typeof__(a) _a = (a);                                        \
		__typeof__(b) _b = (b);                                        \
		_a < _b ? _a : _b;                                             \
	})
#endif /* MIN */

#define BITS_TO_BYTES_SIZE(security_size) (((security_size) + 7) / 8)

#define SET_CLEAR_MASK(val, set, clear) (((val) & ~(clear)) | (set))

#define SMW_UTILS_MALLOC  malloc
#define SMW_UTILS_CALLOC  calloc
#define SMW_UTILS_FREE	  free
#define SMW_UTILS_MEMCPY  memcpy
#define SMW_UTILS_STRLEN  strlen
#define SMW_UTILS_STRCMP  strcmp
#define SMW_UTILS_STRNCMP strncmp
#define SMW_UTILS_STRTOK  strtok
#define SMW_UTILS_STRTOL  strtol

#define SMW_UTILS_CRITICAL_SECTION_START                                       \
	do {                                                                   \
		struct smw_ops *_ops = get_smw_ops();                          \
		if (_ops && _ops->critical_section_start)                      \
			_ops->critical_section_start();                        \
	} while (0)

#define SMW_UTILS_CRITICAL_SECTION_STOP                                        \
	do {                                                                   \
		struct smw_ops *_ops = get_smw_ops();                          \
		if (_ops && _ops->critical_section_stop)                       \
			_ops->critical_section_stop();                         \
	} while (0)

static inline int smw_utils_mutex_init(void **mutex)
{
	struct smw_ops *ops = get_smw_ops();

	if (!ops)
		return -1;

	if (!ops->mutex_init)
		return -1;

	SMW_DBG_ASSERT(mutex);
	return ops->mutex_init(mutex);
}

static inline int smw_utils_mutex_destroy(void **mutex)
{
	struct smw_ops *ops = get_smw_ops();

	if (!ops)
		return -1;

	if (!ops->mutex_destroy)
		return -1;

	SMW_DBG_ASSERT(mutex);
	return ops->mutex_destroy(mutex);
}

static inline int smw_utils_mutex_lock(void *mutex)
{
	struct smw_ops *ops = get_smw_ops();

	if (!ops)
		return -1;

	if (!ops->mutex_lock)
		return -1;

	SMW_DBG_ASSERT(mutex);
	if (!mutex)
		return -1;

	return ops->mutex_lock(mutex);
}

static inline int smw_utils_mutex_unlock(void *mutex)
{
	struct smw_ops *ops = get_smw_ops();

	if (!ops)
		return -1;

	if (!ops->mutex_unlock)
		return -1;

	SMW_DBG_ASSERT(mutex);
	if (!mutex)
		return -1;

	return ops->mutex_unlock(mutex);
}

static inline int smw_utils_thread_create(unsigned long *thread,
					  void *(*start_routine)(void *arg),
					  void *arg)
{
	int err = -1;

	struct smw_ops *ops = get_smw_ops();

	if (ops && ops->thread_create)
		err = ops->thread_create(thread, start_routine, arg);

	return err;
}

static inline int smw_utils_thread_cancel(unsigned long thread)
{
	int err = -1;

	struct smw_ops *ops = get_smw_ops();

	if (ops && ops->thread_cancel)
		err = ops->thread_cancel(thread);

	return err;
}

static inline void
smw_utils_register_active_subsystem(const char *subsystem_name)
{
	struct smw_ops *ops = get_smw_ops();

	if (ops && ops->register_active_subsystem)
		ops->register_active_subsystem(subsystem_name);
}

static inline int smw_utils_get_subsystem_info(const char *subsystem_name,
					       void *info)
{
	struct smw_ops *ops = get_smw_ops();

	if (!ops)
		return -1;

	return ops->get_subsystem_info(subsystem_name, info);
}

static inline bool smw_utils_is_lib_initialized(void)
{
	bool is_initialized = false;

	struct smw_ops *ops = get_smw_ops();

	if (ops && ops->is_lib_initialized)
		is_initialized = ops->is_lib_initialized();

	return is_initialized;
}

static inline unsigned long smw_utils_time(unsigned long ref)
{
	time_t t = time(NULL);

	if (t)
		return (unsigned long)difftime(t, ref);

	return 0;
}

#endif /* __UTILS_H__ */
