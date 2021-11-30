/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021 NXP
 */

#ifndef __LOCAL_H__
#define __LOCAL_H__

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include "compiler.h"
#include "osal.h"

/* Debug levels */
#define DBG_LEVEL_NONE	  0 /* No trace */
#define DBG_LEVEL_ERROR	  1 /* Failures of which the user must be aware */
#define DBG_LEVEL_INFO	  2 /* Traces which could interest the user */
#define DBG_LEVEL_DEBUG	  3 /* First level of debugging information */
#define DBG_LEVEL_VERBOSE 4 /* Maximum level of debugging information */

#if defined(ENABLE_TRACE)

#define DBG_LEVEL TRACE_LEVEL

#define DBG_PRINTF(level, ...)                                                 \
	do {                                                                   \
		if (DBG_LEVEL_##level <= DBG_LEVEL) {                          \
			printf("(%lx) ", pthread_self());                      \
			printf(__VA_ARGS__);                                   \
		}                                                              \
	} while (0)

#define TRACE_FUNCTION_CALL DBG_PRINTF(VERBOSE, "Executing %s\n", __func__)

#else
#define DBG_PRINTF(level, ...)
#define TRACE_FUNCTION_CALL
#endif /* ENABLE_TRACE */

extern const char *active_subsystem_name;

#endif /* __LOCAL_H__ */
