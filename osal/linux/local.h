/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021-2022 NXP
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

#include "smw_osal.h"

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

#ifndef BIT
#define BIT(bit) (1 << (bit))
#endif /* BIT */

/*
 * Define the configuration flags ids
 */
#define CONFIG_TEE BIT(0)
#define CONFIG_SE  BIT(1)

/**
 * struct lib_config_args - Library configuration arguments
 * @config_flags: Flags the library configuration set
 * @tee_info: TEE subsystem configuration
 * @se_info: Secure Enclave subsystem configuration
 */
struct lib_config_args {
	unsigned int config_flags;
	struct tee_info tee_info;
	struct se_info se_info;
};

struct osal_priv {
	int lib_initialized;
	struct lib_config_args config;
	const char *active_subsystem_name;
};

extern struct osal_priv osal_priv;

#endif /* __LOCAL_H__ */
