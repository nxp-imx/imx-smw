/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021-2024 NXP
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
#include "smw/attr.h"
#include "smw/names.h"

#include "builtin_macros.h"
#include "compiler.h"
#include "osal.h"

/* Debug levels */
#define DBG_LEVEL_NONE	  0 /* No trace */
#define DBG_LEVEL_ERROR	  1 /* Failures of which the user must be aware */
#define DBG_LEVEL_INFO	  2 /* Traces which could interest the user */
#define DBG_LEVEL_DEBUG	  3 /* First level of debugging information */
#define DBG_LEVEL_VERBOSE 4 /* Second level of debugging information */
#define DBG_LEVEL_EXTRA	  5 /* Maximum level of debugging information */

#if defined(ENABLE_TRACE)

#define DBG_LEVEL TRACE_LEVEL

#define DBG_PRINTF(level, ...)                                                 \
	do {                                                                   \
		if (DBG_LEVEL_##level <= DBG_LEVEL) {                          \
			printf("[OSAL] (%d) [0x%lx] ", getpid(),               \
			       pthread_self());                                \
			printf(__VA_ARGS__);                                   \
		}                                                              \
	} while (0)

#define DBG_PRINTF_COND(level, cond, ...)                                      \
	do {                                                                   \
		if (cond)                                                      \
			DBG_PRINTF(level, __VA_ARGS__);                        \
	} while (0)

#define TRACE_FUNCTION_CALL DBG_PRINTF(VERBOSE, "Executing %s\n", __func__)

#define TRACE_EXTRA_FUNCTION_CALL DBG_PRINTF(EXTRA, "Executing %s\n", __func__)

#else
#define DBG_PRINTF(level, ...)
#define DBG_PRINTF_COND(...)
#define TRACE_FUNCTION_CALL
#define TRACE_EXTRA_FUNCTION_CALL
#endif /* ENABLE_TRACE */

/*
 * Define the configuration flags ids
 */
#define CONFIG_SMW_CONFIG_FILE BIT(0)
#define CONFIG_SMW_DATABASE    BIT(1)
#define CONFIG_TEE	       BIT(2)
#define CONFIG_SECO	       BIT(3)
#define CONFIG_ELE	       BIT(4)

/**
 * struct smw_info - SMW library configuration
 * @smw_config_file: SMW configuration file
 * @smw_database: SMW database file
 */
struct smw_info {
	char *smw_config_file;
	char *smw_database;
};

/**
 * struct lib_config_args - Library configuration arguments
 * @config_flags: Flags the library configuration set
 * @smw_info: SMW library configuration
 * @tee_info: TEE subsystem configuration
 * @se_seco_info: Secure Enclave SECO subsystem configuration
 * @se_ele_info: Secure Enclave ELE subsystem configuration
 */
struct lib_config_args {
	unsigned int config_flags;
	struct smw_info smw_info;
	struct tee_info tee_info;
	struct se_info se_seco_info;
	struct se_info se_ele_info;
};

struct osal_ctx {
	int lib_initialized;
	struct lib_config_args config;
	smw_subsystem_t active_subsystem_name;
	void *obj_db;
};

/**
 * get_osal_ctx() - Get the OSAL context
 *
 * Return:
 * Pointer to the OSAL context
 */
struct osal_ctx *get_osal_ctx(void);

/**
 * mutex_init() - Create and initialize a mutex
 * @mutex: Mutex object created
 *
 * Return:
 * 0 if success, -1 otherwise
 */
int mutex_init(void **mutex);

/**
 * mutex_destroy() - Destroy and free a mutex
 * @mutex: Mutex object to destroy
 *
 * Function set the @mutex to NULL when freed.
 *
 * Return:
 * 0 if success, -1 otherwise
 */
int mutex_destroy(void **mutex);

/**
 * @mutex_lock() - Lock a mutex
 * @mutex: Mutex to lock
 *
 * Return:
 * 0 if success, -1 otherwise
 */
int mutex_lock(void *mutex);

/**
 * @mutex_unlock() - Unlock a mutex
 * @mutex: Mutex to unlock
 *
 * Return:
 * 0 if success, -1 otherwise
 */
int mutex_unlock(void *mutex);

/**
 * obj_db_open() - Open object database
 * @db: Database file name
 *
 * Return:
 * 0 if success, -1 otherwise
 */
int obj_db_open(const char *db);

/**
 * obj_db_close() - Close object database
 */
void obj_db_close(void);

/**
 * obj_db_get_info() - Get an object information from DB
 * @obj: OSAL object
 *
 * Return:
 * 0 if success, -1 otherwise
 */
int obj_db_get_info(struct osal_obj *obj);

/**
 * obj_db_add() - Add an object in the DB
 * @obj: OSAL object
 *
 * Return:
 * 0 if success, -1 otherwise
 */
int obj_db_add(struct osal_obj *obj);

/**
 * obj_db_update() - Update an object information into the DB
 * @obj: OSAL object
 *
 * Return:
 * 0 if success, -1 otherwise
 */
int obj_db_update(struct osal_obj *obj);

/**
 * obj_db_delete() - Remove an object from the DB
 * @obj: OSAL object
 *
 * Return:
 * 0 if success, -1 otherwise
 */
int obj_db_delete(struct osal_obj *obj);

/**
 * obj_db_find_init() - Init find object
 * @ctx: A pointer to the find context pointer
 * @obj: OSAL object
 *
 * Return:
 * 0 if success, -1 otherwise
 */
int obj_db_find_init(void **ctx, struct osal_obj *obj);

/**
 * obj_db_find_next() - Get next find object
 * @ctx: The find context pointer
 * @obj: OSAL object
 *
 * Return:
 * 0 if success, -1 otherwise
 */
int obj_db_find_next(void *ctx, struct osal_obj *obj);

/**
 * obj_db_find_finalize() - Release the find context
 * @ctx: The find context pointer
 *
 * Return:
 * 0 if success, -1 otherwise
 */
int obj_db_find_finalize(void *ctx);

/**
 * get_strerr() - Return the system error message
 *
 * Return:
 * Pointer to the system message error if supported.
 * Else pointer to default "Unknown error" string.
 */
char *get_strerr(void);

/**
 * config_read_system_cnf() - Read the system configuration file
 *
 * If present, the function reads the system configuration file containing
 * all the library information like:
 *   - SMW_CONFIG_FILE
 *   - object database
 *   - each subsystem configuration
 *
 * Return:
 * SMW_STATUS_OK                 - Success
 * SMW_STATUS_READ_CONF_FAILURE  - Failure
 */
int config_read_system_cnf(void);

/**
 * config_smw_db() - Setup the database file name in the OSAL configuration
 * @file: File name of the database
 * @config: OSAL configuration
 *
 * Return:
 * 0  - Success
 * -1 - Failure
 */
int config_smw_db(const char *file, struct lib_config_args *config);

#endif /* __LOCAL_H__ */
