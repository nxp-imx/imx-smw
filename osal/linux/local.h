/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021-2023 NXP
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

#include "builtin_macros.h"
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
			printf("(%d) [0x%lx] ", getpid(), pthread_self());     \
			printf(__VA_ARGS__);                                   \
		}                                                              \
	} while (0)

#define TRACE_FUNCTION_CALL DBG_PRINTF(VERBOSE, "Executing %s\n", __func__)

#else
#define DBG_PRINTF(level, ...)
#define TRACE_FUNCTION_CALL
#endif /* ENABLE_TRACE */

/*
 * Define the configuration flags ids
 */
#define CONFIG_TEE BIT(0)
#define CONFIG_HSM BIT(1)
#define CONFIG_ELE BIT(2)

/**
 * struct lib_config_args - Library configuration arguments
 * @config_flags: Flags the library configuration set
 * @tee_info: TEE subsystem configuration
 * @se_hsm_info: Secure Enclave HSM subsystem configuration
 * @se_ele_info: Secure Enclave ELE subsystem configuration
 */
struct lib_config_args {
	unsigned int config_flags;
	struct tee_info tee_info;
	struct se_info se_hsm_info;
	struct se_info se_ele_info;
};

struct osal_ctx {
	int lib_initialized;
	struct lib_config_args config;
	const char *active_subsystem_name;
	void *obj_db;
};

enum obj_flags {
	ENTRY_FREE = 0,
	ENTRY_USE,
};

/**
 * struct obj_entry - Object entry header in object database
 * @id: 32 bits object id in the DB
 * @persistence: Object persistence
 * @flags: Flags state of the entry
 * @info_size: Object information block size
 *
 * The object database is a binary file build with
 * -------------------------
 * | Object header         |
 * | (struct obj_entry)    |
 * -------------------------
 * |                       |
 * | Object information of |
 * | info_size bytes       |
 * |                       |
 * -------------------------
 */
struct obj_entry {
	unsigned int id;
	enum obj_flags flags;
	int persistence;
	size_t info_size;
	/* Info data block is right after the object entry header */
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
 * get_strerr() - Return the system error message
 *
 * Return:
 * Pointer to the system message error if supported.
 * Else pointer to default "Unknown error" string.
 */
char *get_strerr(void);

/**
 * dbg_entry() - Debug print the object database entry
 * @entry: Object entry
 */
void dbg_entry(struct obj_entry *entry);

/**
 * dbg_entry_info() - Debug print the object database data
 * @buf: Data buffer
 * @len: Length in bytes of the buffer
 */
void dbg_entry_info(void *buf, size_t len);

/**
 * dbg_get_lock_file - Debug print the lock status of file
 * @fp: File id opened
 */
void dbg_get_lock_file(int fp);

#endif /* __LOCAL_H__ */
