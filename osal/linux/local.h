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
			printf("(%d) [0x%lx] ", getpid(), pthread_self());     \
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
	void *key_db_obj;
};

enum key_flags {
	ENTRY_FREE = 0,
	ENTRY_USE,
};

/**
 * struct key_entry - Key entry header in key database
 * @id: 16 bits key id in the DB
 * @flags: Flags state of the entry
 * @persistent: Key is persistent
 * @info_size: Key information block size
 *
 * The key database is a binary file build with
 * ----------------------
 * | Key header         |
 * | (struct key_entry) |
 * ----------------------
 * |                    |
 * | Key information of |
 * | info_size bytes    |
 * |                    |
 * ----------------------
 */
struct key_entry {
	unsigned int id;
	enum key_flags flags;
	int persitent;
	size_t info_size;
	/* Info data block is right after the key entry header */
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
 * key_db_open() - Open Key database
 * @key_db: Database file name
 *
 * Return:
 * 0 if success, -1 otherwise
 */
int key_db_open(const char *key_db);

/**
 * key_db_close() - Close Key database
 */
void key_db_close(void);

/**
 * key_db_get_info() - Get a key information from DB
 * @key: OSAL key object
 *
 * Return:
 * 0 if success, -1 otherwise
 */
int key_db_get_info(struct osal_key *key);

/**
 * key_db_add() - Add a key in the DB
 * @key: OSAL key object
 *
 * Return:
 * 0 if success, -1 otherwise
 */
int key_db_add(struct osal_key *key);

/**
 * key_db_update() - Update a key information into the DB
 * @key: OSAL key object
 *
 * Return:
 * 0 if success, -1 otherwise
 */
int key_db_update(struct osal_key *key);

/**
 * key_db_delete() - Remove a key from the DB
 * @key: OSAL key object
 *
 * Return:
 * 0 if success, -1 otherwise
 */
int key_db_delete(struct osal_key *key);

/**
 * get_strerr() - Return the system error message
 *
 * Return:
 * Pointer to the system message error if supported.
 * Else pointer to default "Unknown error" string.
 */
char *get_strerr(void);

/**
 * dbg_entry() - Debug print the key database entry object
 * @entry: Key entry object
 */
void dbg_entry(struct key_entry *entry);

/**
 * dbg_entry_info() - Debug print the key database data
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
