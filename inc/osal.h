/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2019-2022 NXP
 */

#ifndef __OSAL_H__
#define __OSAL_H__

#include <stdbool.h>
#include <stddef.h>
#include <stdarg.h>

#include "smw_status.h"

/**
 * DOC:
 * The OSAL module must refer to the following structures and functions to
 * be linked with the SMW core library.
 * The content and prototype of the structures and functions can't be changed
 * otherwise the core library may not build or work correctly.
 */

/**
 * struct osal_key - OSAL Key database operation parameters
 * @id: Key id output when key added, else input
 * @range: Key id range to generate (information set by SMW at key creation)
 * @range.min: Minimum value
 * @range.max: Maximum value
 * @persistent: Key is persistent (information set by SMW at key creation)
 * @info: Key information to store or restore
 * @info_size: Size of the key information
 *
 * This structure defines the key information to be handled by the OSAL
 * key database if needed.
 *
 * Note: if key range min and max are equal, the key id is not generated
 * by the Key database manager.
 */
struct osal_key {
	unsigned int id;
	struct {
		unsigned int min;
		unsigned int max;
	} range;

	int persistent;
	void *info;
	size_t info_size;
};

/**
 * struct smw_ops - SMW OSAL operations
 * @critical_section_start: [optional] Start critical section
 * @critical_section_stop: [optional] Stop critical section
 * @mutex_init: [mandatory] Initialize a mutex
 * @mutex_destroy: [mandatory] Destroy a mutex
 * @mutex_lock: [mandatory] Lock a mutex
 * @mutex_unlock: [mandatory] Unlock a mutex
 * @thread_create: [mandatory] Create a thread
 * @thread_cancel: [mandatory] Cancel a thread
 * @vprint: [optional] Print debug trace
 * @hex_dump: [optional] Print buffer content
 * @register_active_subsystem: [optional] Register the active Secure Subsystem
 * @get_subsystem_info: [mandatory] Get Subsystem configuration info
 * @is_lib_initialized: [mandatory] Check if the library was successfully initialized by OSAL
 * @get_key_info: [mandatory] Get a key information from database
 * @add_key_info: [mandatory] Add a key information into database
 * @update_key_info: [mandatory] Update a key information into database
 * @delete_key_info: [mandatory] Delete a key information from database
 *
 * This structure defines the SMW OSAL.
 * Functions pointers marked as [mandatory] must be assigned.
 * Functions pointers marked as [optional] may not be assigned.
 * mutex_* functions pointers are optional together.
 * critical_* functions pointers are optional together.
 */
struct smw_ops {
	void (*critical_section_start)(void);
	void (*critical_section_stop)(void);

	int (*mutex_init)(void **mutex);
	int (*mutex_destroy)(void **mutex);
	int (*mutex_lock)(void *mutex);
	int (*mutex_unlock)(void *mutex);

	int (*thread_create)(unsigned long *thread,
			     void *(*start_routine)(void *), void *arg);
	int (*thread_cancel)(unsigned long thread);

	void (*vprint)(const char *format, va_list arg);
	void (*hex_dump)(const unsigned char *addr, unsigned int size,
			 unsigned int align);

	void (*register_active_subsystem)(const char *subsystem_name);

	int (*get_subsystem_info)(const char *subsystem_name, void *info);

	bool (*is_lib_initialized)(void);

	int (*get_key_info)(struct osal_key *key);
	int (*add_key_info)(struct osal_key *key);
	int (*update_key_info)(struct osal_key *key);
	int (*delete_key_info)(struct osal_key *key);
};

/**
 * smw_init() - Initialize the SMW library.
 * @ops: pointer to the structure describing the OSAL.
 *
 * This function initializes the Security Middleware.
 * It verifies that ops is valid and
 * then initializes SMW modules.
 *
 * Return:
 * See &enum smw_status_code
 *  - SMW_STATUS_OK                 - Initialization is successful
 *  - SMW_STATUS_OPS_INVALID        - @ops is invalid
 *  - SMW_STATUS_MUTEX_INIT_FAILURE - Mutex initialization has failed
 */
enum smw_status_code smw_init(const struct smw_ops *ops);

/**
 * smw_deinit() - Deinitialize the SMW library.
 *
 * This function deinitializes the Security Middleware.
 * It frees all memory dynamically allocated by SMW.
 *
 * Return:
 * See &enum smw_status_code
 *  - SMW_STATUS_OK                         - Deinitialization is successful
 *  - SMW_STATUS_INVALID_LIBRARY_CONTEXT    - Library context is not valid
 *  - SMW_STATUS_MUTEX_DESTROY_FAILURE      - Mutex destruction has failed
 */
enum smw_status_code smw_deinit(void);

#endif /* __OSAL_H__ */
