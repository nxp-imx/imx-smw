/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2019-2022 NXP
 */

#ifndef __OSAL_H__
#define __OSAL_H__

#include "smw_status.h"

/**
 * struct smw_ops - SMW OSAL
 * @critical_section_start: [optional] Start critical section
 * @critical_section_stop: [optional] Stop critical section
 * @mutex_init: [optional] Initialize a mutex
 * @mutex_destroy: [optional] Destroy a mutex
 * @mutex_lock: [optional] Lock a mutex
 * @mutex_unlock: [optional] Unlock a mutex
 * @thread_create: [mandatory] Create a thread
 * @thread_cancel: [mandatory] Cancel a thread
 * @thread_self: [optional] Return the ID of the thread being executed
 * @register_active_subsystem: [optional] Register the active Secure Subsystem
 * @get_subsystem_info: [mandatory] Get Subsystem configuration info
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

	unsigned long (*thread_self)(void);

	void (*register_active_subsystem)(const char *subsystem_name);

	int (*get_subsystem_info)(const char *subsystem_name, void *info);
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
 * SMW_STATUS_OK			- Initialization is successful
 * SMW_STATUS_OPS_INVALID		- @ops is invalid
 * SMW_STATUS_MUTEX_INIT_FAILURE	- Mutex initialization has failed
 */
enum smw_status_code smw_init(const struct smw_ops *ops);

/**
 * smw_deinit() - Deinitialize the SMW library.
 *
 * This function deinitializes the Security Middleware.
 * It frees all memory dynamically allocated by SMW.
 *
 * Return:
 * SMW_STATUS_OK			- Deinitialization is successful
 * SMW_STATUS_MUTEX_DESTROY_FAILURE	- Mutex destruction has failed
 */
enum smw_status_code smw_deinit(void);

#endif /* __OSAL_H__ */
