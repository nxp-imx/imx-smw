/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2019-2020 NXP
 */

#ifndef SMW_OSAL_H
#define SMW_OSAL_H

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
 * error code.
 */
int smw_init(const struct smw_ops *ops);

/**
 * smw_deinit() - Deinitialize the SMW library.
 *
 * This function deinitializes the Security Middleware.
 * It frees all memory dynamically allocated by SMW.
 *
 * Return:
 * error code.
 */
int smw_deinit(void);

/**
 * smw_config_load() - Load a configuration.
 * @buffer: pointer to the plaintext configuration.
 * @size: size of the plaintext configuration
 *
 * This function loads a configuration.
 * The plaintext configuration is parsed and
 * the content is stored in the Configuration database.
 *
 * Return:
 * error code.
 */
int smw_config_load(char *buffer, unsigned int size);

/**
 * smw_config_unload() - Unload the current configuration.
 *
 * This function unloads the current configuration.
 * It frees all memory dynamically allocated by SMW.
 *
 * Return:
 * none.
 */
void smw_config_unload(void);

#endif /* SMW_OSAL_H */
