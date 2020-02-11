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
 * @thread_self: [optional] Returns the ID of the thread being executed
 *
 * This structure defines the SMW OSAL.
 * Functions pointers marked as [mandatory] must be assigned.
 * Functions pointers marked as [optional] may not be assigned.
 * critical_* functions pointers are optional together.
 */
struct smw_ops {
	void (*critical_section_start)(void);
	void (*critical_section_stop)(void);

	unsigned long (*thread_self)(void);
};

/**
 * smw_start() - Start the SMW library.
 * @ops: pointer the structure describing the OSAL.
 * @dbg_lvl: debug level of the SMW library.
 *
 * This function starts the Security Middleware.
 * It verifies that ops is valid and
 * then initializes SMW.
 *
 * Return:
 * error code.
 */
int smw_start(const struct smw_ops *ops, unsigned char dbg_lvl);

/**
 * smw_stop() - Stop the SMW library.
 *
 * This function stops the Security Middleware.
 * It frees all memory dynamically allocated by SMW.
 *
 * Return:
 * error code.
 */
int smw_stop(void);

#endif /* SMW_OSAL_H */
