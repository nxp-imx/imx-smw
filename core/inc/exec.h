/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2021 NXP
 */

enum smw_op_step {
	SMW_OP_STEP_INIT,
	SMW_OP_STEP_UPDATE,
	SMW_OP_STEP_FINAL,
	SMW_OP_STEP_ONESHOT
};

/**
 * smw_utils_execute_operation() - Execute a Security Operation.
 * @operation_id: Security Operation ID.
 * @args: Pointer to a structure of arguments defined by the internal API.
 * @subsystem_id: Secure Subsystem ID.
 *
 * This function calls the API of a Secure Subsytem to perform
 * the required Security Operation.
 * The Secure Subsystem is either an argument or the default Secure Subsystem
 * configured for this Security Operation.
 *
 * Return:
 * error code.
 */
int smw_utils_execute_operation(enum operation_id operation_id, void *args,
				enum subsystem_id subsystem_id);

/**
 * smw_utils_execute_init() - Initialize a Security Operation.
 * @operation_id: Security Operation ID.
 * @args: Pointer to a structure of arguments defined by the internal API.
 * @subsystem_id: Secure Subsystem ID.
 *
 * This function calls the API of a Secure Subsytem to perform
 * the required initialization Security Operation.
 * The Secure Subsystem is either an argument or the default Secure Subsystem
 * configured for this Security Operation.
 *
 * Return:
 * error code.
 */
int smw_utils_execute_init(enum operation_id operation_id, void *args,
			   enum subsystem_id subsystem_id);

/**
 * smw_utils_execute_update() - Update a Security Operation.
 * @operation_id: Security Operation ID.
 * @args: Pointer to a structure of arguments defined by the internal API.
 * @subsystem_id: Secure Subsystem ID.
 *
 * This function calls the API of a Secure Subsytem to perform
 * the required update Security Operation.
 * The Secure Subsystem is either an argument or the default Secure Subsystem
 * configured for this Security Operation.
 *
 * Return:
 * error code.
 */
int smw_utils_execute_update(enum operation_id operation_id, void *args,
			     enum subsystem_id subsystem_id);

/**
 * smw_utils_execute_final() - Finalize a Security Operation.
 * @operation_id: Security Operation ID.
 * @args: Pointer to a structure of arguments defined by the internal API.
 * @subsystem_id: Secure Subsystem ID.
 *
 * This function calls the API of a Secure Subsytem to perform
 * the required final Security Operation.
 * The Secure Subsystem is either an argument or the default Secure Subsystem
 * configured for this Security Operation.
 *
 * Return:
 * error code.
 */
int smw_utils_execute_final(enum operation_id operation_id, void *args,
			    enum subsystem_id subsystem_id);
