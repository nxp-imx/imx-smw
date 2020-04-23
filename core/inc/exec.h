/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020 NXP
 */

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
