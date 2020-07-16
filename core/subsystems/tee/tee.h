/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020 NXP
 */

#ifndef TEE_H
#define TEE_H

/**
 * execute_tee_cmd() - Invoke a command within the SMW TA session.
 * @cmd_id: ID of the command to execute.
 * @op: Pointer to the operation structure.
 *
 * Return:
 * SMW_STATUS_OK		- Success.
 * SMW_STATUS_SUBSYSTEM_FAILURE - Operation failed.
 */
int execute_tee_cmd(uint32_t cmd_id, TEEC_Operation *op);

/**
 * tee_key_handle() - Handle the key operations.
 * @operation_id: Security Operation ID.
 * @args: Pointer to a structure of arguments defined by the internal API.
 * @status: Error code set only if the Security Operation is handled.
 *
 * Return:
 * true		- the Security Operation has been handled.
 * false	- the Security Operation has not been handled.
 */
bool tee_key_handle(enum operation_id operation_id, void *args, int *status);

#endif /* TEE_H */
