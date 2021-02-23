/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2021 NXP
 */

#ifndef TEE_H
#define TEE_H

#include "tee_subsystem.h"

/**
 * tee_convert_key_type() - Convert SMW key type to TEE key type.
 * @smw_key_type: SMW key type.
 * @tee_key_type: TEE key type. Not updated if conversion can't be done.
 *
 * Return:
 * SMW_STATUS_OK			- Success.
 * SMW_STATUS_OPERATION_NOT_SUPPORTED	- Invalid key type.
 */
int tee_convert_key_type(enum smw_config_key_type_id smw_key_type,
			 enum tee_key_type *tee_key_type);

/**
 * tee_convert_hash_algorithm_id() - Convert SMW algorithm to TEE algorithm.
 * @smw_id: Hash algorithm ID as defined in SMW.
 * @tee_id: Hash algorithm ID as defined in TEE subsystem.
 *
 * Return:
 * SMW_STATUS_OK			- Success.
 * SMW_STATUS_OPERATION_NOT_SUPPORTED	- Invalid key type.
 */
int tee_convert_hash_algorithm_id(enum smw_config_hash_algo_id smw_id,
				  enum tee_algorithm_id *tee_id);

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

/**
 * tee_hash_handle() - Handle the hash operations.
 * @operation_id: Security Operation ID.
 * @args: Pointer to a structure of arguments defined by the internal API.
 * @status: Error code set only if the Security Operation is handled.
 *
 * Return:
 * true		- the Security Operation has been handled.
 * false	- the Security Operation has not been handled.
 */
bool tee_hash_handle(enum operation_id operation_id, void *args, int *status);

/**
 * tee_sign_verify_handle() - Handle the sign and verify operations.
 * @operation_id: Security Operation ID.
 * @args: Pointer to a structure of arguments defined by the internal API.
 * @status: Error code set only if the Security Operation is handled.
 *
 * Return:
 * true		- the Security Operation has been handled.
 * false	- the Security Operation has not been handled.
 */
bool tee_sign_verify_handle(enum operation_id operation_id, void *args,
			    int *status);

#endif /* TEE_H */
