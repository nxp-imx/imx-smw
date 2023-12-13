/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2024 NXP
 */

#ifndef __LOCAL_H__
#define __LOCAL_H__

#include "common.h"

/**
 * ele_device_attest_handle() - Handle the device attestation operations.
 * @ele_ctx: Pointer to the ELE subsystem context structure.
 * @operation_id: Security Operation ID.
 * @args: Pointer to a structure of arguments defined by the internal API.
 * @status: Error code set only if the Security Operation is handled.
 *
 * This function handles the device attestation  operations.
 * @status is set only if the function returns true.
 *
 * Return:
 * * true:	- the Security Operation has been handled.
 * * false:	- the Security Operation has not been handled.
 */
bool ele_device_attest_handle(struct subsystem_context *ele_ctx,
			      enum operation_id operation_id, void *args,
			      int *status);

/**
 * ele_device_lifecycle_handle() - Handle the device lifecycle operations.
 * @ele_ctx: Pointer to the ELE subsystem context structure.
 * @operation_id: Security Operation ID.
 * @args: Pointer to a structure of arguments defined by the internal API.
 * @status: Error code set only if the Security Operation is handled.
 *
 * This function handles the device lifecycle management operations.
 * @status is set only if the function returns true.
 *
 * Return:
 * * true:	- the Security Operation has been handled.
 * * false:	- the Security Operation has not been handled.
 */
bool ele_device_lifecycle_handle(struct subsystem_context *ele_ctx,
				 enum operation_id operation_id, void *args,
				 int *status);

/**
 * ele_device_reprovisioning_handle() - Handle the device reprovisioning
 *                                      operations.
 * @ele_ctx: Pointer to the ELE subsystem context structure.
 * @operation_id: Security Operation ID.
 * @args: Pointer to a structure of arguments defined by the internal API.
 * @status: Error code set only if the Security Operation is handled.
 *
 * This function handles the device storage reprovisioning operations.
 * @status is set only if the function returns true.
 *
 * Return:
 * * true:	- the Security Operation has been handled.
 * * false:	- the Security Operation has not been handled.
 */
bool ele_device_reprovisioning_handle(struct subsystem_context *ele_ctx,
				      enum operation_id operation_id,
				      void *args, int *status);

/**
 * ele_devmgr_fill_msg_block() - Fill the signed message block
 * @msg: Message block to be filled
 * @cmd: Payload command
 * @payload_length: Length of the signed message payload
 *
 * Fill the signed message block fields that are not fixed.
 */
void ele_devmgr_fill_msg_block(void *msg, unsigned char cmd,
			       unsigned int payload_length);

/**
 * ele_devmgr_get_msg_block_length() - Return the signed message block length
 *
 * Return:
 * Length of signed message block
 */
unsigned int ele_devmgr_get_msg_block_length(void);

#endif /* __LOCAL_H__ */
