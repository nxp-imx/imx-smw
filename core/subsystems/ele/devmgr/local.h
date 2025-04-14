/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2024-2025 NXP
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

#endif /* __LOCAL_H__ */
