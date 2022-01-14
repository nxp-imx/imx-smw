/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021-2022 NXP
 */

#ifndef __OPERATION_CONTEXT_H__
#define __OPERATION_CONTEXT_H__

/**
 * cancel_operation() - Cancel operation
 * @params: Cancel operation parameters.
 * @common_params: Some parameters common to commands.
 * @ctx: Context linked list.
 * @ret_status: Status returned by SMW API.
 *
 * Return:
 * PASSED
 * -BAD_ARGS		- One of the arguments is bad
 * -BAD_PARAM_TYPE	- A parameter value is undefined.
 * -MISSING_PARAMS	- Missing mandatory parameters in @params
 * -BAD_RESULT		- SMW API status differs from expected one
 * -FAILED		- Operation context is not found
 */
int cancel_operation(json_object *params,
		     struct common_parameters *common_params, struct llist *ctx,
		     enum smw_status_code *ret_status);

/**
 * copy_context() - Copy operation context
 * @params: Cancel operation parameters.
 * @common_params: Some parameters common to commands.
 * @app: Application data.
 * @ret_status: Status returned by SMW API.
 *
 * Return:
 * PASSED                  - Success
 * -BAD_ARGS               - One of the arguments is bad
 * -BAD_PARAM_TYPE         - A parameter value is undefined.
 * -MISSING_PARAMS         - Missing mandatory parameters in @params
 * -BAD_RESULT             - SMW API status differs from expected one
 * -FAILED                 - Operation context is not found
 * -INTERNAL_OUT_OF_MEMORY - Memory allocation failed
 * -INTERNAL               - Internal error
 */
int copy_context(json_object *params, struct common_parameters *common_params,
		 struct app_data *app, enum smw_status_code *ret_status);

#endif /* __OPERATION_CONTEXT_H__ */
