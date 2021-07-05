/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021 NXP
 */

#ifndef __RNG_H__
#define __RNG_H__

/**
 * rng() - Do a RNG operation.
 * @params: RNG parameters.
 * @common_params: Common commands parameters.
 * @ret_status: Status returned by SMW API.
 *
 * Return:
 * PASSED			- Success.
 * -INTERNAL_OUT_OF_MEMORY	- Memory allocation failed.
 * -BAD_RESULT			- SMW API status differs from expected one.
 * -BAD_ARGS			- One of the arguments is bad.
 * -SUBSYSTEM			- RNG operation failed.
 * -BAD_PARAM_TYPE		- A parameter value is undefined.
 * Error code from util_read_hex_buffer().
 * Error code from set_rng_bad_args().
 */
int rng(json_object *params, struct common_parameters *common_params,
	enum smw_status_code *ret_status);

#endif /* __RNG_H__ */
