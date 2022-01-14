/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021-2022 NXP
 */

#ifndef __CONFIG_H__
#define __CONFIG_H__

/**
 * config_load() - Call configuration load API.
 * @params: Configuration parameters.
 * @cmn_params: Common commands parameters.
 * @ret_status: Status returned by SMW API.
 *
 * Return:
 * PASSED                   - Success.
 * -INTERNAL_OUT_OF_MEMORY  - Memory allocation failed.
 * -BAD_RESULT              - SMW API status differs from expected one.
 * -BAD_ARGS                - One of the arguments is bad.
 * -BAD_PARAM_TYPE          - A parameter value is undefined.
 * Error code from util_read_hex_buffer().
 */
int config_load(json_object *params, struct cmn_params *cmn_params,
		enum smw_status_code *ret_status);

/**
 * config_unload() - Call configuration unload API.
 * @params: Configuration parameters.
 * @cmn_params: Common commands parameters.
 * @ret_status: Status returned by SMW API.
 *
 * Return:
 * PASSED       - Success.
 * -BAD_RESULT  - SMW API status differs from expected one.
 */
int config_unload(json_object *params, struct cmn_params *cmn_params,
		  enum smw_status_code *ret_status);

#endif /* __CONFIG_H__ */
