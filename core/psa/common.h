/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2022 NXP
 */

#ifndef __COMMON__H__
#define __COMMON__H__

#include "config.h"

/**
 * call_smw_api() - Call SMW API.
 * @api: SMW API.
 * @args: Arguments of the SMW API.
 * @config: PSA configuration.
 * @subsystem_name: Pointer to the subsystem name in the arguments structure.
 *
 * This function first calls the SMW API with the requested subsystem.
 * If the operation is not supported and the subsystem fallback mechanism is configured,
 * the SMW API is called another time with the default subsystem configured if different
 * from the requested subsystem.
 *
 * Return:
 * See &enum smw_status_code.
 */
enum smw_status_code call_smw_api(enum smw_status_code (*api)(void *a),
				  void *args,
				  struct smw_config_psa_config *config,
				  smw_subsystem_t *subsystem_name);

/**
 * get_subsystem_name() - Get the configured PSA subsystem name.
 * @config: PSA configuration.
 *
 * This function returns the default subsystem to be used for PSA operations
 * if one has been configured, NULL otherwise.
 *
 * Return:
 * See &typedef smw_subsystem_t.
 */
smw_subsystem_t get_subsystem_name(struct smw_config_psa_config *config);

#endif /* __COMMON__H__ */
