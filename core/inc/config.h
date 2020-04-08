/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020 NXP
 */

#define SMW_CONFIG_MAX_STRING_LENGTH 256

#define SMW_CONFIG_MAX_OPERATION_NAME_LENGTH 16

#define SMW_CONFIG_MAX_SUBSYSTEM_NAME_LENGTH 8

#define SMW_CONFIG_MAX_LOAD_METHOD_NAME_LENGTH 32

/**
 * smw_config_init() - Initialize the Configuration module.
 *
 * This function initializes the Configuration module.
 *
 * Return:
 * error code.
 */
int smw_config_init(void);

/**
 * smw_config_deinit() - Deinitialize the Configuration module.
 *
 * This function deinitializes the Configuration module.
 *
 * Return:
 * error code.
 */
int smw_config_deinit(void);

/**
 * smw_config_notify_subsystem_failure() - Notify subsystem failure.
 * @id: ID of the subsystem.
 *
 * This function notifies about a subsystem failure.
 * It is called by the subsystem module when the subsystem has encountered
 * a failure so that the configuration module can take appropriate action.
 *
 * Return:
 * none.
 */
void smw_config_notify_subsystem_failure(enum subsystem_id id);
