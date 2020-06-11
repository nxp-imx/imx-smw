/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020 NXP
 */
#ifndef __SMW_CONFIG_H__
#define __SMW_CONFIG_H__

/**
 * smw_config_subsystem_present() - Check if the subsystem is present or not.
 * @subsystem: Name of the subsystem
 *
 * Return:
 * SMW_STATUS_OK  Subsystem is present
 * error code otherwise
 */
int smw_config_subsystem_present(const char *subsystem);

/**
 * smw_config_subsystem_check_digest() - Check if a digest @algo is supported
 * @subsystem: Name of the subsystem
 * @algo: Digest algorithm name
 *
 * Return:
 * SMW_STATUS_OK                       Subsystem is present
 * SMW_STATUS_OPERATION_NOT_CONFIGURED Algorithm not supported
 * error code otherwise
 */
int smw_config_subsystem_check_digest(const char *subsystem, const char *algo);

#endif /* __SMW_CONFIG_H__ */
