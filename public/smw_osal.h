/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021 NXP
 */

#ifndef __SMW_OSAL_H__
#define __SMW_OSAL_H__

/**
 * DOC:
 * The OSAL interface is the library API specific to the Operating System.
 * It's under the charge of the library integrator to adapt the OSAL library
 * part to the OS targeted.
 */

/**
 * smw_osal_latest_subsystem_name() - Return the latest Secure Subsystem name
 *
 * In DEBUG mode only, function returns the name of the latest Secure Subsystem
 * invoked by SMW.
 * This Secure Subsystem have been either explicitly requested by the caller or
 * selected by SMW given the operation arguments and the configuration file.
 * In other modes, function always returns NULL.
 *
 * Return:
 * In DEBUG mode only, the pointer to the static buffer containing the
 * null-terminated string name of the Secure Subsystem.
 * In other modes, NULL
 */
const char *smw_osal_latest_subsystem_name(void);

#endif /* __SMW_OSAL_H__ */
