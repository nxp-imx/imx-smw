/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021 NXP
 */

#ifndef __SMW_INFO_H__
#define __SMW_INFO_H__

#include "smw_strings.h"

/**
 * DOC:
 * Library user can get general library information using following APIs.
 */

/**
 * smw_get_version() - Get the library version.
 * @major: Library major version.
 * @minor: Library minor version.
 *
 * Return:
 * See &enum smw_status_code
 *	- SMW_STATUS_OK:
 *		Success
 *	- SMW_STATUS_INVALID_PARAM:
 *		Either @major or @minor parameter is NULL
 */
enum smw_status_code smw_get_version(unsigned int *major, unsigned int *minor);

#endif /* __SMW_INFO_H__ */
