/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021, 2024, 2026 NXP
 */

#ifndef __SMW_INFO_H__
#define __SMW_INFO_H__

#include "smw_status.h"
#include "smw/names.h"

/**
 * smw_get_version() - Get the library version.
 * @major: [out] Library major version.
 * @minor: [out] Library minor version.
 *
 * This function returns the library major and minor version numbers.
 *
 * Return:
 *  - SMW_STATUS_OK:
 *      Success.
 *  - SMW_STATUS_INVALID_PARAM:
 *      Either @major or @minor parameter is NULL.
 *  - Other error codes from &enum smw_status_code
 */
enum smw_status_code smw_get_version(unsigned int *major, unsigned int *minor);

#endif /* __SMW_INFO_H__ */
