// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021 NXP
 */

#include "smw_info.h"
#include "smw_status.h"

#include "compiler.h"
#include "info.h"

__export enum smw_status_code smw_get_version(unsigned int *major,
					      unsigned int *minor)
{
	if (!major || !minor)
		return SMW_STATUS_INVALID_PARAM;

	*major = LIB_VER_MAJOR;
	*minor = LIB_VER_MINOR;

	return SMW_STATUS_OK;
}
