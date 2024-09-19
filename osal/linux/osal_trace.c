// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2024 NXP
 */

#include <errno.h>
#include <sys/file.h>

#include "local.h"

char *get_strerr(void)
{
	if (__errno_location())
		return strerror(errno);

	return "Unknown error";
}
