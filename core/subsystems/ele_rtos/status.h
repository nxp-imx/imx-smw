/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2026 NXP
 */

#ifndef __STATUS_H__
#define __STATUS_H__

#include <stdint.h>

#define MAKE_STATUS(group, code) ((((group) << 8) + (code)))

/**
 * STATUSGROUP_GENERIC - Group number for generic status codes.
 * STATUSGROUP_ELEMU - Group number for ELEMU status codes.
 * STATUSGROUP_ELE - Group number for ELE status codes.
 */
enum _status_groups {
	STATUSGROUP_GENERIC = 0,
	STATUSGROUP_ELEMU = 1,
	STATUSGROUP_ELE = 2,
};

#define MAKE_STATUS_GENERIC(code) MAKE_STATUS(STATUSGROUP_GENERIC, code)
#define MAKE_STATUS_ELE(code)	  MAKE_STATUS(STATUSGROUP_ELE, code)
#define MAKE_STATUS_ELEMU(code)	  MAKE_STATUS(STATUSGROUP_ELEMU, code)

/**
 * STATUS_SUCCESS - Generic status for Success.
 * STATUS_FAIL - Generic status for Fail.
 * STATUS_READ_ONLY - Generic status for read only failure.
 * STATUS_OUT_OF_RANGE - Generic status for out of range access.
 * STATUS_INVALID_ARGUMENT - Generic status for invalid argument check.
 * STATUS_TIMEOUT - Generic status for timeout.
 * STATUS_NO_TRANSFER_IN_PROGRESS - Generic status for no transfer in progress.
 * STATUS_BUSY - Generic status for module is busy.
 * STATUS_NO_DATA - Generic status for no data is found for the operation.
 * Note: Specific status codes for ELEMU and ELE are defined in their respective headers.
 */
enum _status {
	STATUS_SUCCESS = MAKE_STATUS_GENERIC(0u),
	STATUS_FAIL = MAKE_STATUS_GENERIC(1u),
	STATUS_READ_ONLY = MAKE_STATUS_GENERIC(2u),
	STATUS_OUT_OF_RANGE = MAKE_STATUS_GENERIC(3u),
	STATUS_INVALID_ARGUMENT = MAKE_STATUS_GENERIC(4u),
	STATUS_TIMEOUT = MAKE_STATUS_GENERIC(5u),
	STATUS_NO_TRANSFER_IN_PROGRESS = MAKE_STATUS_GENERIC(6u),
	STATUS_BUSY = MAKE_STATUS_GENERIC(7u),
	STATUS_NO_DATA = MAKE_STATUS_GENERIC(8u),
};

/* Type used for all status and error return values. */
typedef int32_t status_t;

#endif /* __STATUS_H__ */
