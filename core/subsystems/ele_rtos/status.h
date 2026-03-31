/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2026 NXP
 */

#ifndef __STATUS_H__
#define __STATUS_H__

#include <stdint.h>

#define MAKE_STATUS(group, code) ((((group) << 8) + (code)))

/**
 * kStatusGroup_Generic - Group number for generic status codes.
 * kStatusGroup_ELEMU - Group number for ELEMU status codes.
 * kStatusGroup_ELE - Group number for ELE status codes.
 */
enum _status_groups {
	kStatusGroup_Generic = 0,
	kStatusGroup_ELEMU = 1,
	kStatusGroup_ELE = 2,
};

#define MAKE_STATUS_GENERIC(code) MAKE_STATUS(kStatusGroup_Generic, code)
#define MAKE_STATUS_ELE(code)	  MAKE_STATUS(kStatusGroup_ELE, code)
#define MAKE_STATUS_ELEMU(code)	  MAKE_STATUS(kStatusGroup_ELEMU, code)

/**
 * kStatus_Success - Generic status for Success.
 * kStatus_Fail - Generic status for Fail.
 * kStatus_ReadOnly - Generic status for read only failure.
 * kStatus_OutOfRange - Generic status for out of range access.
 * kStatus_InvalidArgument - Generic status for invalid argument check.
 * kStatus_Timeout - Generic status for timeout.
 * kStatus_NoTransferInProgress - Generic status for no transfer in progress.
 * kStatus_Busy - Generic status for module is busy.
 * kStatus_NoData - Generic status for no data is found for the operation.
 * Note: Specific status codes for ELEMU and ELE are defined in their respective headers.
 */
enum _status {
	kStatus_Success = MAKE_STATUS_GENERIC(0u),
	kStatus_Fail = MAKE_STATUS_GENERIC(1u),
	kStatus_ReadOnly = MAKE_STATUS_GENERIC(2u),
	kStatus_OutOfRange = MAKE_STATUS_GENERIC(3u),
	kStatus_InvalidArgument = MAKE_STATUS_GENERIC(4u),
	kStatus_Timeout = MAKE_STATUS_GENERIC(5u),
	kStatus_NoTransferInProgress = MAKE_STATUS_GENERIC(6u),
	kStatus_Busy = MAKE_STATUS_GENERIC(7u),
	kStatus_NoData = MAKE_STATUS_GENERIC(8u),
};

/* Type used for all status and error return values. */
typedef int32_t status_t;

#endif /* __STATUS_H__ */
