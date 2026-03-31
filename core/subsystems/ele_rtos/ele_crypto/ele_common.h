/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2026 NXP
 */

#ifndef __ELE_COMMON_H__
#define __ELE_COMMON_H__

#include <stdbool.h>

#include "status.h"
#include "s3mu.h"

enum {
	/* ELE status for buffer sizes that are too small. */
	kStatus_ELE_BufferTooSmall = MAKE_STATUS_ELE(0x1u),
	kStatus_ELE_KeyGroupFull = MAKE_STATUS_ELE(0x2u),
};

/**
 * nvm_storage_handle_req() - Handle NVM storage requests from ELE
 * @mu: MU peripheral base address
 * @buf: Buffer containing the request message
 * @wordCount: Number of words in the buffer
 *
 * This function is the main dispatcher for NVM storage requests from
 * EdgeLock Enclave. It handles master export, chunk export, and chunk
 * get commands by calling the appropriate handler functions and
 * interfacing with the registered NVM manager.
 *
 * Return:
 * kStatus_Success                  - Success
 * kStatus_Fail                     - Fail
 * kStatus_S3MU_InvalidArgument     - Invalid argument parameter
 */
status_t nvm_storage_handle_req(s3mu_t *mu, uint32_t *buf, uint32_t wordCount);

/**
 * ele_mu_get_response() - Get response from MU
 * @mu: MU peripheral base address
 * @buf: buffer to store read data
 *
 * This function reads response data from EdgeLock Enclave if available.
 *
 * Return:
 * kStatus_Success                  - Success
 * kStatus_Fail                     - Fail
 * kStatus_S3MU_InvalidArgument     - Invalid argument parameter
 * kStatus_S3MU_AgumentOutOfRange   - Argument out of range
 */
status_t ele_mu_get_response(s3mu_t *mu, uint32_t *buf);

/* If addr is NULL, allocate on heap, eitherway return a given addr */
void *malloc_if_not_null(void *addr, size_t size);

#endif /* __ELE_COMMON_H__ */
