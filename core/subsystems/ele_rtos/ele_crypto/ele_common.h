/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2026 NXP
 */

#ifndef __ELE_COMMON_H__
#define __ELE_COMMON_H__

#include <stdbool.h>

#include "builtin_macros.h"
#include "status.h"
#include "s3mu.h"

enum {
	/* ELE status for buffer sizes that are too small. */
	STATUS_ELE_BUFFER_TOO_SMALL = MAKE_STATUS_ELE(0x1u),
	STATUS_ELE_KEY_GROUP_FULL = MAKE_STATUS_ELE(0x2u),
};

/**
 * nvm_storage_handle_req() - Handle NVM storage requests from ELE
 * @mu: MU peripheral base address
 * @buf: Buffer containing the request message
 * @word_count: Number of words in the buffer
 *
 * This function is the main dispatcher for NVM storage requests from
 * EdgeLock Enclave. It handles master export, chunk export, and chunk
 * get commands by calling the appropriate handler functions and
 * interfacing with the registered NVM manager.
 *
 * Return:
 * Status_Success                  - Success
 * Status_Fail                     - Fail
 * Status_S3MU_InvalidArgument     - Invalid argument parameter
 */
status_t nvm_storage_handle_req(s3mu_t *mu, uint32_t *buf, uint32_t word_count);

/**
 * ele_mu_get_response() - Get response from MU
 * @mu: MU peripheral base address
 * @buf: Buffer to store read data
 *
 * This function reads response data from EdgeLock Enclave if available.
 *
 * Return:
 * Status_Success                  - Success
 * Status_Fail                     - Fail
 * Status_S3MU_InvalidArgument     - Invalid argument parameter
 * Status_S3MU_AgumentOutOfRange   - Argument out of range
 */
status_t ele_mu_get_response(s3mu_t *mu, uint32_t *buf);

/* If addr is NULL, allocate on heap, eitherway return a given addr */
void *malloc_if_not_null(void *addr, size_t size);

#endif /* __ELE_COMMON_H__ */
