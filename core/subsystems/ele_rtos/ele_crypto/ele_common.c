// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <malloc.h>
#include <string.h>

#include "ele_common.h"
#include "ele_crypto_internal.h"

/*******************************************************************************
 * Code
 ******************************************************************************/

/* If addr is NULL, allocate on heap, eitherway return a given addr */
void *malloc_if_not_null(void *addr, size_t size)
{
	/* If out address is null, use HEAP */
	if (!addr && size > 0u)
		addr = calloc(1, size);

	return addr;
}

/* Weak function to handle nvm manager requests from ELE */
/* If NVM Manager is defined, this function can be over-ridden */
__weak status_t nvm_storage_handle_req(s3mu_t *mu, uint32_t *buf,
				       uint32_t wordCount)
{
	return kStatus_Fail;
}

status_t ele_mu_get_response(s3mu_t *mu, uint32_t *buf)
{
	status_t status = kStatus_Fail;
	uint32_t rmsg[MSG_RESPONSE_MAX] = { 0u };
	mu_hdr_t *msg = (mu_hdr_t *)rmsg;

	do {
		status = s3mu_get_response(mu, rmsg);
		if (status != kStatus_Success)
			break;

		if (msg->hdr_byte.tag == MSG_TAG_RESP) {
			(void)memcpy((void *)buf, (void *)msg,
				     (uint32_t)(msg->hdr_byte.size *
						sizeof(uint32_t)));
			break;
		} else if (msg->hdr_byte.tag == MSG_TAG_CMD) {
			status = nvm_storage_handle_req(mu, rmsg,
							msg->hdr_byte.size);
			if (status != kStatus_Success)
				break;

		} else {
			return kStatus_Fail;
		}
	} while (msg->hdr_byte.tag != MSG_TAG_RESP);

	return status;
}
