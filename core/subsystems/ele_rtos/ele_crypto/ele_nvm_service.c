// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include "ele_crypto_internal.h"
#include "ele_crypto_key_group_mng.h"

#include "utils_ex.h"

status_t ele_open_nvm_storage_service(s3mu_t *mu, uint32_t session_id,
				      uint32_t *nvm_storage_id)
{
	status_t status = STATUS_FAIL;
	uint32_t tmsg[NVM_STORAGE_OPEN_SIZE] = { 0u };
	uint32_t rmsg[S3MU_RR_COUNT] = { 0u };

	tmsg[0] = NVM_STORAGE_OPEN; /* NVM_STORAGE_OPEN Command Header */
	tmsg[1] = session_id;	    /* Session handle ID */
	tmsg[2] =
		0x00000000u; /* User Input address extension (UIA) - not used */
	tmsg[3] =
		0x00000000u; /* User Output address extension (UOA) - not used */
	tmsg[4] = 0x00000000u; /* Flag (reserved) */
	tmsg[5] = s3mu_compute_msg_crc(tmsg, NVM_STORAGE_OPEN_SIZE - 1u);

	/* Send message Security Sub-System */
	status = s3mu_send_message(mu, tmsg, NVM_STORAGE_OPEN_SIZE);
	if (status != STATUS_SUCCESS)
		return status;

	/* Wait for response from Security Sub-System */
	status = ele_mu_get_response(mu, rmsg);
	if (status != STATUS_SUCCESS)
		return status;

	/* Check that response corresponds to the sent command */
	if (rmsg[0] == NVM_STORAGE_OPEN_RESPONSE_HDR &&
	    rmsg[1] == RESPONSE_SUCCESS) {
		/* read storage ID data */
		*nvm_storage_id = rmsg[2];
		return STATUS_SUCCESS;
	}

	return STATUS_FAIL;
}

status_t ele_close_nvm_storage_service(s3mu_t *mu, uint32_t nvm_storage_id)
{
	status_t status = STATUS_FAIL;
	uint32_t tmsg[NVM_STORAGE_CLOSE_SIZE] = { 0u };
	uint32_t rmsg[S3MU_RR_COUNT] = { 0u };

	tmsg[0] = NVM_STORAGE_CLOSE; /* NVM_STORAGE_CLOSE Command Header */
	tmsg[1] = nvm_storage_id;    /* NVM storage handle ID */

	/* Send message Security Sub-System */
	status = s3mu_send_message(mu, tmsg, NVM_STORAGE_CLOSE_SIZE);
	if (status != STATUS_SUCCESS)
		return status;

	/* Wait for response from Security Sub-System */
	status = ele_mu_get_response(mu, rmsg);
	if (status != STATUS_SUCCESS)
		return status;

	/* Check that response corresponds to the sent command */
	if (rmsg[0] == NVM_STORAGE_CLOSE_RESPONSE_HDR &&
	    rmsg[1] == RESPONSE_SUCCESS)
		return STATUS_SUCCESS;

	return STATUS_FAIL;
}

status_t ele_storage_export_finish(s3mu_t *mu, uint32_t nvm_storage_id)
{
	chunk_export_finish_t finish_response = { 0 };

	finish_response.header.value = EXPORT_FINISH_RESPONSE_HDR;
	finish_response.storage_handle =
		nvm_storage_id; /* NVM Storage handle ID */
	finish_response.status = RESPONSE_SUCCESS;

	/* Send Storage export finish response to Security Sub-System */
	return s3mu_send_message(mu, &finish_response,
				 STORAGE_EXPORT_CHUNK_SIZE);
}

status_t ele_storage_master_import(s3mu_t *mu, uint32_t nvm_storage_id,
				   uint32_t *addr)
{
	status_t status = STATUS_FAIL;
	uint32_t tmsg[NVM_MASTER_IMPORT_SIZE] = { 0u };
	uint32_t rmsg[S3MU_RR_COUNT] = { 0u };
	uintptr_t chunk_phys = 0u;
	void *chunk_addr = NULL;

	if (!addr)
		/* No address for import provided */
		return STATUS_FAIL;

	chunk_addr = smw_utils_shared_memory_alloc(addr, MASTER_CHUNK_SIZE,
						   &chunk_phys);
	if (!chunk_addr)
		return STATUS_FAIL;

	tmsg[0] = NVM_MASTER_IMPORT;	/* NVM_MASTER_IMPORT Command Header */
	tmsg[1] = nvm_storage_id;	/* NVM storage ID handle ID */
	tmsg[2] = (uint32_t)chunk_phys; /* Address of master chunk */
	tmsg[3] = MASTER_CHUNK_SIZE;	/* Master chunk size */

	/* Send message Security Sub-System */
	status = s3mu_send_message(mu, tmsg, NVM_MASTER_IMPORT_SIZE);
	if (status != STATUS_SUCCESS)
		goto end;

	/* Wait for response from Security Sub-System */
	status = ele_mu_get_response(mu, rmsg);
	if (status != STATUS_SUCCESS)
		goto end;

	/* Check that response corresponds to the sent command */
	if (rmsg[0] == NVM_MASTER_IMPORT_RESPONSE_HDR &&
	    rmsg[1] == RESPONSE_SUCCESS)
		status = STATUS_SUCCESS;
	else
		status = STATUS_FAIL;

end:
	smw_utils_shared_memory_free(chunk_addr, MASTER_CHUNK_SIZE, NULL);

	return status;
}
