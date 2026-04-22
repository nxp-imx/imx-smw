// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include "ele_common.h"
#include "ele_crypto_data_storage.h"
#include "ele_crypto_internal.h"
#include "ele_nvm_service.h"
#include "ele_nvm_manager.h"

#include "utils.h"
#include "utils_ex.h"

static status_t nvm_storage_handle_get_req(s3mu_t *mu, uint32_t *buf,
					   ele_data_storage_t *conf)
{
	status_t status = STATUS_FAIL;
	chunk_get_req_t *chunk_req = NULL;
	chunk_get_respond_t get_response = { 0 };
	chunk_get_done_t get_done = { 0 };
	chunk_get_done_resp_t get_done_resp = { 0 };

	if (!mu || !buf || !conf)
		return STATUS_INVALID_ARGUMENT;

	/* Obtain chunk get request from Security Sub-System */
	chunk_req = (chunk_get_req_t *)buf;

	/* Check request comman header from Secure Sub-System */
	if (chunk_req->header.value != STORAGE_GET_RESPONSE_REQ_HDR)
		goto end;

	get_response.header.value = GET_CHUNK_RESPONSE_HDR;
	get_response.chunk_size = conf->chunk_size;
	get_response.chunk_addr = conf->chunk_addr;
	get_response.response_code = RESPONSE_SUCCESS;

	/* Send export chunk address message to Security Sub-System */
	status = s3mu_send_message(mu, &get_response, STORAGE_GET_CHUNK_SIZE);
	if (status != STATUS_SUCCESS)
		goto end;

	/* Obtain Storage get chunk done command from Security Sub-System */
	status = s3mu_get_response(mu, &get_done);
	if (status != STATUS_SUCCESS)
		goto end;

	if (get_done.header.value != GET_DONE_HDR ||
	    get_done.status != GET_STATUS_SUCCESS) {
		status = STATUS_FAIL;
		goto end;
	}

	get_done_resp.header.value = GET_DONE_RESPONSE_HDR;
	get_done_resp.status = RESPONSE_SUCCESS;

	/* Send Storage export finish response to Security Sub-System */
	status = s3mu_send_message(mu, &get_done_resp, GET_DONE_RESPONSE_SIZE);

end:
	return status;
}

static uint32_t *nvm_storage_handle_export_req(s3mu_t *mu, uint32_t *buf,
					       uint8_t *out, size_t *size)
{
	status_t status = STATUS_FAIL;
	chunk_master_export_respond_t chunk_master_respond = { 0 };
	chunk_export_respond_t chunk_response = { 0 };
	chunk_export_req_t *chunk_req = NULL;
	chunk_export_finish_t finish = { 0 };
	uint32_t *chunk_address = NULL;
	uintptr_t chunk_address_phys = 0;
	size_t chunk_sz = 0;

	if (!mu || !buf || !size)
		return NULL;

	chunk_req = (chunk_export_req_t *)buf;
	chunk_sz = chunk_req->chunk_size;
	/*
	 * Check if out is not NULL that it's size is sufficient for chunk.
	 * Ideally BUFFER SHORT error should be returned with required size in *size,
	 * but function prototype doesn't allow it, so returning back NULL.
	 */
	if (out && *size < chunk_sz)
		goto end;

	/* ----- Step 2) Send response to ELE with address where to store the chunk */
	/* Check command request header from Secure Sub-System */
	switch (chunk_req->header.value) {
	case STORAGE_EXPORT_RESPONSE_REQ_HDR:
		/* Regular (data storage, key group or keystore) chunk export. */
		chunk_response.header.value = EXPORT_CHUNK_RESPONSE_HDR;
		chunk_response.response_code = RESPONSE_SUCCESS;

		*size = chunk_sz;
		chunk_address = (uint32_t *)
			/* Allocate shared memory for the chunk */
			smw_utils_shared_memory_alloc(out, *size,
						      &chunk_address_phys);
		if (!chunk_address)
			goto end;

		chunk_response.chunk_addr = (uint32_t)chunk_address_phys;

		/* Send export chunk address message to Security Sub-System */
		status = s3mu_send_message(mu, &chunk_response,
					   STORAGE_EXPORT_CHUNK_SIZE);

		break;

	case STORAGE_EXPORT_MASTER_RESPONSE_REQ_HDR:
		/* Master storage export request */
		chunk_master_respond.header.value =
			EXPORT_MASTER_CHUNK_RESPONSE_HDR;
		chunk_master_respond.storage_handle = chunk_req->storage_handle;
		chunk_master_respond.response_code = RESPONSE_SUCCESS;

		*size = chunk_sz;
		chunk_address = (uint32_t *)
			/* Allocate shared memory for the chunk */
			smw_utils_shared_memory_alloc(out, *size,
						      &chunk_address_phys);
		if (!chunk_address)
			goto end;

		chunk_master_respond.chunk_addr = (uint32_t)chunk_address_phys;

		/* Send export chunk address message to Security Sub-System */
		status = s3mu_send_message(mu, &chunk_master_respond,
					   STORAGE_MASTER_EXPORT_CHUNK_SIZE);

		break;

	default:
		goto end;
	}

	if (status != STATUS_SUCCESS)
		goto end;

	/* ----- Step 3) Get export finish request from ELE */
	/* Get Storage export finish command from Security Sub-System */
	status = s3mu_get_response(mu, &finish);
	if (status != STATUS_SUCCESS)
		goto end;

	if (finish.header.value != EXPORT_FINISH_HDR &&
	    finish.status != EXPORT_STATUS_SUCCESS) {
		status = STATUS_FAIL;
		goto end;
	}

	/* ----- Step 4) Send Export finish response to ELE */
	/* Send Storage export finish response to Security Sub-System */
	status = ele_storage_export_finish(mu, finish.storage_handle);

end:
	if (status == STATUS_SUCCESS)
		out = malloc_if_not_null(out, *size);
	else
		out = NULL;

	if (chunk_address)
		smw_utils_shared_memory_free((void *)chunk_address, *size, out);

	return out;
}

uint32_t *nvm_storage_export_req(s3mu_t *mu, uint32_t *out, size_t *size)
{
	status_t status = STATUS_FAIL;
	chunk_export_req_t chunk_req = { 0 };

	/* ----- Step 1) Get request and check */
	/* Obtain chunk export request from Security Sub-System */
	status = s3mu_get_response(mu, &chunk_req);
	if (status != STATUS_SUCCESS)
		return NULL;

	return nvm_storage_handle_export_req(mu, (uint32_t *)&chunk_req, out,
					     size);
}

status_t nvm_storage_get_req(s3mu_t *mu, ele_data_storage_t *conf)
{
	status_t status = STATUS_FAIL;
	chunk_get_req_t chunk_req = { 0 };

	/* Obtain chunk get request from Security Sub-System */
	status = s3mu_get_response(mu, &chunk_req);
	if (status != STATUS_SUCCESS)
		return status;

	return nvm_storage_handle_get_req(mu, (uint32_t *)&chunk_req, conf);
}

status_t nvm_storage_handle_req(s3mu_t *mu, uint32_t *buf, uint32_t word_count)
{
	status_t status = STATUS_FAIL;
	mu_hdr_t *msg = (mu_hdr_t *)buf;
	uint32_t *buffer = NULL;
	uint32_t *chunk = NULL;
	uintptr_t chunk_phys = 0;
	size_t chunk_sz = 0;
	chunk_export_req_t *chunk_export_req = NULL;
	chunk_get_req_t *chunk_req = NULL;
	ele_data_storage_t storage_conf = { 0 };
	ele_nvm_manager_t *nvm_manager = ele_get_nvm_manager();

	/* The request can be handled only if NVM Manager is registered */
	if (!nvm_manager)
		return STATUS_FAIL;

	switch (msg->hdr_byte.command) {
	case STORAGE_MASTER_EXPORT_CMD:
		/* Chunk will be allocated by nvm_storage_export_req() */
		chunk = nvm_storage_handle_export_req(mu, buf, NULL, &chunk_sz);
		if (!chunk)
			return STATUS_FAIL;

		/* Blob ID -> 0 fixed for storage master. */
		status = nvm_manager->nvm_write(STORAGE_MASTER_BLOB_ID,
						STORAGE_MASTER_BLOB_ID, 0,
						chunk, chunk_sz);

		/* Free the chunk allocated by nvm_storage_export_req() */
		SMW_UTILS_FREE(chunk);
		break;

	case STORAGE_CHUNK_EXPORT_CMD:
		chunk_export_req = (chunk_export_req_t *)buf;
		/* Chunk will be allocated by nvm_storage_export_req() */
		chunk = nvm_storage_handle_export_req(mu, buf, NULL, &chunk_sz);
		if (!chunk)
			return STATUS_FAIL;

		/* use full blob ID (MSB and LSB) and extension */
		/* NVM manager call to Store chunk in actual NVM */
		status = nvm_manager->nvm_write(chunk_export_req->blob_id_msb,
						chunk_export_req->blob_id_lsb,
						chunk_export_req->blob_id_ext,
						chunk, chunk_sz);

		/* Free the chunk allocated by nvm_storage_export_req() */
		SMW_UTILS_FREE(chunk);
		break;

	case STORAGE_GET_CHUNK_CMD:
		chunk_req = (chunk_get_req_t *)buf;

		/*
		 * Retrieve chunk from NVM
		 * NVMmgr allocates chunk based on size of data and returns a pointer.
		 */
		status = nvm_manager->nvm_read(chunk_req->blob_id_msb,
					       chunk_req->blob_id_lsb,
					       chunk_req->blob_id_ext, NULL,
					       &chunk_sz);
		if (status != STATUS_SUCCESS)
			return status;

		if (chunk_sz == 0u)
			return STATUS_NO_DATA;

		buffer = SMW_UTILS_MALLOC(chunk_sz);
		if (!buffer)
			return STATUS_FAIL;

		status = nvm_manager->nvm_read(chunk_req->blob_id_msb,
					       chunk_req->blob_id_lsb,
					       chunk_req->blob_id_ext, buffer,
					       &chunk_sz);
		if (status != STATUS_SUCCESS) {
			SMW_UTILS_FREE(buffer);
			return status;
		}

		chunk = smw_utils_shared_memory_alloc(buffer, chunk_sz,
						      &chunk_phys);
		if (!chunk) {
			SMW_UTILS_FREE(buffer);
			return STATUS_FAIL;
		}

		storage_conf.chunk_size = chunk_sz;
		storage_conf.chunk_addr = chunk_phys;

		/* Import chunk into the ELE */
		status = nvm_storage_handle_get_req(mu, buf, &storage_conf);

		smw_utils_shared_memory_free(chunk, chunk_sz, NULL);
		SMW_UTILS_FREE(buffer);
		break;
	default:
		return STATUS_FAIL;
	}

	return status;
}
