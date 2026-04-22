// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include "ele_crypto_key_group_mng.h"
#include "ele_crypto_data_storage.h"
#include "ele_crypto_internal.h"
#include "ele_nvm_storage.h"

#include "common.h"
#include "utils_ex.h"

status_t ele_manage_key_group(s3mu_t *mu, uint32_t key_handle_id,
			      uint32_t key_group_id, key_group_mng_t operation,
			      uint32_t *addr, size_t size)
{
	status_t status = STATUS_SUCCESS;
	uint32_t tmsg[KEY_MNG_GROUP_SIZE] = { 0u };
	uint32_t rmsg[S3MU_RR_COUNT] = { 0u };
	ele_data_storage_t storage_conf = { 0 };

	if ((operation == ELE_KEYMNG_IMPORT ||
	     operation == ELE_KEYMNG_EXPORT) &&
	    !addr)
		/* Operation with chunk(s) requested, but no address for provided */
		return STATUS_FAIL;

	tmsg[0] = KEY_MNG_GROUP; /* KEY_MNG_GROUP Command Header */
	tmsg[1] = key_handle_id; /* Key Management handle ID */
	tmsg[2] = (uint32_t)operation << SHIFT_16 | key_group_id;

	/* Send message Security Sub-System */
	status = s3mu_send_message(mu, tmsg, KEY_MNG_GROUP_SIZE);
	if (status != STATUS_SUCCESS)
		return status;

	if (IS_ENABLED(CONFIG_SMW_NVM_MANAGER)) {
		switch (operation) {
		case ELE_KEYMNG_IMPORT:
			/* Prepare data for chunk import */
			storage_conf.chunk_size = size;
			storage_conf.chunk_addr = (uint32_t *)addr;

			/* Import chunk into the ELE */
			status = nvm_storage_get_req(mu, &storage_conf);
			if (status != STATUS_SUCCESS)
				return status;

			break;
		case ELE_KEYMNG_EXPORT:
			/* Handle export of key group chunk */
			addr = nvm_storage_export_req(mu, addr, &size);
			if (!addr)
				return STATUS_FAIL;

			break;
		default:
			/* Unlock or lock - no chunk needed */
			break;
		}
	}

	/* Wait for response from Security Sub-System */
	status = ele_mu_get_response(mu, rmsg);
	if (status != STATUS_SUCCESS)
		return status;

	/* Check that response corresponds to the sent command */
	if (rmsg[0] == KEY_MNG_GROUP_RESPONSE_HDR &&
	    rmsg[1] == RESPONSE_SUCCESS)
		return STATUS_SUCCESS;

	return STATUS_FAIL;
}

status_t ele_export_chunks(s3mu_t *mu, uint32_t key_handle_id,
			   bool export_key_group, uint32_t key_group_id,
			   bool monotonic, ele_chunks_t *chunks)
{
	status_t status = STATUS_SUCCESS;
	uint32_t tmsg[KEY_MNG_GROUP_SIZE] = { 0u };
	uint32_t rmsg[S3MU_RR_COUNT] = { 0u };
	size_t unused_size = 0;
	uint32_t flags = 0u;

	if (!chunks)
		/* Operation with chunk(s) requested, but no address provided */
		return STATUS_FAIL;

	if (!export_key_group) {
		flags = SYNC_OP_NO_KEY;
		key_group_id = 0u;
	} else {
		flags = SYNC_OP;
	}

	/* This will trigger update anti-roolback counter in fuse */
	if (monotonic)
		flags |= SYNC_MONOTONIC;

	tmsg[0] = KEY_MNG_GROUP; /* KEY_MNG_GROUP Command Header */
	tmsg[1] = key_handle_id; /* Key Management handle ID */
	tmsg[2] = flags << SHIFT_16 | key_group_id; /* Sync Operation */

	/* Send message Security Sub-System */
	status = s3mu_send_message(mu, tmsg, KEY_MNG_GROUP_SIZE);
	if (status != STATUS_SUCCESS)
		return status;

	/* Skip key group export if only keystore and master are required */
	if (export_key_group) {
		/* Handle export of key group chunk */
		chunks->keygroup_chunk =
			nvm_storage_export_req(mu, chunks->keygroup_chunk,
					       &chunks->keygroup_size);
		if (!chunks->keygroup_chunk)
			return STATUS_FAIL;

		smw_utils_dcache_invalidate(chunks->keygroup_chunk,
					    chunks->keygroup_size);
	}

	/* Handle export of key store chunk */
	chunks->keystore_chunk =
		nvm_storage_export_req(mu, chunks->keystore_chunk,
				       &chunks->keystore_size);
	if (!chunks->keystore_chunk)
		return STATUS_FAIL;

	smw_utils_dcache_invalidate(chunks->keystore_chunk,
				    chunks->keystore_size);

	/* Handle export of storage master chunk */
	if (nvm_storage_export_req(mu, chunks->master_chunk, &unused_size) ==
		    NULL ||
	    unused_size != MASTER_CHUNK_SIZE) {
		/* Even if chunks->MasterChunk is allocated as spart of ele_chunks_t structure,
		 * nvm_storage_export_req() return it's address if success, NULL otherwise.
		 */
		return STATUS_FAIL;
	}
	smw_utils_dcache_invalidate(chunks->master_chunk, MASTER_CHUNK_SIZE);

	/* Wait for response from Security Sub-System */
	status = s3mu_get_response(mu, rmsg);
	if (status != STATUS_SUCCESS)
		return status;

	/* Check that response corresponds to the sent command */
	if (rmsg[0] == KEY_MNG_GROUP_RESPONSE_HDR &&
	    rmsg[1] == RESPONSE_SUCCESS)
		return STATUS_SUCCESS;

	return STATUS_FAIL;
}
