// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022, 2026 NXP
 */

#include "ele_crypto.h"
#include "ele_crypto_internal.h"
#include "ele_crypto_data_storage.h"
#include "ele_nvm_manager.h"
#include "ele_nvm_service.h"
#include "s3mu.h"

#include "utils.h"
#include "utils_ex.h"

static ele_nvm_manager_t *g_ELE_NVM_Mngr;

status_t ele_register_nvm_manager(ele_nvm_manager_t *manager)
{
	if (!manager || !manager->nvm_read || !manager->nvm_write)
		return STATUS_FAIL;

	if (g_ELE_NVM_Mngr)
		return STATUS_BUSY;

	g_ELE_NVM_Mngr = SMW_UTILS_MALLOC(sizeof(ele_nvm_manager_t));
	if (!g_ELE_NVM_Mngr)
		return STATUS_FAIL;

	g_ELE_NVM_Mngr->nvm_read = manager->nvm_read;
	g_ELE_NVM_Mngr->nvm_write = manager->nvm_write;

	return STATUS_SUCCESS;
}

status_t ele_unregister_nvm_manager(void)
{
	SMW_UTILS_FREE(g_ELE_NVM_Mngr);

	g_ELE_NVM_Mngr = NULL;

	return STATUS_SUCCESS;
}

ele_nvm_manager_t *ele_get_nvm_manager(void)
{
	return g_ELE_NVM_Mngr;
}

status_t ele_export_chunks_to_nvm(s3mu_t *mu, uint32_t key_handle_id,
				  bool export_key_group, uint32_t key_group_id)
{
	status_t status = STATUS_FAIL;
	uint32_t tmsg[KEY_MNG_GROUP_SIZE] = { 0u };
	uint32_t rmsg[S3MU_RR_COUNT] = { 0u };
	uint32_t flags = SYNC_OP;

	if (!export_key_group) {
		flags = SYNC_OP_NO_KEY;
		key_group_id = 0u;
	}

	tmsg[0] = KEY_MNG_GROUP; /* KEY_MNG_GROUP Command Header */
	tmsg[1] = key_handle_id; /* Key Management handle ID */
	tmsg[2] = flags << SHIFT_16 | key_group_id; /* STRICT Operation */

	/* Send message Security Sub-System */
	status = s3mu_send_message(mu, tmsg, KEY_MNG_GROUP_SIZE);
	if (status != STATUS_SUCCESS)
		return status;

	/* Wait for response from Security Sub-System */
	status = ele_mu_get_response(mu, rmsg);
	if (status != STATUS_SUCCESS)
		return status;

	/* Check that response corresponds to the sent command */
	if (rmsg[0] == KEY_MNG_GROUP_RESPONSE_HDR &&
	    rmsg[1] == RESPONSE_SUCCESS)
		return STATUS_SUCCESS;
	else
		return STATUS_FAIL;
}

status_t ele_manage_key_group_to_nvm(s3mu_t *mu, uint32_t key_handle_id,
				     uint32_t key_group_id,
				     key_group_mng_t operation)
{
	status_t status = STATUS_FAIL;
	uint32_t tmsg[KEY_MNG_GROUP_SIZE] = { 0u };
	uint32_t rmsg[S3MU_RR_COUNT] = { 0u };

	tmsg[0] = KEY_MNG_GROUP; /* KEY_MNG_GROUP Command Header */
	tmsg[1] = key_handle_id; /* Key Management handle ID */
	tmsg[2] = ((uint32_t)operation << SHIFT_16) | key_group_id;

	/* Send message Security Sub-System */
	status = s3mu_send_message(mu, tmsg, KEY_MNG_GROUP_SIZE);
	if (status != STATUS_SUCCESS)
		return status;

	/* Wait for response from Security Sub-System */
	status = ele_mu_get_response(mu, rmsg);
	if (status != STATUS_SUCCESS)
		return status;

	/* Check that response corresponds to the sent command */
	if (rmsg[0] == KEY_MNG_GROUP_RESPONSE_HDR &&
	    rmsg[1] == RESPONSE_SUCCESS)
		return STATUS_SUCCESS;
	else
		return STATUS_FAIL;
}

status_t ele_storage_master_import_from_nvm(s3mu_t *mu, uint32_t nvm_storage_id)
{
	status_t status = STATUS_FAIL;
	uint32_t tmsg[NVM_MASTER_IMPORT_SIZE] = { 0u };
	uint32_t rmsg[S3MU_RR_COUNT] = { 0u };
	uint32_t *chunk = NULL;
	uintptr_t chunk_phys = 0;
	size_t chunk_sz = 0u;
	uint32_t *buffer = NULL;

	/* The request can be handled only if NVM Manager is registered */
	if (!g_ELE_NVM_Mngr)
		return STATUS_FAIL;

	tmsg[0] = NVM_MASTER_IMPORT; /* NVM_MASTER_IMPORT Command Header */
	tmsg[1] = nvm_storage_id;    /* NVM storage ID handle ID */

	status = g_ELE_NVM_Mngr->nvm_read(STORAGE_MASTER_BLOB_ID,
					  STORAGE_MASTER_BLOB_ID, 0, NULL,
					  &chunk_sz);
	if (status != STATUS_SUCCESS)
		return status;

	if (chunk_sz == 0u)
		/* Master Chunk doesn't exist in NVM */
		return STATUS_NO_DATA;

	buffer = SMW_UTILS_MALLOC(chunk_sz);
	if (!buffer)
		return STATUS_FAIL;

	status = g_ELE_NVM_Mngr->nvm_read(STORAGE_MASTER_BLOB_ID,
					  STORAGE_MASTER_BLOB_ID, 0, buffer,
					  &chunk_sz);
	if (status != STATUS_SUCCESS)
		goto end;

	chunk = smw_utils_shared_memory_alloc(buffer, chunk_sz, &chunk_phys);
	if (!chunk)
		goto end;

	tmsg[2] = (uint32_t)chunk_phys; /* Address of master chunk */
	tmsg[3] = (uint32_t)chunk_sz;	/* Master chunk size */

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
	if (chunk)
		smw_utils_shared_memory_free(chunk, chunk_sz, NULL);

	if (buffer)
		SMW_UTILS_FREE(buffer);

	return status;
}
