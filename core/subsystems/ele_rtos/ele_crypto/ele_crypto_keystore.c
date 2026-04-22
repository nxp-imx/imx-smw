// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include "ele_crypto_keystore.h"
#include "ele_crypto_data_storage.h"
#include "ele_crypto_internal.h"

#include "common.h"
#include "utils_ex.h"

status_t ele_create_keystore(s3mu_t *mu, uint32_t session_id,
			     ele_keystore_t *conf, uint32_t *keystore_handle_id)
{
	status_t status = STATUS_FAIL;
	uint32_t tmsg[OPEN_KEY_STORE_SIZE] = { 0u };
	uint32_t rmsg[S3MU_RR_COUNT] = { 0u };

	/* Create Flag word */
	/*   +----------------+----------+------------------------+
	 *   |     Reserved   |  Flags   |       Reserved         |
	 *   +----------------+----------+------------------------+
	 *   |    bit 31-24   | Bit 23-16|       Bit 15-0         |
	 *   +----------------+----------+------------------------+
	 */
	uint32_t flags = (1UL << KEYSTORE_CREATE_SHIFT);

	tmsg[0] = OPEN_KEY_STORE; /* OPEN_KEY_STORE Command Header */
	tmsg[1] = session_id;	  /* Session handle ID */
	tmsg[2] = conf->id;	  /* Key Store ID (User defined) */
	tmsg[3] = conf->nonce;	  /* Authentication nonce */
	tmsg[4] = flags;	  /* Flag (bit 23-16) */
	tmsg[5] = s3mu_compute_msg_crc(tmsg, OPEN_KEY_STORE_SIZE - 1u);

	/* Send message Security Sub-System */
	if (s3mu_send_message(mu, tmsg, OPEN_KEY_STORE_SIZE) != STATUS_SUCCESS)
		return status;

	/* Wait for response from Security Sub-System */
	if (ele_mu_get_response(mu, rmsg) != STATUS_SUCCESS)
		return status;

	/* Check that response corresponds to the sent command */
	if (rmsg[0] == OPEN_KEY_STORE_RESPONSE_HDR &&
	    rmsg[1] == RESPONSE_SUCCESS) {
		/* read Key Store ID data */
		*keystore_handle_id = rmsg[2];
		return STATUS_SUCCESS;
	}

	return STATUS_FAIL;
}

status_t ele_open_keystore(s3mu_t *mu, uint32_t session_id,
			   ele_keystore_t *conf, uint32_t *keystore_handle_id,
			   uint32_t *keystore_chunk, size_t chunk_size)
{
	status_t status = STATUS_FAIL;
	uint32_t tmsg[OPEN_KEY_STORE_SIZE] = { 0u };
	uint32_t rmsg[S3MU_RR_COUNT] = { 0u };
	uintptr_t keystore_chunk_phys = 0;
	void *keystore_chunk_addr = NULL;

	/* Create Flag word */
	/*   +----------------+----------+------------------------+
	 *   |     Reserved   |  Flags   |       Reserved         |
	 *   +----------------+----------+------------------------+
	 *   |    bit 31-24   | Bit 23-16|       Bit 15-0         |
	 *   +----------------+----------+------------------------+
	 */
	uint32_t flags = (0UL << KEYSTORE_CREATE_SHIFT);

	if (keystore_chunk && chunk_size != 0u) {
		keystore_chunk_addr =
			smw_utils_shared_memory_alloc(keystore_chunk,
						      chunk_size,
						      &keystore_chunk_phys);
		if (!keystore_chunk_addr)
			return STATUS_FAIL;
	}

	tmsg[0] = OPEN_KEY_STORE; /* OPEN_KEY_STORE Command Header */
	tmsg[1] = session_id;	  /* Session handle ID */
	tmsg[2] = conf->id;	  /* Key Store ID (User defined) */
	tmsg[3] = conf->nonce;	  /* Authentication nonce */
	tmsg[4] = flags;	  /* Flag (bit 23-16) */
	tmsg[5] = s3mu_compute_msg_crc(tmsg, OPEN_KEY_STORE_SIZE - 1u);

	/* Send message Security Sub-System */
	if (s3mu_send_message(mu, tmsg, OPEN_KEY_STORE_SIZE) != STATUS_SUCCESS)
		return status;

	if (keystore_chunk && chunk_size != 0u) {
		/* Prepare data for chunk import */
		ele_data_storage_t storage_conf;

		storage_conf.chunk_size = chunk_size;
		storage_conf.chunk_addr = (uint32_t *)keystore_chunk_phys;

		if (IS_ENABLED(CONFIG_SMW_NVM_MANAGER)) {
			/* Import chunk into the ELE */
			status = nvm_storage_get_req(mu, &storage_conf);
			if (status != STATUS_SUCCESS)
				goto end;
		}
	}

	/* Wait for response from Security Sub-System */
	if (ele_mu_get_response(mu, rmsg) != STATUS_SUCCESS)
		goto end;

	/* Check that response corresponds to the sent command */
	if (rmsg[0] == OPEN_KEY_STORE_RESPONSE_HDR &&
	    rmsg[1] == RESPONSE_SUCCESS) {
		/* read Key Store ID data */
		*keystore_handle_id = rmsg[2];
		status = STATUS_SUCCESS;
	} else {
		status = STATUS_FAIL;
	}

end:
	smw_utils_shared_memory_free(keystore_chunk_addr, chunk_size, NULL);

	return status;
}

status_t ele_close_keystore(s3mu_t *mu, uint32_t keystore_handle_id)
{
	status_t status = STATUS_FAIL;
	uint32_t tmsg[OPEN_KEY_STORE_SIZE] = { 0u };
	uint32_t rmsg[S3MU_RR_COUNT] = { 0u };

	tmsg[0] = CLOSE_KEY_STORE;    /* CLOSE_KEY_STORE Command Header */
	tmsg[1] = keystore_handle_id; /* Key Store HandleID */
	tmsg[2] = 0x0;		      /* Flags (reserved) */

	/* Send message Security Sub-System */
	if (s3mu_send_message(mu, tmsg, CLOSE_KEY_STORE_SIZE) != STATUS_SUCCESS)
		return status;

	/* Wait for response from Security Sub-System */
	if (ele_mu_get_response(mu, rmsg) != STATUS_SUCCESS)
		return status;

	/* Check that response corresponds to the sent command */
	if (rmsg[0] == CLOSE_KEY_STORE_RESPONSE_HDR &&
	    rmsg[1] == RESPONSE_SUCCESS)
		return STATUS_SUCCESS;

	return STATUS_FAIL;
}
