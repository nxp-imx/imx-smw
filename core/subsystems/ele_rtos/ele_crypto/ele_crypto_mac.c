// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "ele_crypto_mac.h"
#include "ele_crypto_internal.h"

#include "utils_ex.h"

status_t ele_open_mac_service(s3mu_t *mu, uint32_t keystore_handle_id,
			      uint32_t *mac_handle_id)
{
	status_t status = STATUS_SUCCESS;
	uint32_t tmsg[OPEN_MAC_SESSION_SIZE] = { 0u };
	uint32_t rmsg[S3MU_RR_COUNT] = { 0u };

	tmsg[0] = OPEN_MAC_SESSION;   /* OPEN_SESSION Command Header */
	tmsg[1] = keystore_handle_id; /* Key store handle ID */
	tmsg[2] =
		0x00000000u; /* User Input address extension (UIA) - not used */
	tmsg[3] =
		0x00000000u; /* User Output address extension (UOA) - not used */
	tmsg[4] = 0x00000000u; /* Flags (reserved) */
	tmsg[5] = s3mu_compute_msg_crc(tmsg, OPEN_MAC_SESSION_SIZE - 1u);
	/* CRC sum of all the words of the message (excluding the CRC itself) */

	/* Send message Security Sub-System */
	status = s3mu_send_message(mu, tmsg, OPEN_MAC_SESSION_SIZE);
	if (status != STATUS_SUCCESS)
		return status;

	/* Wait for response from Security Sub-System */
	status = ele_mu_get_response(mu, rmsg);
	if (status != STATUS_SUCCESS)
		return status;

	/* Check that response corresponds to the sent command */
	if (rmsg[0] == OPEN_MAC_SESSION_RESPONSE_HDR &&
	    rmsg[1] == RESPONSE_SUCCESS) {
		/* read MAC Handle ID data */
		*mac_handle_id = rmsg[2];
		return STATUS_SUCCESS;
	}

	return STATUS_FAIL;
}

status_t ele_close_mac_service(s3mu_t *mu, uint32_t mac_handle_id)
{
	status_t status = STATUS_SUCCESS;
	uint32_t tmsg[CLOSE_MAC_SESSION_SIZE] = { 0u };
	uint32_t rmsg[S3MU_RR_COUNT] = { 0u };

	tmsg[0] = CLOSE_MAC_SESSION; /* Close MAC session Command Header */
	tmsg[1] = mac_handle_id;     /* MAC handle ID */

	/* Send message Security Sub-System */
	status = s3mu_send_message(mu, tmsg, CLOSE_MAC_SESSION_SIZE);
	if (status != STATUS_SUCCESS)
		return status;

	/* Wait for response from Security Sub-System */
	status = ele_mu_get_response(mu, rmsg);
	if (status != STATUS_SUCCESS)
		return status;

	/* Check that response corresponds to the sent command */
	if (rmsg[0] == CLOSE_MAC_SESSION_RESPONSE_HDR &&
	    rmsg[1] == RESPONSE_SUCCESS)
		return STATUS_SUCCESS;

	return STATUS_FAIL;
}

status_t ele_mac(s3mu_t *mu, ele_mac_t *conf, uint16_t *out_mac_size)
{
	status_t status = STATUS_FAIL;
	uint32_t tmsg[MAC_ONE_GO_SIZE_PT_KEY] = { 0u };
	uint32_t rmsg[S3MU_RR_COUNT] = { 0u };
	size_t mac_one_go_size = 0u;
	uintptr_t payload_phys = 0;
	void *payload_addr = NULL;
	uintptr_t mac_phys = 0;
	void *mac_addr = NULL;
	uintptr_t key_phys = 0;
	void *key_addr = NULL;

	/* Check argument validity */
	if (!mu || !conf || !out_mac_size)
		return STATUS_INVALID_ARGUMENT;

	payload_addr =
		smw_utils_shared_memory_alloc(conf->payload, conf->payload_size,
					      &payload_phys);
	if (!payload_addr)
		goto end;

	mac_addr = smw_utils_shared_memory_alloc(conf->mac, conf->mac_size,
						 &mac_phys);
	if (!mac_addr)
		goto end;

	tmsg[1] = conf->mac_handle_id;
	if (SET_OVERFLOW(payload_phys, tmsg[3]) ||
	    SET_OVERFLOW(mac_phys, tmsg[4]))
		goto end;

	tmsg[5] = conf->payload_size;
	tmsg[6] = (uint32_t)conf->mode << SHIFT_16 |
		  conf->mac_size;      /* Flags | MAC size */
	tmsg[7] = (uint32_t)conf->alg; /* Algorithm identifier */
	tmsg[9] = 0x00000000u;	       /* Reserved */
	tmsg[10] = 0x00000000u;	       /* Reserved */
	tmsg[11] = 0x00000000u;	       /* Reserved */

	if (conf->mode & MAC_USE_PLAIN_KEY_BUFFER) {
		if (!conf->key) {
			status = STATUS_INVALID_ARGUMENT;
			goto end;
		}

		key_addr =
			smw_utils_shared_memory_alloc(conf->key, conf->key_size,
						      &key_phys);
		if (!key_addr)
			goto end;

		/* MAC_ONE_GO wit Plaintext key Command Header */
		tmsg[0] = MAC_ONE_GO_PT_KEY;
		if (SET_OVERFLOW(key_phys, tmsg[2]))
			goto end;

		tmsg[8] = (uint32_t)conf->key_type << SHIFT_16 |
			  conf->key_size; /* Key type and size in bits */
		tmsg[12] =
			s3mu_compute_msg_crc(tmsg, MAC_ONE_GO_SIZE_PT_KEY - 1u);
		mac_one_go_size = MAC_ONE_GO_SIZE_PT_KEY;
	} else {
		if (conf->key_id == 0u) {
			status = STATUS_INVALID_ARGUMENT;
			goto end;
		}

		/* MAC_ONE_GO Command Header */
		tmsg[0] = MAC_ONE_GO;
		tmsg[2] = conf->key_id;
		tmsg[8] = s3mu_compute_msg_crc(tmsg, MAC_ONE_GO_SIZE - 1u);
		mac_one_go_size = MAC_ONE_GO_SIZE;
	}

	/* Send message Security Sub-System */
	status = s3mu_send_message(mu, tmsg, mac_one_go_size);
	if (status != STATUS_SUCCESS)
		goto end;

	/* Wait for response from Security Sub-System */
	if (ele_mu_get_response(mu, rmsg) != STATUS_SUCCESS)
		goto end;

	/* Check that response corresponds to the sent command */
	if (rmsg[0] != MAC_ONE_GO_RESPONSE_HDR) {
		status = STATUS_FAIL;
		goto end;
	}

	/* Header OK, check for success */
	if (rmsg[1] == RESPONSE_SUCCESS) {
		/* Checking verification status has meaning only for MAC_VERIFY mode */
		status = STATUS_SUCCESS;
		if (conf->mode == MAC_VERIFY)
			/* check verification status from ELE */
			if (rmsg[2] != MAC_VERIFY_SUCCESS)
				status = STATUS_INVALID_SIGNATURE;

		/* Return the output MAC size field from the response */
		*out_mac_size = (uint16_t)(rmsg[3] & MAC_ONE_GO_MAC_SIZE_MASK);

		if (conf->mode == MAC_GENERATE)
			smw_utils_dcache_invalidate(conf->mac, *out_mac_size);
	} else if (rmsg[1] == RESPONSE_ERROR_SIZE) {
		/* Return the expected size and fail with error */
		status = STATUS_ELE_BUFFER_TOO_SMALL;
		*out_mac_size = (uint16_t)(rmsg[3] & MAC_ONE_GO_MAC_SIZE_MASK);
	} else {
		status = STATUS_FAIL;
	}

end:
	if (mac_addr)
		smw_utils_shared_memory_free(mac_addr, conf->mac_size,
					     conf->mac);

	if (payload_addr)
		smw_utils_shared_memory_free(payload_addr, conf->payload_size,
					     NULL);

	if (key_addr)
		smw_utils_shared_memory_free(key_addr, conf->key_size, NULL);

	return status;
}

status_t ele_fast_mac_start(s3mu_t *mu, const uint8_t *key)
{
	status_t status = STATUS_SUCCESS;
	uint32_t tmsg[FAST_MAC_START_SIZE] = { 0u };
	uint32_t rmsg[S3MU_RR_COUNT] = { 0u };
	size_t key_size = 32u; /* 256 bit key size in bytes */
	uintptr_t key_phys = 0;
	void *key_addr =
		smw_utils_shared_memory_alloc((void *)key, key_size, &key_phys);

	if (!key_addr)
		return STATUS_FAIL;

	tmsg[0] = FAST_MAC_START; /* FAST_MAC_START Command Header */
	if (SET_OVERFLOW(key_phys, tmsg[1])) {
		status = STATUS_FAIL;
		goto end;
	}

	tmsg[2] = 0x0u; /* Reserved */
	tmsg[3] = 0x0u; /* Reserved */

	/* Send message Security Sub-System */
	status = s3mu_send_message(mu, tmsg, FAST_MAC_START_SIZE);
	if (status != STATUS_SUCCESS)
		goto end;

	/* Wait for response from Security Sub-System */
	status = ele_mu_get_response(mu, rmsg);
	if (status != STATUS_SUCCESS)
		goto end;

	/* Check that response corresponds to the sent command */
	if (rmsg[0] == FAST_MAC_START_RESPONSE_HDR &&
	    rmsg[1] == RESPONSE_SUCCESS)
		status = STATUS_SUCCESS;
	else
		status = STATUS_FAIL;

end:
	smw_utils_shared_memory_free(key_addr, key_size, NULL);

	return status;
}

status_t ele_fast_mac_proceed(s3mu_t *mu, const uint8_t *msg, uint8_t *mac,
			      uint16_t msg_size, uint16_t flags,
			      uint32_t *verif_status)
{
	status_t status = STATUS_FAIL;
	uint32_t tmsg[FAST_MAC_PROCEED_SIZE] = { 0u };
	uint32_t rmsg[S3MU_RR_COUNT] = { 0u };
	size_t mac_size = 32u;
	uintptr_t msg_phys = 0;
	void *msg_addr =
		smw_utils_shared_memory_alloc(msg, msg_size, &msg_phys);
	uintptr_t mac_phys = 0;
	void *mac_addr =
		smw_utils_shared_memory_alloc(mac, mac_size, &mac_phys);

	if (!msg_addr || !mac_addr)
		goto end;

	tmsg[0] = FAST_MAC_PROCEED; /* FAST_MAC_PROCEED Command Header */
	if (SET_OVERFLOW(msg_phys, tmsg[1]) || SET_OVERFLOW(mac_phys, tmsg[2]))
		goto end;

	tmsg[3] = ((uint32_t)flags << 16u) | (uint32_t)msg_size;

	/* Send message Security Sub-System */
	status = s3mu_send_message(mu, tmsg, FAST_MAC_PROCEED_SIZE);
	if (status != STATUS_SUCCESS)
		goto end;

	/* Wait for response from Security Sub-System */
	status = ele_mu_get_response(mu, rmsg);
	if (status != STATUS_SUCCESS)
		goto end;

	if (verif_status)
		*verif_status = rmsg[2];

	/* Check that response corresponds to the sent command */
	if (rmsg[0] == FAST_MAC_PROCEED_RESPONSE_HDR &&
	    rmsg[1] == RESPONSE_SUCCESS) {
		smw_utils_dcache_invalidate(mac, 32u);

		status = STATUS_SUCCESS;
	} else {
		status = STATUS_FAIL;
	}

end:
	smw_utils_shared_memory_free(msg_addr, msg_size, NULL);
	smw_utils_shared_memory_free(mac_addr, mac_size, mac);

	return status;
}

status_t ele_fast_mac_end(s3mu_t *mu)
{
	status_t status = STATUS_SUCCESS;
	uint32_t tmsg[FAST_MAC_END_SIZE] = { 0u };
	uint32_t rmsg[S3MU_RR_COUNT] = { 0u };

	tmsg[0] = FAST_MAC_END; /* FAST_MAC_END Command Header */
	/* Send message Security Sub-System */
	status = s3mu_send_message(mu, tmsg, FAST_MAC_END_SIZE);
	if (status != STATUS_SUCCESS)
		return status;

	/* Wait for response from Security Sub-System */
	status = ele_mu_get_response(mu, rmsg);
	if (status != STATUS_SUCCESS)
		return status;

	/* Check that response corresponds to the sent command */
	if (rmsg[0] == FAST_MAC_END_RESPONSE_HDR && rmsg[1] == RESPONSE_SUCCESS)
		return STATUS_SUCCESS;

	return STATUS_FAIL;
}
