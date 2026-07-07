// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include "ele_rng.h"
#include "ele_crypto_internal.h"

#include "utils_ex.h"

status_t ele_rng_get_random(s3mu_t *mu, uint32_t *output, size_t size,
			    rng_reseed_flag_t reseed_flag)
{
	status_t status = STATUS_SUCCESS;
	uint32_t tmsg[GET_RNG_RANDOM_SIZE] = { 0u };
	uint32_t rmsg[S3MU_RR_COUNT] = { 0u };
	uintptr_t output_phys = 0;
	void *output_addr =
		smw_utils_shared_memory_alloc(output, size, &output_phys);

	if (!output_addr)
		return STATUS_FAIL;

	tmsg[0] = GET_RNG_RANDOM; /* GET_RNG_RANDOM Command Header */
	tmsg[1] = (uint16_t)reseed_flag << SHIFT_16; /* Reseed flag */
	if (SET_OVERFLOW(output_phys, tmsg[2]) || SET_OVERFLOW(size, tmsg[3])) {
		status = STATUS_FAIL;
		goto end;
	}

	/* Send message Security Sub-System */
	status = s3mu_send_message(mu, tmsg, GET_RNG_RANDOM_SIZE);
	if (status != STATUS_SUCCESS)
		goto end;

	/* Wait for response from Security Sub-System */
	status = s3mu_get_response(mu, rmsg);
	if (status != STATUS_SUCCESS)
		goto end;

	/* Check that response corresponds to the sent command */
	if (rmsg[0] == GET_RNG_RANDOM_RESPONSE_HDR &&
	    rmsg[1] == RESPONSE_SUCCESS) {
		smw_utils_dcache_invalidate(output_addr, size);
		status = STATUS_SUCCESS;
	} else {
		status = STATUS_FAIL;
	}

end:
	smw_utils_shared_memory_free(output_addr, size, output);
	return status;
}

status_t ele_start_rng(s3mu_t *mu)
{
	status_t status = STATUS_SUCCESS;
	uint32_t tmsg[START_RNG_SIZE] = { 0u };
	uint32_t rmsg[S3MU_RR_COUNT] = { 0u };

	/****************** Start RNG ***********************/
	tmsg[0] = START_RNG; /* Start RNG message Command Header */

	/* Send message to Security Sub-System */
	status = s3mu_send_message(mu, tmsg, START_RNG_SIZE);
	if (status != STATUS_SUCCESS)
		return status;

	/* Wait for response from Security Sub-System */
	status = ele_mu_get_response(mu, rmsg);
	if (status != STATUS_SUCCESS)
		return status;

	/* Check that response corresponds to the sent command */
	if (rmsg[0] == START_RNG_RESPONSE_HDR && rmsg[1] == RESPONSE_SUCCESS)
		return STATUS_SUCCESS;

	return STATUS_FAIL;
}

status_t ele_get_trng_state(s3mu_t *mu, uint32_t *state)
{
	status_t status = STATUS_SUCCESS;
	uint32_t tmsg[GET_TRNG_STATE_SIZE] = { 0u };
	uint32_t rmsg[S3MU_RR_COUNT] = { 0u };

	/****************** Get info message ***********************/
	tmsg[0] = GET_TRNG_STATE; /* Get trng state message Command Header */

	/* Send message Security Sub-System */
	status = s3mu_send_message(mu, tmsg, GET_TRNG_STATE_SIZE);
	if (status != STATUS_SUCCESS)
		return status;

	/* Wait for response from Security Sub-System */
	status = ele_mu_get_response(mu, rmsg);
	if (status != STATUS_SUCCESS)
		return status;

	/* Check that response corresponds to the sent command */
	if (rmsg[0] == GET_TRNG_STATE_RESPONSE_HDR &&
	    rmsg[1] == RESPONSE_SUCCESS) {
		*state = rmsg[2];
		return STATUS_SUCCESS;
	}

	return STATUS_FAIL;
}
