// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include "ele_rng.h"
#include "ele_crypto_internal.h"

#include "utils_ex.h"

/**
 * ele_rng_get_random() - ELE RNG Get random
 * @mu: MU peripheral base address
 * @output: pointer to output buffer where to store random number
 * @size: size of requested random data
 * @reseed_flag: option to reseed the DRBG instance
 *
 * This function gets random number from ELE RNG.
 *
 * Return:
 * kStatus_Success                  - Success
 * kStatus_Fail                     - Fail
 * kStatus_S3MU_InvalidArgument     - Invalid argument parameter
 * kStatus_S3MU_AgumentOutOfRange   - Argument out of range
 */
status_t ele_rng_get_random(s3mu_t *mu, uint32_t *output, size_t size,
			    rng_reseed_flag_t reseed_flag)
{
	status_t status = kStatus_Success;
	uint32_t tmsg[GET_RNG_RANDOM_SIZE] = { 0u };
	uint32_t rmsg[S3MU_RR_COUNT] = { 0u };
	uintptr_t output_phys = 0;
	void *output_addr =
		smw_utils_shared_memory_alloc(output, size, &output_phys);

	tmsg[0] = GET_RNG_RANDOM; // GET_RNG_RANDOM Command Header
	tmsg[1] = (uint16_t)reseed_flag << SHIFT_16; // Reseed flag
	tmsg[2] = output_phys;			     // Output buffer address
	tmsg[3] = size;				     // Size of requested data

	/* Send message Security Sub-System */
	status = s3mu_send_message(mu, tmsg, GET_RNG_RANDOM_SIZE);
	if (status != kStatus_Success)
		goto end;

	/* Wait for response from Security Sub-System */
	status = s3mu_get_response(mu, rmsg);
	if (status != kStatus_Success)
		goto end;

	/* Check that response corresponds to the sent command */
	if (rmsg[0] == GET_RNG_RANDOM_RESPONSE_HDR &&
	    rmsg[1] == RESPONSE_SUCCESS) {
		smw_utils_dcache_invalidate(output_addr, size);
		status = kStatus_Success;
	} else {
		status = kStatus_Fail;
	}

end:
	smw_utils_shared_memory_free(output_addr, size, output);
	return status;
}

/**
 * ele_start_rng() - Start the initialization of the RNG context.
 * @mu: MU peripheral base address
 *
 * The RNG must be started before using some of the ELE services.
 *
 * Return:
 * kStatus_Success                  - Success
 * kStatus_Fail                     - Fail
 * kStatus_S3MU_InvalidArgument     - Invalid argument parameter
 * kStatus_S3MU_AgumentOutOfRange   - Argument out of range
 */
status_t ele_start_rng(s3mu_t *mu)
{
	status_t status = kStatus_Success;
	uint32_t tmsg[START_RNG_SIZE] = { 0u };
	uint32_t rmsg[S3MU_RR_COUNT] = { 0u };

	/****************** Start RNG ***********************/
	tmsg[0] = START_RNG; // Start RNG message Command Header

	/* Send message to Security Sub-System */
	status = s3mu_send_message(mu, tmsg, START_RNG_SIZE);
	if (status != kStatus_Success)
		return status;

	/* Wait for response from Security Sub-System */
	status = ele_mu_get_response(mu, rmsg);
	if (status != kStatus_Success)
		return status;

	/* Check that response corresponds to the sent command */
	if (rmsg[0] == START_RNG_RESPONSE_HDR && rmsg[1] == RESPONSE_SUCCESS)
		return kStatus_Success;

	return kStatus_Fail;
}

/**
 * ele_get_trng_state() - Get TRNG State
 * @mu: MU peripheral base address
 * @state: output buffer where response data will be writen, user must ensure at least 4 bytes
 *         available. Lower byte map to TRNG state, upper byte to CSAL (Cryptolib) context state.
 *
 * This command is used to get TRNG state from ELE.
 *
 * Return:
 * kStatus_Success                  - Success
 * kStatus_Fail                     - Fail
 * kStatus_S3MU_InvalidArgument     - Invalid argument parameter
 * kStatus_S3MU_AgumentOutOfRange   - Argument out of range
 */
status_t ele_get_trng_state(s3mu_t *mu, uint32_t *state)
{
	status_t status = kStatus_Success;
	uint32_t tmsg[GET_TRNG_STATE_SIZE] = { 0u };
	uint32_t rmsg[S3MU_RR_COUNT] = { 0u };

	/****************** Get info message ***********************/
	tmsg[0] = GET_TRNG_STATE; // Get trng state message Command Header

	/* Send message Security Sub-System */
	status = s3mu_send_message(mu, tmsg, GET_TRNG_STATE_SIZE);
	if (status != kStatus_Success)
		return status;

	/* Wait for response from Security Sub-System */
	status = ele_mu_get_response(mu, rmsg);
	if (status != kStatus_Success)
		return status;

	/* Check that response corresponds to the sent command */
	if (rmsg[0] == GET_TRNG_STATE_RESPONSE_HDR &&
	    rmsg[1] == RESPONSE_SUCCESS) {
		*state = rmsg[2];
		return kStatus_Success;
	}

	return kStatus_Fail;
}
