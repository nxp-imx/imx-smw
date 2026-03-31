/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2026 NXP
 */

#ifndef __ELE_RNG_H__
#define __ELE_RNG_H__

#include "ele_common.h"

/*******************************************************************************
 * Random Number Generator
 ******************************************************************************/

/**
 * ele_trng_state_t - ELE TRNG State
 * kELE_TRNG_program: TRNG is in program mode, which means TRNG is being configured
 *                    and not generating entropy yet
 * kELE_TRNG_generate: TRNG is still generating entropy,
 *                     which means TRNG is configured but entropy is not ready yet
 * kELE_TRNG_ready: TRNG entropy is valid and ready to be read
 * kELE_TRNG_error: TRNG encounter an error while generating
 */
typedef enum _ele_trng_state_t {
	kELE_TRNG_program = 0x1u,
	kELE_TRNG_generate = 0x2u,
	kELE_TRNG_ready = 0x3u,
	kELE_TRNG_error = 0x4u,
} ele_trng_state_t;

/**
 * ele_trng_csal_state_t- ELE TRNG CSAL (Cryptolib) context state
 * kELE_TRNG_CSAL_not_ready: Crypto Lib random context initialization is not done yet
 * kELE_TRNG_CSAL_busy: Crypto Lib random context initialization is on-going
 * kELE_TRNG_CSAL_success: Crypto Lib random context initialization succeed
 * kELE_TRNG_CSAL_fail: Crypto Lib random context initialization failed
 * kELE_TRNG_CSAL_pause: Crypto Lib random context initialization is in pause mode
 */
typedef enum _ele_trng_csal_state_t {
	kELE_TRNG_CSAL_not_ready = 0x0u,
	kELE_TRNG_CSAL_busy = 0x1u,
	kELE_TRNG_CSAL_success = 0x2u,
	kELE_TRNG_CSAL_fail = 0x3u,
	kELE_TRNG_CSAL_pause = 0x4u,
} ele_trng_csal_state_t;

/**
 * rng_reseed_flag_t - RNG reseed flags
 * kNoReseed: Do not reseed RNG
 * kReseedNonBlocking: If ELE is not ready to reseed, return failure
 * kReseedBlocking: If ELE is not ready to reseed, wait until ready
 */
typedef enum _rng_reseed_flag_t {
	kNoReseed = 0x0u,
	kReseedNonBlocking = 0x1u,
	kReseedBlocking = 0x2u,
} rng_reseed_flag_t;

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
			    rng_reseed_flag_t reseed_flag);

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
status_t ele_start_rng(s3mu_t *mu);

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
status_t ele_get_trng_state(s3mu_t *mu, uint32_t *state);

#endif /* __ELE_RNG_H__ */
