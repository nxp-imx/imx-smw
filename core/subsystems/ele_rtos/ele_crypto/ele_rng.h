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
 * ELE_TRNG_PROGRAM: TRNG is in program mode, which means TRNG is being configured
 *                    and not generating entropy yet
 * ELE_TRNG_GENERATE: TRNG is still generating entropy,
 *                     which means TRNG is configured but entropy is not ready yet
 * ELE_TRNG_READY: TRNG entropy is valid and ready to be read
 * ELE_TRNG_ERROR: TRNG encounter an error while generating
 */
typedef enum {
	ELE_TRNG_PROGRAM = 0x1u,
	ELE_TRNG_GENERATE = 0x2u,
	ELE_TRNG_READY = 0x3u,
	ELE_TRNG_ERROR = 0x4u,
} ele_trng_state_t;

/**
 * ele_trng_csal_state_t- ELE TRNG CSAL (Cryptolib) context state
 * ELE_TRNG_CSAL_NOT_READY: Crypto Lib random context initialization is not done yet
 * ELE_TRNG_CSAL_BUSY: Crypto Lib random context initialization is on-going
 * ELE_TRNG_CSAL_SUCCESS: Crypto Lib random context initialization succeed
 * ELE_TRNG_CSAL_FAIL: Crypto Lib random context initialization failed
 * ELE_TRNG_CSAL_PAUSE: Crypto Lib random context initialization is in pause mode
 */
typedef enum {
	ELE_TRNG_CSAL_NOT_READY = 0x0u,
	ELE_TRNG_CSAL_BUSY = 0x1u,
	ELE_TRNG_CSAL_SUCCESS = 0x2u,
	ELE_TRNG_CSAL_FAIL = 0x3u,
	ELE_TRNG_CSAL_PAUSE = 0x4u,
} ele_trng_csal_state_t;

/**
 * rng_reseed_flag_t - RNG reseed flags
 * NORESEED: Do not reseed RNG
 * RESEEDNONBLOCKING: If ELE is not ready to reseed, return failure
 * RESEEDBLOCKING: If ELE is not ready to reseed, wait until ready
 */
typedef enum {
	NORESEED = 0x0u,
	RESEEDNONBLOCKING = 0x1u,
	RESEEDBLOCKING = 0x2u,
} rng_reseed_flag_t;

/**
 * ele_rng_get_random() - ELE RNG Get random
 * @mu: MU peripheral base address
 * @output: Pointer to output buffer where to store random number
 * @size: Size of requested random data
 * @reseed_flag: Option to reseed the DRBG instance
 *
 * This function gets random number from ELE RNG.
 *
 * Return:
 * Status_Success                  - Success
 * Status_Fail                     - Fail
 * Status_S3MU_InvalidArgument     - Invalid argument parameter
 * Status_S3MU_AgumentOutOfRange   - Argument out of range
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
 * Status_Success                  - Success
 * Status_Fail                     - Fail
 * Status_S3MU_InvalidArgument     - Invalid argument parameter
 * Status_S3MU_AgumentOutOfRange   - Argument out of range
 */
status_t ele_start_rng(s3mu_t *mu);

/**
 * ele_get_trng_state() - Get TRNG State
 * @mu: MU peripheral base address
 * @state: Output buffer where response data will be writen, user must ensure at least 4 bytes
 *         available. Lower byte map to TRNG state, upper byte to CSAL (Cryptolib) context state.
 *
 * This command is used to get TRNG state from ELE.
 *
 * Return:
 * Status_Success                  - Success
 * Status_Fail                     - Fail
 * Status_S3MU_InvalidArgument     - Invalid argument parameter
 * Status_S3MU_AgumentOutOfRange   - Argument out of range
 */
status_t ele_get_trng_state(s3mu_t *mu, uint32_t *state);

#endif /* __ELE_RNG_H__ */
