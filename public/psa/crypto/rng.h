/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2022-2026 NXP
 */

#ifndef __PSA_CRYPTO_RNG_H__
#define __PSA_CRYPTO_RNG_H__

/**
 * psa_generate_random() - Generate random bytes.
 * @output: [out] Output buffer for the generated data.
 * @output_size: [in] Number of bytes to generate and output.
 *
 * .. warning::
 *    This function can fail! Callers MUST check the return status and MUST NOT
 *    use the content of the @output buffer if the return status is not
 *    PSA_SUCCESS.
 *
 * Return:
 *  - PSA_SUCCESS
 *      Success. output contains @output_size bytes of generated random data.
 *  - PSA_ERROR_NOT_SUPPORTED
 *  - PSA_ERROR_INSUFFICIENT_ENTROPY
 *  - PSA_ERROR_INSUFFICIENT_MEMORY
 *  - PSA_ERROR_COMMUNICATION_FAILURE
 *  - PSA_ERROR_HARDWARE_FAILURE
 *  - PSA_ERROR_CORRUPTION_DETECTED
 *  - PSA_ERROR_BAD_STATE:
 *      The library has not been previously initialized by psa_crypto_init().
 */
psa_status_t psa_generate_random(uint8_t *output, size_t output_size);

#endif /* __PSA_CRYPTO_RNG_H__ */
