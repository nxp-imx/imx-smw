/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021 NXP
 */

/**
 * struct smw_crypto_rng_args - Random number generator arguments
 * @pub: Pointer to the public API arguments structure
 *
 */
struct smw_crypto_rng_args {
	/* Inputs */
	struct smw_rng_args *pub;
};

/**
 * smw_crypto_get_rng_output_data() - Return the address of the RNG output buffer.
 * @args: Pointer to the internal RNG args structure.
 *
 * This function returns the address of the RNG output buffer.
 *
 * Return:
 * NULL
 * address of the RNG output buffer.
 */
unsigned char *smw_crypto_get_rng_output_data(struct smw_crypto_rng_args *args);

/**
 * smw_crypto_get_rng_output_length() - Return the length of the RNG output buffer.
 * @args: Pointer to the internal RNG args structure.
 *
 * This function returns the length of the RNG output buffer.
 *
 * Return:
 * 0
 * length of the RNG output buffer.
 */
unsigned int smw_crypto_get_rng_output_length(struct smw_crypto_rng_args *args);
