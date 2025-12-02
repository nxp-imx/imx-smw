/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2026 NXP
 */

#ifndef __SMW_CRYPTO_RNG_H__
#define __SMW_CRYPTO_RNG_H__

/**
 * struct smw_rng_args - Random number generator arguments
 * @version: [in] Version of this structure.
 * @subsystem_name: [in] Secure Subsystem name. See &typedef smw_subsystem_t.
 * @output: [out] Pointer to the random number buffer generated.
 * @output_length: [in] Length in bytes of the random number buffer to generate.
 *
 * The @subsystem_name designates the Secure Subsystem to be used.
 * If this field is :ref:`SMW_SUBSYSTEM_NAME_NONE <smw_subsystem_t>`,
 * the default configured Secure Subsystem is used.
 */
struct smw_rng_args {
	unsigned char version;
	smw_subsystem_t subsystem_name;
	unsigned char *output;
	unsigned int output_length;
};

/**
 * smw_rng() - Compute a random number.
 * @args: Pointer to the structure that contains the RNG arguments.
 *
 * This function computes a random number.
 *
 * Return:
 *  - SMW_STATUS_OK:
 *      Random number generated successfully.
 *  - SMW_STATUS_INVALID_PARAM:
 *      - @arg is NULL.
 *      - @arg->output is NULL.
 *      - @arg->output_length is 0.
 *      - Additional invalid parameters returned by the subsystem.
 *  - Other error code from &enum smw_status_code
 */
enum smw_status_code smw_rng(struct smw_rng_args *args);

#endif /* __SMW_CRYPTO_RNG_H__ */
