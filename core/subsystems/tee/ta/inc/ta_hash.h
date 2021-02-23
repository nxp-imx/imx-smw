/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2021 NXP
 */

#ifndef TA_HASH_H
#define TA_HASH_H

/**
 * hash() - Hash a message.
 * @param_types: Parameters types.
 * @params: Shared parameters between Secure and Normal world.
 *
 * Return:
 * TEE_SUCCESS			- Success.
 * TEE_ERROR_BAD_PARAMETERS	- One of the parameters is invalid.
 * Error code from internal functions.
 */
TEE_Result hash(uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS]);

/**
 * ta_get_digest_length() - Get digest length.
 * @tee_algorithm_id: Hash algorithm ID.
 * @digest_len: Pointer to the digest length.
 *
 * If @hash points to NULL address, it is allocated by ta_compute_digest() and
 * caller has to free memory.
 *
 * Return:
 * TEE_SUCCESS			- Success.
 * TEE_ERROR_BAD_PARAMETERS	- One of the parameters is invalid.
 * TEE_ERROR_NOT_SUPPORTED	- Hash algorithm is not supported.
 */
TEE_Result ta_get_digest_length(enum tee_algorithm_id tee_algorithm_id,
				uint32_t *digest_len);

/**
 * ta_compute_digest() - Compute a digest.
 * @tee_algorithm_id: Hash algorithm ID.
 * @chunk: Address of data to be hashed.
 * @chunk_len: Length of @chunk.
 * @hash: Pointer to the output buffer filled with the message hash.
 * @hash_len: Pointer to @hash length in bytes. Not updated if function failed.
 *
 * If @hash points to NULL address, it is allocated by ta_compute_digest() and
 * caller has to free memory.
 *
 * Return:
 * TEE_SUCCESS			- Success.
 * TEE_ERROR_BAD_PARAMETERS	- One of the parameters is invalid.
 * Error code from internal functions.
 */
TEE_Result ta_compute_digest(enum tee_algorithm_id tee_algorithm_id,
			     const void *chunk, uint32_t chunk_len, void **hash,
			     uint32_t *hash_len);

#endif /* TA_HASH_H */
