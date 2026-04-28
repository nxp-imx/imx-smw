/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2021, 2023-2026 NXP
 */

#ifndef __HASH_H__
#define __HASH_H__

#include "config.h"
#include "operation_step.h"
#include "operation_context.h"

#define SMW_HASH_BLOCK_SIZE_SHA1   64
#define SMW_HASH_BLOCK_SIZE_SHA224 64
#define SMW_HASH_BLOCK_SIZE_SHA256 64
#define SMW_HASH_BLOCK_SIZE_SHA384 128
#define SMW_HASH_BLOCK_SIZE_SHA512 128

#define SMW_HASH_DIGEST_SIZE_SHA1   20
#define SMW_HASH_DIGEST_SIZE_SHA224 28
#define SMW_HASH_DIGEST_SIZE_SHA256 32
#define SMW_HASH_DIGEST_SIZE_SHA384 48
#define SMW_HASH_DIGEST_SIZE_SHA512 64

#define SMW_HASH_PAD_LENGTH_SHA1   8
#define SMW_HASH_PAD_LENGTH_SHA224 8
#define SMW_HASH_PAD_LENGTH_SHA256 8
#define SMW_HASH_PAD_LENGTH_SHA384 16
#define SMW_HASH_PAD_LENGTH_SHA512 16

#define SMW_HASH_INTERMEDIATE_SIZE_SHA1                                        \
	(SMW_HASH_DIGEST_SIZE_SHA1 / sizeof(uint32_t))
#define SMW_HASH_INTERMEDIATE_SIZE_SHA224                                      \
	(SMW_HASH_DIGEST_SIZE_SHA256 / sizeof(uint32_t))
#define SMW_HASH_INTERMEDIATE_SIZE_SHA256                                      \
	(SMW_HASH_DIGEST_SIZE_SHA256 / sizeof(uint32_t))
#define SMW_HASH_INTERMEDIATE_SIZE_SHA384                                      \
	(SMW_HASH_DIGEST_SIZE_SHA512 / sizeof(uint32_t))
#define SMW_HASH_INTERMEDIATE_SIZE_SHA512                                      \
	(SMW_HASH_DIGEST_SIZE_SHA512 / sizeof(uint32_t))

union smw_hash_intermediate {
	uint32_t sha1[SMW_HASH_INTERMEDIATE_SIZE_SHA1];
	uint32_t sha224[SMW_HASH_INTERMEDIATE_SIZE_SHA224];
	uint32_t sha256[SMW_HASH_INTERMEDIATE_SIZE_SHA256];
	uint32_t sha384[SMW_HASH_INTERMEDIATE_SIZE_SHA384];
	uint32_t sha512[SMW_HASH_INTERMEDIATE_SIZE_SHA512];
};

union smw_hash_block {
	uint8_t sha1[SMW_HASH_BLOCK_SIZE_SHA1];
	uint8_t sha224[SMW_HASH_BLOCK_SIZE_SHA224];
	uint8_t sha256[SMW_HASH_BLOCK_SIZE_SHA256];
	uint8_t sha384[SMW_HASH_BLOCK_SIZE_SHA384];
	uint8_t sha512[SMW_HASH_BLOCK_SIZE_SHA512];
};

/**
 * struct smw_hash_context - Hash context
 * @hash_id: Hash algorithm ID
 * @intermediate: Intermediate hash
 * @block: Message block remainder
 * @block_length: Length of message block remainder in bytes
 * @message_length: Total length of the message in bits
 */
struct smw_hash_context {
	enum smw_config_hash_algo_id hash_id;
	union smw_hash_intermediate intermediate;
	union smw_hash_block block;
	unsigned int block_length;
	unsigned long long message_length;
};

/**
 * struct smw_crypto_hash_args - Hash arguments
 * @algo_id: Algorithm ID
 * @op_step: Multi-part operation step
 * @one_shot_pub: Pointer to the public API one-shot arguments structure
 * @init_pub: Pointer to the public API initialization arguments structure
 * @update_pub: Pointer to the public API update arguments structure
 * @final_pub: Pointer to the public API final arguments structure
 *
 */
struct smw_crypto_hash_args {
	/* Inputs */
	enum smw_config_hash_algo_id algo_id;
	enum smw_op_step op_step;
	union {
		struct smw_hash_args *oneshot_pub;
		struct smw_hash_init_args *init_pub;
		struct smw_hash_update_args *update_pub;
		struct smw_hash_final_args *final_pub;
	};
};

/**
 * smw_crypto_get_hash_input_data() - Return the address of the Hash input buffer.
 * @args: Pointer to the internal Hash args structure.
 *
 * This function returns the address of the Hash input buffer.
 *
 * Return:
 * NULL
 * address of the Hash input buffer.
 */
unsigned char *
smw_crypto_get_hash_input_data(struct smw_crypto_hash_args *args);

/**
 * smw_crypto_get_hash_input_length() - Return the length of the Hash input buffer.
 * @args: Pointer to the internal Hash args structure.
 *
 * This function returns the length of the Hash input buffer.
 *
 * Return:
 * 0
 * length of the Hash input buffer.
 */
unsigned int
smw_crypto_get_hash_input_length(struct smw_crypto_hash_args *args);

/**
 * smw_crypto_get_hash_output_data() - Return the address of the Hash output buffer.
 * @args: Pointer to the internal Hash args structure.
 *
 * This function returns the address of the Hash output buffer.
 *
 * Return:
 * NULL
 * address of the Hash output buffer.
 */
unsigned char *
smw_crypto_get_hash_output_data(struct smw_crypto_hash_args *args);

/**
 * smw_crypto_get_hash_output_length() - Return the length of the Hash output buffer.
 * @args: Pointer to the internal Hash args structure.
 *
 * This function returns the length of the Hash output buffer.
 *
 * Return:
 * 0
 * length of the Hash output buffer.
 */
unsigned int
smw_crypto_get_hash_output_length(struct smw_crypto_hash_args *args);

/**
 * smw_crypto_set_hash_output_length() - Set the length of the Hash output buffer.
 * @args: Pointer to the internal Hash args structure.
 * @output_length: Length of the Hash output buffer.
 *
 * This function sets the length of the Hash output buffer.
 *
 * Return:
 * none.
 */
void smw_crypto_set_hash_output_length(struct smw_crypto_hash_args *args,
				       unsigned int output_length);

/**
 * smw_crypto_get_hash_op_context() - Get Hash operation context pointer
 * @args: Pointer to internal Hash arguments.
 *
 * Return:
 * Address of Hash operation context structure
 */
struct smw_op_context *
smw_crypto_get_hash_op_context(struct smw_crypto_hash_args *args);

/**
 * smw_utils_hash() - Hash one-shot.
 * @hash_id: Hash algorithm ID.
 * @input: Location of the stream to be hashed.
 * @input_length: Length of the stream to be hashed.
 * @digest: Location where the digest has to be written.
 * @digest_length: Length of the digest.
 *
 * This function computes a hash.
 *
 * Return:
 * SMW_STATUS_OK                        - Success.
 * SMW_STATUS_INVALID_PARAM             - One of the parameter is invalid.
 * SMW_STATUS_OPERATION_NOT_SUPPORTED   - Hash algorithm not supported.
 */
int smw_utils_hash(enum smw_config_hash_algo_id hash_id, unsigned char *input,
		   unsigned int input_length, unsigned char *digest,
		   unsigned int *digest_length);

/**
 * smw_utils_hash_init() - Initialize hash multi-part.
 * @hash_id: Hash algorithm ID.
 * @context: Pointer to operation context arguments structure.
 *
 * This function intializes hash multi-part.
 *
 * Return:
 * SMW_STATUS_OK                        - Success.
 * SMW_STATUS_INVALID_PARAM             - One of the parameter is invalid.
 * SMW_STATUS_OPERATION_NOT_SUPPORTED   - Hash algorithm not supported.
 */
int smw_utils_hash_init(enum smw_config_hash_algo_id hash_id,
			struct smw_hash_context *context);

/**
 * smw_utils_hash_update() - Update hash multi-part.
 * @context: Pointer to operation context arguments structure.
 * @input: Location of the stream to be hashed.
 * @input_length: Length of the stream to be hashed.
 *
 * This function updates hash multi-part.
 *
 * Return:
 * SMW_STATUS_OK                        - Success.
 * SMW_STATUS_INVALID_PARAM             - One of the parameter is invalid.
 * SMW_STATUS_OPERATION_NOT_SUPPORTED   - Hash algorithm not supported.
 */
int smw_utils_hash_update(struct smw_hash_context *context,
			  const uint8_t *input, unsigned int input_length);

/**
 * smw_utils_hash_final() - Finalize hash multi-part.
 * @context: Pointer to operation context arguments structure.
 * @input: Location of the stream to be hashed.
 * @input_length: Length of the stream to be hashed.
 * @digest: Location where the digest has to be written.
 * @digest_length: Length of the digest.
 *
 * This function finalizes hash multi-part.
 *
 * Return:
 * SMW_STATUS_OK                        - Success.
 * SMW_STATUS_INVALID_PARAM             - One of the parameter is invalid.
 * SMW_STATUS_OPERATION_NOT_SUPPORTED   - Hash algorithm not supported.
 * SMW_STATUS_OUTPUT_TOO_SHORT          - Ouptut buffer is too short.
 */
int smw_utils_hash_final(struct smw_hash_context *context, const uint8_t *input,
			 unsigned int input_length, uint8_t *digest,
			 unsigned int *digest_length);

#endif /* __HASH_H__ */
