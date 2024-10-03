/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2021, 2023-2024 NXP
 */

#ifndef __HASH_H__
#define __HASH_H__

#include "config.h"
#include "exec.h"
#include "operation_context.h"

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

#endif /* __HASH_H__ */
