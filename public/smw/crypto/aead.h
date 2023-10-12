/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2023 NXP
 */

#ifndef __SMW_AEAD_H__
#define __SMW_AEAD_H__

#include "smw_status.h"
#include "smw_strings.h"

/**
 * struct smw_aead_init_args - AEAD initialization arguments
 * @version: Version of this structure
 * @subsystem_name: Secure Subsystem name. See &typedef smw_subsystem_t
 * @key_desc: Pointer to a key descriptor object. See &struct smw_key_descriptor
 * @mode_name: AEAD mode name. See &typedef smw_aead_mode_t
 * @operation_name: AEAD operation name. See &typedef smw_aead_operation_t
 * @iv: Pointer to initialization vector
 * @iv_length: iv length in bytes
 * @aad_length: Additional authentication data length in bytes
 * @tag_length: Tag buffer length in bytes
 * @plaintext_length: Length in bytes of the data to encrypt
 * @context: Pointer to operation context. See &struct smw_op_context
 */
struct smw_aead_init_args {
	/* Inputs */
	unsigned char version;
	smw_subsystem_t subsystem_name;
	struct smw_key_descriptor *key_desc;
	smw_aead_mode_t mode_name;
	smw_aead_operation_t operation_name;
	unsigned char *iv;
	unsigned int iv_length;
	unsigned int aad_length;
	unsigned int tag_length;
	unsigned int plaintext_length;
	/* Output */
	struct smw_op_context *context;
};

/**
 * struct smw_aead_data_args - AEAD data arguments
 * @version: Version of this structure
 * @context: Pointer to operation context. See &struct smw_op_context
 * @input: Pointer to input data buffer to be encrypted or decrypted
 * @input_length: Input data buffer length in bytes
 * @output: Pointer to output buffer
 * @output_length: Output buffer length in bytes
 */
struct smw_aead_data_args {
	/* Inputs */
	unsigned char version;
	struct smw_op_context *context;
	unsigned char *input;
	unsigned int input_length;
	/* Output */
	unsigned char *output;
	unsigned int output_length;
};

/**
 * struct smw_aead_aad_args - Authentication Encryption AAD arguments
 * @version: Version of this structure
 * @aad: Pointer to additional authentication data
 * @aad_length: AAD length in bytes
 * @context: Pointer to operation context. See &struct smw_op_context
 */
struct smw_aead_aad_args {
	/* Inputs */
	unsigned char version;
	unsigned char *aad;
	unsigned int aad_length;
	struct smw_op_context *context;
};

/**
 * struct smw_aead_final_args - AEAD final arguments
 * @version: Version of this structure
 * @data: AEAD data arguments. See &struct smw_aead_data_args
 * @operation_name: AEAD operation name. See &typedef smw_aead_operation_t
 * @tag_length: Tag buffer length in bytes
 *
 */
struct smw_aead_final_args {
	/* Inputs */
	unsigned char version;
	struct smw_aead_data_args data;
	smw_aead_operation_t operation_name;
	/* Input output */
	unsigned int tag_length;
};

/**
 * struct smw_aead_args - AEAD one-shot arguments
 * @init: Initialization arguments. See &struct smw_aead_init_args
 * @data: Data arguments. See &struct smw_aead_data_args
 * @aad: Pointer to additional authentication data
 *
 * Field @context present in @init and @data is ignored.
 */
struct smw_aead_args {
	struct smw_aead_init_args init;
	struct smw_aead_data_args data;
	unsigned char *aad;
};

/**
 * smw_aead() - One-shot AEAD operation.
 * @args: Pointer to the structure that contains the AEAD one-shot arguments.
 *
 * This function executes one-shot AEAD encryption or decryption operation.
 *
 *  - One-shot AEAD encryption operation:
 *
 *    - This function encrypts a message and computes the tag.
 *
 *  - One-shot AEAD decryption operation:
 *
 *    - This function authenticates and decrypts the ciphertext.
 *    - If the computed tag does not match the supplied tag, the operation
 *      will be terminated.
 *    - The input data field of @args should be large enough to accommodate
 *      the ciphertext and the tag.
 *
 * Output data field of @args can be a NULL pointer to get the required output
 * buffer length. If this feature succeeds, returned error code is SMW_STATUS_OK.
 *
 * Output length @args field is updated to the correct value when:
 *
 *  - Output length is bigger than expected. In this case operation is succeeded.
 *  - Output length is shorter than expected. In this case operation failed and
 *    returned SMW_STATUS_OUTPUT_TOO_SHORT.
 *
 * If output data field of @args is not a NULL pointer, then
 *
 *  - For encryption operation, output length should be large enough to
 *    accommodate both the ciphertext and tag.
 *  - For decryption operation, output length should be large enough to
 *    accommodate the plaintext.
 *
 * Return:
 * See &enum smw_status_code
 *	- Common return codes
 */
enum smw_status_code smw_aead(struct smw_aead_args *args);

/**
 * smw_aead_init() - AEAD multi-part initialization.
 * @args: Pointer to the structure that contains the AEAD initialization
 * arguments.
 *
 * This function initializes AEAD multi-part encryption or decryption operation.
 *
 * Key used can be defined either as a buffer or as a key ID.
 *
 * Return:
 * See &enum smw_status_code
 *	- Common return codes
 */
enum smw_status_code smw_aead_init(struct smw_aead_init_args *args);

/**
 * smw_aead_update_add() - Add additional data to the AEAD operation.
 * @args: Pointer to the structure that contains the AEAD additional data
 *        arguments.
 *
 * This function can be called multiple time while the update data
 * (to encrypt or to decrypt) step is not called.
 *
 * The context used must be initialized by the AEAD multi-part initialization.
 *
 * Return:
 * See &enum smw_status_code
 *	- Common return codes
 */
enum smw_status_code smw_aead_update_add(struct smw_aead_aad_args *args);

/**
 * smw_aead_update() - AEAD multi-part update operation
 * @args: Pointer to the structure that contains the AEAD multi-part data
 *        arguments.
 *
 * This function executes a AEAD multi-part encryption or decryption update
 * operation.
 *
 * The context used must be initialized by the AEAD multi-part initialization.
 *
 * Output data field of @args can be a NULL pointer to get the required output
 * buffer length. If this feature succeeds, returned error code is SMW_STATUS_OK.
 *
 * Output length @args field is updated to the correct value when:
 *
 *  - Output length is bigger than expected. In this case operation succeeded.
 *  - Output length is shorter than expected. In this case operation failed and
 *    returned SMW_STATUS_OUTPUT_TOO_SHORT.
 *
 * If the returned error code is SMW_STATUS_OK, SMW_STATUS_INVALID_PARAM,
 * SMW_STATUS_VERSION_NOT_SUPPORTED or SMW_STATUS_OUTPUT_TOO_SHORT the operation
 * is not terminated and the context remains valid.
 *
 * Return:
 * See &enum smw_status_code
 *	- Common return codes
 */
enum smw_status_code smw_aead_update(struct smw_aead_data_args *args);

/**
 * smw_aead_final() - AEAD multi-part encryption/decryption final operation
 * @args: Pointer to the structure that contains the AEAD multi-part final
 *        arguments.
 *
 * This function completes the active AEAD multi-part encryption/decryption
 * operation.
 *
 * The context used must be initialized by the AEAD multi-part initialization.
 *
 *  - AEAD Encryption final operation:
 *
 *    - This function finishes encrypting a message in an active multi-part
 *      AEAD operation and computes the tag.
 *
 *  - AEAD Decryption final operation:
 *
 *    - This function finishes authenticating and decrypting a message in an
 *      active multi-part AEAD operation.
 *    - If the computed tag does not match the supplied tag, the operation will
 *      be terminated. The returned error code is SMW_STATUS_SIGNATURE_INVALID.
 *    - The input data field of @args should be large enough to accommodate
 *      the ciphertext and the tag.
 *
 * Output data field of @args can be a NULL pointer to get the required output
 * buffer length. If this feature succeeds, returned error code is SMW_STATUS_OK.
 * Output length @args field is updated to the correct value when:
 *
 *  - Output length is bigger than expected. In this case operation succeeded.
 *  - Output length is shorter than expected. In this case operation failed and
 *    returned SMW_STATUS_OUTPUT_TOO_SHORT.
 *
 * If output data field of @args is not a NULL pointer, then
 *
 *  - For encryption operation, output length should be large enough to
 *    accommodate both the plaintext and tag.
 *  - For decryption operation, output length should be large enough to
 *    accommodate the plaintext.
 *
 * If the returned error code is SMW_STATUS_OK, SMW_STATUS_INVALID_PARAM,
 * SMW_STATUS_VERSION_NOT_SUPPORTED or SMW_STATUS_OUTPUT_TOO_SHORT the operation
 * is not terminated and the context remains valid.
 *
 * Return:
 * See &enum smw_status_code
 *	- Common return codes
 */
enum smw_status_code smw_aead_final(struct smw_aead_final_args *args);

#endif /* __SMW_AEAD_H__ */
