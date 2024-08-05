/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2023-2024 NXP
 */

#ifndef __SMW_AEAD_H__
#define __SMW_AEAD_H__

#include "smw_status.h"
#include "smw/names.h"

/**
 * struct smw_aead_init_args - AEAD initialization arguments
 * @version: Version of this structure
 * @subsystem_name: Secure Subsystem name. See &typedef smw_subsystem_t
 * @key_desc: Pointer to a key descriptor object. See &struct smw_key_descriptor
 * @mode_name: AEAD mode name. See &typedef smw_aead_mode_t
 * @op_type_name: AEAD operation name. See &typedef smw_aead_op_type_t
 * @user_iv: Pointer to user initialization vector
 * @user_iv_length: User IV buffer length in bytes
 * @iv_length: Requested IV buffer length in bytes
 * @aad_length: Additional authentication data length in bytes
 * @tag_length: Tag buffer length in bytes
 * @plaintext_length: Length in bytes of the data to encrypt
 * @context: Pointer to an opaque operation context structure
 *
 * If subsystem offers the capability to generate partial or complete IV,
 * the user can set the input @init->user_iv_length to 0 (requesting full generated
 * IV) or set @init->iv_length to the requested IV size (requesting partial generated IV).
 * Otherwise, if @init->user_iv_length is set to the maximum IV size supported by the
 * subsystem, @init->iv_length is not taking into consideration.
 * Please refer to the AEAD subsystems capabilities.
 *
 */
struct smw_aead_init_args {
	/* Inputs */
	unsigned char version;
	smw_subsystem_t subsystem_name;
	struct smw_key_descriptor *key_desc;
	smw_aead_mode_t mode_name;
	smw_aead_op_type_t op_type_name;
	unsigned char *user_iv;
	unsigned int user_iv_length;
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
 * @context: Pointer to an opaque operation context structure
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
 * @data: Pointer to additional authentication data
 * @data_length: AAD length in bytes
 * @context: Pointer to an opaque operation context structure
 */
struct smw_aead_aad_args {
	/* Inputs */
	unsigned char version;
	unsigned char *data;
	unsigned int data_length;
	struct smw_op_context *context;
};

/**
 * struct smw_aead_final_args - AEAD final arguments
 * @version: Version of this structure
 * @data: Pointer to AEAD data arguments. See &struct smw_aead_data_args
 * @op_type_name: AEAD operation name. See &typedef smw_aead_op_type_t
 * @tag: Pointer to tag buffer
 * @tag_length: Tag buffer length in bytes
 * @output_iv_length: Length of output IV buffer
 * @output_iv: Pointer to output IV buffer
 *
 * @output_iv buffer should be allocated by the caller application for
 * encryption operation.
 * Upon successful encryption operation, @output_iv will contain the IV
 * used by subsystem during operation.
 *
 * Fields @output_iv_length and @output_iv are ignored for decryption operation.
 *
 */
struct smw_aead_final_args {
	/* Inputs */
	unsigned char version;
	struct smw_aead_data_args *data;
	smw_aead_op_type_t op_type_name;
	/* Input output */
	unsigned char *tag;
	unsigned int tag_length;
	unsigned int output_iv_length;
	/* Output */
	unsigned char *output_iv;
};

/**
 * struct smw_aead_args - AEAD one-shot arguments
 * @version: Version of this structure
 * @aad: Pointer to AAD arguments. See &struct smw_aead_aad_args
 * @init: Pointer to initialization arguments. See &struct smw_aead_init_args
 * @final: Pointer to final arguments. See &struct smw_aead_final_args
 *
 * Field @context present in @init, @aad and @final is ignored.
 * Field @operation_name present in @final is ignored.
 *
 */
struct smw_aead_args {
	/* Input */
	unsigned char version;
	struct smw_aead_aad_args *aad;
	/* Input output */
	struct smw_aead_init_args *init;
	struct smw_aead_final_args *final;
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
 *    - If the @args->final->tag field is set, the computed tag will be stored
 *      in the dedicated @args->final->tag field.
 *    - If the @args->final->tag field is not set, @args->final->data->output
 *      field will contain the ciphertext followed by the tag.
 *
 *  - One-shot AEAD decryption operation:
 *
 *    - This function authenticates and decrypts the ciphertext.
 *    - If the @args->final->tag field is not set, the @args->final->data->input
 *      should contain the ciphertext followed by the tag.
 *    - If the computed tag does not match the supplied tag, the operation
 *      will be terminated.
 *
 * If @args->final->data->output is a NULL pointer, then the function updates
 * @args->final->data->output_length field and returns error code SMW_STATUS_OK.
 * Additionally, if the operation is encryption, the tag length
 * @args->final->tag_length and output IV length @args->final->output_iv_length
 * are updated with generated tag value length and IV length, respectively.
 *
 * On operation completion, the @args->final->data->output_length is updated to
 * the correct value when
 *
 *  - Output length is bigger than expected. In this case, operation succeeds.
 *  - Output length is shorter than expected. In this case, operation fails and
 *    returns SMW_STATUS_OUTPUT_TOO_SHORT.
 *  - In the above mentioned two scenarios, if the operation is encryption, the
 *    function also updates the required tag buffer length
 *    @args->final->tag_length and output IV length
 *    @args->final->output_iv_length.
 *
 * If @args->final->data->output is not a NULL pointer, then
 *
 *  - For an encryption operation, if the @args->final->tag field is not set,
 *    @args->final->data->output should be sufficiently large to accommodate
 *    both the ciphertext and tag.
 *  - For an encryption operation, if the @args->final->tag field is set,
 *    @args->final->data->output should be sufficiently large to accommodate the
 *    ciphertext.
 *  - For decryption operation, @args->final->data->output should be
 *    sufficiently large to accommodate the plaintext.
 *
 * If the IV is generated fully or partially by the subsystem,
 * @args->final->output_iv will hold the IV generated by subsystem.
 * If the IV is supplied fully by the user, @args->final->output_iv will hold IV
 * supplied by he user.
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
 * This function initializes AEAD multi-part encryption or decryption
 * operation.
 *
 * The operation context must be allocated using smw_allocate_context() API
 * prior to invoking this API.
 *
 * If the returned error code is SMW_STATUS_OK or SMW_STATUS_INVALID_PARAM, the
 * operation is not terminated and the context remains valid.
 *
 * Key used can be defined either as a buffer or as a key ID.
 *
 * Return:
 * See &enum smw_status_code
 *	- Common return codes
 */
enum smw_status_code smw_aead_init(struct smw_aead_init_args *args);

/**
 * smw_aead_update_aad() - Update AEAD additional authenticated data.
 * @args: Pointer to the structure that contains the AEAD additional data
 *        arguments.
 *
 * This function can be called multiple time while the update data
 * (to encrypt or to decrypt) step is not called.
 *
 * The context used must be initialized by the AEAD multi-part initialization.
 *
 * If the returned error code is SMW_STATUS_OK, SMW_STATUS_INVALID_PARAM or
 * SMW_STATUS_VERSION_NOT_SUPPORTED, the operation is not terminated, and the
 * context remains valid.
 *
 * Return:
 * See &enum smw_status_code
 *	- Common return codes
 */
enum smw_status_code smw_aead_update_aad(struct smw_aead_aad_args *args);

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
 * The @args->output can be a NULL pointer to get the required output buffer
 * length. If this feature succeeds, returned error code is SMW_STATUS_OK.
 *
 * The @args->output_length field is updated to the correct value when:
 *
 *  - Output length is bigger than expected. In this case operation succeeded.
 *  - Output length is shorter than expected. In this case operation failed and
 *    returned SMW_STATUS_OUTPUT_TOO_SHORT.
 *
 * If the returned error code is SMW_STATUS_OK, SMW_STATUS_INVALID_PARAM,
 * SMW_STATUS_VERSION_NOT_SUPPORTED or SMW_STATUS_OUTPUT_TOO_SHORT the
 * operation is not terminated and the context remains valid.
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
 *    - If the @args->tag field is set, the computed tag will be stored in the
 *      dedicated @args->tag field.
 *    - If the @args->tag field is not set, @args->data->output field will point
 *      to the ciphertext followed by the tag.
 *
 *  - AEAD Decryption final operation:
 *
 *    - This function finishes authenticating and decrypting a message in an
 *      active multi-part AEAD operation.
 *    - If the computed tag does not match the supplied tag, the operation will
 *      be terminated. The returned error code is SMW_STATUS_SIGNATURE_INVALID.
 *    - If the @args->tag is not supplied in the tag field, the
 *      @args->data->input field should be sufficiently large to accommodate
 *      both the ciphertext and the tag.
 *
 * If @args->data->output is a NULL pointer, then the function updates
 * @args->data->output_length field and returns error code SMW_STATUS_OK.
 * In this case, if the operation is encryption, the function also updates the
 * required tag buffer length @args->tag_length.
 *
 * The @args->data->output_length field is updated to the correct value when:
 *
 *  - Output length is bigger than expected. In this case, operation succeeds.
 *  - Output length is shorter than expected. In this case, operation fails and
 *    returns SMW_STATUS_OUTPUT_TOO_SHORT error code.
 *  - In the above mentioned two scenarios, if the operation is encryption, the
 *    function also updates the required tag buffer length @args->tag_length.
 *
 * If @args->data->output field is not a NULL pointer, then
 *
 *  - For an encryption operation, if the @args->tag field is not set,
 *    @args->data->output should be sufficiently large to accommodate both the
 *    ciphertext and tag.
 *  - For an encryption operation, if the @args->tag field is set,
 *    @args->data->output should be sufficiently large to accommodate the
 *    ciphertext.
 *  - For decryption operation, @args->data->output should be sufficiently large
 *    to accommodate the plaintext.
 *
 * If the IV is generated fully or partially by the subsystem, @args->output_iv
 * will hold the IV generated by subsystem.
 * If the IV is supplied fully by the user, @args->output_iv will hold IV
 * supplied by he user.
 *
 * If the returned error code is SMW_STATUS_INVALID_PARAM,
 * SMW_STATUS_VERSION_NOT_SUPPORTED or SMW_STATUS_OUTPUT_TOO_SHORT the operation
 * is not terminated and the context remains valid.
 *
 * Return:
 * See &enum smw_status_code
 *	- Common return codes
 */
enum smw_status_code smw_aead_final(struct smw_aead_final_args *args);

#endif /* __SMW_AEAD_H__ */
