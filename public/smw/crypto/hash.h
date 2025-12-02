/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2026 NXP
 */

#ifndef __SMW_CRYPTO_HASH_H__
#define __SMW_CRYPTO_HASH_H__

/**
 * struct smw_hash_args - Hash one-shot arguments
 * @version: [in] Version of this structure.
 * @subsystem_name: [in] Secure Subsystem name. See &typedef smw_subsystem_t.
 * @algo_name: [in] Algorithm name. See &typedef smw_hash_algo_t.
 * @input: [in] Pointer to the input buffer to digest.
 * @input_length: [in] Length in bytes of the input buffer.
 * @output: [out] Pointer to the digest buffer.
 * @output_length: [out] Length in bytes of the digest buffer.
 *
 * The @subsystem_name designates the Secure Subsystem to be used.
 * If this field is :ref:`SMW_SUBSYSTEM_NAME_NONE <smw_subsystem_t>`,
 * the default configured Secure Subsystem is used.
 */
struct smw_hash_args {
	unsigned char version;
	smw_subsystem_t subsystem_name;
	smw_hash_algo_t algo_name;
	unsigned char *input;
	unsigned int input_length;
	unsigned char *output;
	unsigned int output_length;
};

/**
 * struct smw_hash_init_args - Hash multi-part initialization arguments
 * @version: [in] Version of this structure (must be set to 1).
 * @subsystem_name: [in] Secure Subsystem name. See &typedef smw_subsystem_t.
 * @algo_name: [in] Algorithm name. See &typedef smw_hash_algo_t.
 * @input: [in] Pointer to the input buffer to digest.
 * @input_length: [in] Length in bytes of the input buffer.
 * @context: [in/out] Pointer the multipart operation context.
 *
 * The @subsystem_name designates the Secure Subsystem to be used.
 * If this field is :ref:`SMW_SUBSYSTEM_NAME_NONE <smw_subsystem_t>`,
 * the default configured Secure Subsystem is used.
 *
 * Field @context:\
 *
 *  - Is used only for multi-part operations.
 *  - Must be allocated by smw_allocate_context().
 *  - Is initialized when initialization operation returned successfully.
 */
struct smw_hash_init_args {
	unsigned char version;
	smw_subsystem_t subsystem_name;
	smw_hash_algo_t algo_name;
	unsigned char *input;
	unsigned int input_length;
	struct smw_op_context *context;
};

/**
 * struct smw_hash_update_args - Hash multi-part update arguments
 * @version: [in] Version of this structure.
 * @context: [in/out] Pointer the multipart operation context updated by
 *           smw_hash_init() or smw_hash_update().
 * @input: [in] Pointer to the input buffer to digest.
 * @input_length: [in] Length in bytes of the input buffer.
 *
 * Field @context:\
 *
 *  - Is used only for multi-part operations.
 *  - Is updated when update operation returned successfully.
 */
struct smw_hash_update_args {
	unsigned char version;
	struct smw_op_context *context;
	unsigned char *input;
	unsigned int input_length;
};

/**
 * struct smw_hash_final_args - Hash multi-part final arguments
 * @version: [in] Version of this structure.
 * @context: [in/out] Pointer the multipart operation context updated by
 *           smw_hash_init() or smw_hash_update().
 * @input: [in] Pointer to the input buffer to digest.
 * @input_length: [in] Length in bytes of the input buffer.
 * @output: [out] Pointer to the digest buffer.
 * @output_length: [out] Length in bytes of the digest buffer.
 *
 * Field @context:\
 *
 *  - Is used only for multi-part operations.
 *  - Is deleted when final operation returned except under conditions detailed
 *    in the smw_hash_final() function description.
 */
struct smw_hash_final_args {
	unsigned char version;
	struct smw_op_context *context;
	unsigned char *input;
	unsigned int input_length;
	unsigned char *output;
	unsigned int output_length;
};

/**
 * smw_hash() - Compute hash.
 * @args: Pointer to the structure that contains the Hash arguments.
 *
 * This function computes a hash.
 *
 * To query the required digest buffer length, set @args->output to NULL.
 * The function will then set the required digest buffer length in
 * @args->output_length and return SMW_STATUS_OK. In this condition, the
 * input data can be omitted.
 *
 * On operation completion, the @args->output_length is updated to the
 * correct value when:\
 *
 *  - Digest buffer length is bigger than expected. In this case, operation
 *    succeeds.
 *  - Digest buffer length is shorter than expected. In this case, operation
 *    fails and returns SMW_STATUS_OUTPUT_TOO_SHORT.
 *
 * Return:
 *  - SMW_STATUS_OK:
 *      Operation succeeded.
 *  - SMW_STATUS_INVALID_PARAM:
 *      - @args is NULL.
 *      - @args->input is NULL and @args->input_length is not 0.
 *      - @args->input is not NULL and @args->input_length is 0.
 *      - @args->output is NULL and @args->output_length is not 0.
 *      - Additional invalid parameters returned by the subsystem.
 *  - Other error code from &enum smw_status_code
 */
enum smw_status_code smw_hash(struct smw_hash_args *args);

/**
 * smw_hash_init() - Hash multi-part initialization.
 * @args: Pointer to the structure that contains the hash multi-part
 *        initialization arguments.
 *
 * This function executes a hash multi-part initialization.
 *
 * The operation context must be allocated using smw_allocate_context() API
 * prior to invoking this API.
 *
 * The **context** remains valid after this operation if return error code is:\
 *
 *  - SMW_STATUS_OK
 *  - SMW_STATUS_INVALID_PARAM
 *  - SMW_STATUS_VERSION_NOT_SUPPORTED
 *  - SMW_STATUS_UNKNOWN_SUBSYSTEM_NAME
 *  - SMW_STATUS_OPERATION_ALREADY_INIT
 *
 * Otherwise, the **context** is freed and becomes invalid, @args->context is
 * set to NULL.
 *
 * Return:
 *  - SMW_STATUS_OK:
 *      Operation succeeded.
 *  - SMW_STATUS_INVALID_PARAM:
 *      - @args is NULL.
 *      - @args->context is NULL.
 *      - @args->input is NULL and @args->input_length is not 0.
 *      - @args->input is not NULL and @args->input_length is 0.
 *      - Additional invalid parameters returned by the subsystem.
 *  - Other error code from &enum smw_status_code
 */
enum smw_status_code smw_hash_init(struct smw_hash_init_args *args);

/**
 * smw_hash_update() - Hash multi-part update.
 * @args: Pointer to the structure that contains the hash multi-part update
 *        arguments.
 *
 * This function executes a hash multi-part update operation.
 *
 * The context used must be initialized by the hash multi-part initialization
 * smw_hash_init() API or updated by a previous smw_hash_update() call.
 *
 * The **context** remains valid after this operation if return error code is:\
 *
 *  - SMW_STATUS_OK
 *  - SMW_STATUS_INVALID_PARAM
 *  - SMW_STATUS_VERSION_NOT_SUPPORTED
 *  - SMW_STATUS_UNKNOWN_SUBSYSTEM_NAME
 *
 * Otherwise, the **context** is freed and becomes invalid, @args->context is
 * set to NULL.
 *
 * Return:
 *  - SMW_STATUS_OK:
 *      Operation succeeded.
 *  - SMW_STATUS_INVALID_PARAM:
 *      - @args is NULL.
 *      - @args->context is NULL.
 *      - @args->input is NULL.
 *      - @args->input_length is 0.
 *      - Additional invalid parameters returned by the subsystem.
 *  - Other error code from &enum smw_status_code
 */
enum smw_status_code smw_hash_update(struct smw_hash_update_args *args);

/**
 * smw_hash_final() - Hash multi-part final.
 * @args: Pointer to the structure that contains the hash multi-part final
 *        arguments.
 *
 * This function executes a hash multi-part final operation.
 *
 * The context used must be initialized by the hash multi-part initialization
 * smw_hash_init() API or updated by a previous smw_hash_update() call.
 *
 * Input data field of @args can be a NULL pointer if no additional data are
 * used.
 *
 * To query the required digest buffer length, set @args->output to NULL.
 * The function will then set the required digest buffer length in
 * @args->output_length and return SMW_STATUS_OK. In this condition, the
 * input data can be omitted and the context remains valid.
 *
 * On operation completion, the @args->output_length is updated to the
 * correct value when:\
 *
 *  - Digest buffer length is bigger than expected. In this case, operation
 *    succeeds.
 *  - Digest buffer length is shorter than expected. In this case, operation
 *    fails and returns SMW_STATUS_OUTPUT_TOO_SHORT.
 *
 * The **context** remains valid after this operation if return error code is:\
 *
 *  - SMW_STATUS_OK in case output buffer is set to NULL.
 *  - SMW_STATUS_OUTPUT_TOO_SHORT
 *  - SMW_STATUS_INVALID_PARAM
 *  - SMW_STATUS_VERSION_NOT_SUPPORTED
 *  - SMW_STATUS_UNKNOWN_SUBSYSTEM_NAME
 *
 * Otherwise, the **context** is freed and becomes invalid, @args->context is
 * set to NULL.
 *
 * Return:
 *  - SMW_STATUS_OK:
 *      Operation succeeded.
 *  - SMW_STATUS_INVALID_PARAM:
 *      - @args is NULL.
 *      - @args->context is NULL.
 *      - @args->input is not NULL and @args->input_length is 0.
 *      - @args->output is not NULL and @args->output_length is 0.
 *      - Additional invalid parameters returned by the subsystem.
 *  - Other error code from &enum smw_status_code
 */
enum smw_status_code smw_hash_final(struct smw_hash_final_args *args);

#endif /* __SMW_CRYPTO_HASH_H__ */
