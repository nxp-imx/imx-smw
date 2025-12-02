/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2026 NXP
 */

#ifndef __SMW_CRYPTO_CIPHER_H__
#define __SMW_CRYPTO_CIPHER_H__

/**
 * struct smw_cipher_init_args - Cipher multi-part initialization arguments
 * @version: [in] Version of this structure.
 * @subsystem_name: [in] Secure Subsystem name. See &typedef smw_subsystem_t.
 * @keys_desc: [in] Pointer to an array of pointers to key descriptors.
 *             See &struct smw_key_descriptor.
 * @nb_keys: [in] Number of entries of the key descriptors array @keys_desc.
 * @mode_name: [in] Cipher mode name. See &typedef smw_cipher_mode_t.
 * @op_type_name: [in] Cipher operation type name.
 *                See &typedef smw_cipher_op_type_t.
 * @iv: [in] Pointer to initialization vector. Not used in ECB mode.
 * @iv_length: [in] Length in bytes of the initialization vector. Not used in
 *             ECB mode.
 * @context: [in/out] Pointer the multipart operation context.
 *
 * Field @context:\
 *
 *  - Is used only for multi-part operations.
 *  - Must be allocated by smw_allocate_context().
 *  - Is initialized when initialization operation returned successfully.
 *
 * The number of keys @nb_keys is usually 1 key, but for the XTS mode, 2 keys
 * are required. In the case of multi-key cipher operation, the keys must be
 * owned by the same Secure Subsystem and must be the same key type.
 *
 * The @subsystem_name designates the Secure Subsystem to be used.
 * If this field is :ref:`SMW_SUBSYSTEM_NAME_NONE <smw_subsystem_t>`,
 * the Secure Subsystem is the default one defined in the library configuration
 * or it's the one handling the key is key identifier is defined.
 */
struct smw_cipher_init_args {
	unsigned char version;
	smw_subsystem_t subsystem_name;
	struct smw_key_descriptor **keys_desc;
	unsigned int nb_keys;
	smw_cipher_mode_t mode_name;
	smw_cipher_op_type_t op_type_name;
	unsigned char *iv;
	unsigned int iv_length;
	struct smw_op_context *context;
};

/**
 * struct smw_cipher_data_args - Cipher data arguments
 * @version: [in] Version of this structure.
 * @context: [in/out] Pointer the multipart operation context updated by
 *           smw_cipher_init() or smw_cipher_update().
 * @input: [in] Pointer to the input buffer to encrypt or decrypt.
 * @input_length: [in] Length in bytes of the input buffer.
 * @output: [out] Pointer to the output buffer decrypted or encrypted.
 * @output_length: [out] Length in bytes of the output buffer.
 *
 * Field @context:\
 *
 *  - Is used only for multi-part operations.
 *  - Is updated when update operation returned successfully.
 *  - Is deleted when final operation returned except under conditions detailed
 *    in the smw_cipher_final() function description.
 *
 * In case of final operation, @input and @input_length are optional.
 */
struct smw_cipher_data_args {
	unsigned char version;
	struct smw_op_context *context;
	unsigned char *input;
	unsigned int input_length;
	unsigned char *output;
	unsigned int output_length;
};

/**
 * struct smw_cipher_args - Cipher one-shot arguments
 * @init: Initialization arguments. See &struct smw_cipher_init_args.
 * @data: Data arguments. See &struct smw_cipher_data_args.
 *
 * This structure is defined with the multi-part operation but field @context
 * present in @init and @data is ignored.
 */
struct smw_cipher_args {
	struct smw_cipher_init_args init;
	struct smw_cipher_data_args data;
};

/**
 * smw_cipher() - Cipher encryption or decryption.
 * @args: Pointer to the structure that contains the cipher arguments.
 *
 * This function executes a cipher encryption or decryption using a key present
 * in the Secure Subsystem storage identified by the key descriptor identifier
 * or a plaintext key value filled in the key descriptor private data buffer.
 *
 * To query the required output buffer length, set @args->data.output to
 * NULL. The function will then set the required output buffer length in
 * @args->data.output_length and return SMW_STATUS_OK.
 *
 * On operation completion, the @args->data.output_length is updated to the
 * correct value when:\
 *
 *  - Output buffer length is bigger than expected. In this case, operation
 *    succeeds.
 *  - Output buffer length is shorter than expected. In this case, operation
 *    fails and returns SMW_STATUS_OUTPUT_TOO_SHORT.
 *
 * Return:
 *  - SMW_STATUS_OK:
 *      Operation succeeded.
 *  - SMW_STATUS_INVALID_PARAM:
 *      - @args is NULL.
 *      - @args->data.input is NULL.
 *      - @args->data.input_length is 0.
 *      - @args->data.output is not NULL and @args->data.output_length is 0.
 *      - @args->init.key_desc is NULL.
 *      - @args->init.nb_keys is 0.
 *      - @args->init.nb_keys is not equal to 1 in case of mode other than XTS.
 *      - @args->init.nb_keys is not equal to 2 in case of XTS mode.
 *      - In case of multiple keys, key type are not identical, keys are not
 *        owned by the same Secure Subsystem.
 *      - If key descriptor is not correctly defined. No key id and no key
 *        buffer.
 *      - @args->init.mode_name is SMW_CIPHER_MODE_NAME_NONE.
 *      - @args->init.op_type_name is SMW_CIPHER_OP_TYPE_NAME_NONE.
 *      - @args->init.iv is NULL in case of mode requiring an IV/counter/tweak.
 *      - @args->init.iv_length is 0 in case of mode requiring an
 *        IV/counter/tweak.
 *      - In case of using plaintext key(s), private buffer is NULL or length
 *        is 0.
 *      - Additional invalid parameters returned by the subsystem.
 *  - Other error code from &enum smw_status_code
 */
enum smw_status_code smw_cipher(struct smw_cipher_args *args);

/**
 * smw_cipher_init() - Cipher multi-part initialization.
 * @args: Pointer to the structure that contains the cipher multi-part
 *        initialization arguments.
 *
 * This function executes a cipher multi-part encryption or decryption
 * initialization using a key present in the Secure Subsystem storage
 * identified by the key descriptor identifier or a plaintext key value filled
 * in the key descriptor private data buffer.
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
 *  - SMW_STATUS_UNKNOWN_MODE_NAME
 *  - SMW_STATUS_UNKNOWN_OP_TYPE_NAME
 *  - SMW_STATUS_OPERATION_ALREADY_INIT
 *  - SMW_STATUS_UNKNOWN_ID
 *  - SMW_STATUS_OPERATION_NOT_SUPPORTED
 *
 * Otherwise, the **context** is freed and becomes invalid, @args->context is
 * set to NULL.
 *
 * Return:
 *  - SMW_STATUS_OK:
 *      Operation succeeded.
 *  - SMW_STATUS_INVALID_PARAM:
 *      - @args is NULL.
 *      - @args_>context is NULL.
 *      - @args->key_desc is NULL.
 *      - @args->nb_keys is 0.
 *      - @args->nb_keys is not equal to 1 in case of mode other than XTS.
 *      - @args->nb_keys is not equal to 2 in case of XTS mode.
 *      - In case of multiple keys, key type are not identical, keys are not
 *        owned by the same Secure Subsystem.
 *      - If key descriptor is not correctly defined. No key id and no key
 *        buffer.
 *      - @args->mode_name is SMW_CIPHER_MODE_NAME_NONE.
 *      - @args->op_type_name is SMW_CIPHER_OP_TYPE_NAME_NONE.
 *      - @args->iv is NULL in case of mode requiring an IV/counter/tweak.
 *      - @args->iv_length is 0 in case of mode requiring an
 *        IV/counter/tweak.
 *      - In case of using plaintext key(s), private buffer is NULL or length
 *        is 0.
 *      - Additional invalid parameters returned by the subsystem.
 *  - Other error code from &enum smw_status_code
 */
enum smw_status_code smw_cipher_init(struct smw_cipher_init_args *args);

/**
 * smw_cipher_update() - Cipher multi-part update.
 * @args: Pointer to the structure that contains the cipher multi-part update
 *        arguments.
 *
 * This function executes a cipher multi-part encryption or decryption update
 * operation.
 *
 * The context used must be initialized by the cipher multi-part initialization
 * smw_cipher_init() API or updated by a previous smw_cipher_update() call.
 *
 * To query the required output buffer length, set @args->output to
 * NULL. The function will then set the required output buffer length in
 * @args->output_length and return SMW_STATUS_OK.
 *
 * On operation completion, the @args->output_length is updated to the
 * correct value when:\
 *
 *  - Output buffer length is bigger than expected. In this case, operation
 *    succeeds.
 *  - Output buffer length is shorter than expected. In this case, operation
 *    fails and returns SMW_STATUS_OUTPUT_TOO_SHORT.
 *
 * The **context** remains valid after this operation if return error code is:\
 *
 *  - SMW_STATUS_OK
 *  - SMW_STATUS_INVALID_PARAM
 *  - SMW_STATUS_VERSION_NOT_SUPPORTED
 *  - SMW_STATUS_UNKNOWN_SUBSYSTEM_NAME
 *  - SMW_STATUS_OUTPUT_TOO_SHORT
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
 *      - @args->input_length is NULL.
 *      - @args->output is not NULL and @args->output_length is 0.
 *      - Additional invalid parameters returned by the subsystem.
 *  - Other error code from &enum smw_status_code
 */
enum smw_status_code smw_cipher_update(struct smw_cipher_data_args *args);

/**
 * smw_cipher_final() - Cipher multi-part final.
 * @args: Pointer to the structure that contains the cipher multi-part final
 *        arguments.
 *
 * This function executes a cipher multi-part encryption or decryption final
 * operation.
 *
 * The context used must be initialized by the cipher multi-part initialization
 * smw_cipher_init() API or updated by a previous smw_cipher_update() call.
 *
 * Input data field of @args can be a NULL pointer if no additional data are
 * used.
 *
 * To query the required output buffer length, set @args->output to
 * NULL. The function will then set the required output buffer length in
 * @args->output_length and return SMW_STATUS_OK.
 *
 * On operation completion, the @args->output_length is updated to the
 * correct value when:\
 *
 *  - Output buffer length is bigger than expected. In this case, operation
 *    succeeds.
 *  - Output buffer length is shorter than expected. In this case, operation
 *    fails and returns SMW_STATUS_OUTPUT_TOO_SHORT.
 *
 * The **context** remains valid after this operation if return error code is:\
 *
 *  - SMW_STATUS_OK in case output buffer is set to NULL.
 *  - SMW_STATUS_INVALID_PARAM
 *  - SMW_STATUS_VERSION_NOT_SUPPORTED
 *  - SMW_STATUS_UNKNOWN_SUBSYSTEM_NAME
 *  - SMW_STATUS_OUTPUT_TOO_SHORT
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
enum smw_status_code smw_cipher_final(struct smw_cipher_data_args *args);

#endif /* __SMW_CRYPTO_CIPHER_H__ */
