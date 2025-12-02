/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2026 NXP
 */

#ifndef __SMW_CRYPTO_SIGN_H__
#define __SMW_CRYPTO_SIGN_H__

/**
 * TLS12_MAC_FINISH_DEFAULT_LEN - Default TLS 1.2 verify data length for
 *                                finished message
 */
#define TLS12_MAC_FINISH_DEFAULT_LEN 12

/**
 * struct smw_eddsa_params - eddsa signature parameters
 * @context: [in] Pointer to the context parameters.
 * @context_length: [in] Length of the context parameters.
 */
struct smw_eddsa_params {
	unsigned char *context;
	unsigned int context_length;
};

/**
 * struct smw_sign_verify_args - Sign or verify arguments
 * @version: [in] Version of this structure.
 * @subsystem_name: [in] Secure Subsystem name. See &typedef smw_subsystem_t.
 * @key_descriptor: [in] Pointer to a Key descriptor object.
 *                  See &struct smw_key_descriptor.
 * @sign_algo: [in] Signature algorithm and attributes.
 *             See &typedef smw_attr_algo_t.
 * @message: [in] Pointer to the message to sign or verify.
 * @message_length: [in] Length in bytes of the message.
 * @signature:
 *  - [in] Pointer to the signature buffer to verify.
 *  - [out] Pointer to the signature buffer generated.
 * @signature_length:
 *  - [in] Length in bytes of the signature buffer.
 *  - [out] Length in bytes of the signature buffer generated.
 * @eddsa_params: [in] (**optional**) Pointer to eddsa parameters.
 *
 * The @subsystem_name designates the Secure Subsystem to be used.
 * If this field is :ref:`SMW_SUBSYSTEM_NAME_NONE <smw_subsystem_t>`,
 * the Secure Subsystem is the default one defined in the library configuration
 * or it's the one handling the key is key identifier is defined.
 */
struct smw_sign_verify_args {
	unsigned char version;
	smw_subsystem_t subsystem_name;
	struct smw_key_descriptor *key_descriptor;
	smw_attr_algo_t sign_algo;
	unsigned char *message;
	unsigned int message_length;
	unsigned char *signature;
	unsigned int signature_length;
	union {
		struct smw_eddsa_params *eddsa_params;
	};
};

/**
 * struct smw_sign_verify_init_args - Sign or verify multi-part initialization
 *                                    arguments
 * @version: [in] Version of this structure.
 * @subsystem_name: [in] Secure Subsystem name. See &typedef smw_subsystem_t.
 * @key_descriptor: [in] Pointer to a Key descriptor object.
 *                  See &struct smw_key_descriptor.
 * @sign_algo: [in] Signature algorithm and attributes.
 *             See &typedef smw_attr_algo_t.
 * @message: [in] Pointer to the message to sign or verify.
 * @message_length: [in] Length in bytes of the message.
 * @eddsa_params: [in] (**optional**) Pointer to edwards signature parameters.
 * @context: [in/out] Pointer the multipart operation context.
 *
 * Field @context:\
 *
 *  - Is used only for multi-part operations.
 *  - Must be allocated by smw_allocate_context().
 *  - Is initialized when initialization operation returned successfully.
 *
 * The @subsystem_name designates the Secure Subsystem to be used.
 * If this field is :ref:`SMW_SUBSYSTEM_NAME_NONE <smw_subsystem_t>`,
 * the Secure Subsystem is the default one defined in the library configuration
 * or it's the one handling the key is key identifier is defined.
 */
struct smw_sign_verify_init_args {
	unsigned char version;
	smw_subsystem_t subsystem_name;
	struct smw_key_descriptor *key_descriptor;
	smw_attr_algo_t sign_algo;
	unsigned char *message;
	unsigned int message_length;
	union {
		struct smw_eddsa_params *eddsa_params;
	};
	struct smw_op_context *context;
};

/**
 * struct smw_sign_verify_update_args - Sign or verify multi-part update
 *                                      arguments
 * @version: [in] Version of this structure.
 * @context: [in/out] Pointer the multipart operation context updated by
 *           smw_sign_init() or smw_sign_update() in case of signature
 *           generation, smw_verify_init() or smw_verify_update() in case of
 *           signature verification.
 * @message: [in] Pointer to the message to sign or verify.
 * @message_length: [in] Length in bytes of the message.
 *
 * Field @context:\
 *
 *  - Is used only for multi-part operations.
 *  - Is updated when update operation returned successfully.
 */
struct smw_sign_verify_update_args {
	unsigned char version;
	struct smw_op_context *context;
	unsigned char *message;
	unsigned int message_length;
};

/**
 * struct smw_sign_verify_final_args - Sign or verify multi-part final arguments
 * @version: [in] Version of this structure.
 * @context: [in/out] Pointer the multipart operation context updated by
 *           smw_sign_init() or smw_sign_update() in case of signature
 *           generation, smw_verify_init() or smw_verify_update() in case of
 *           signature verification.
 * @message: [in] Pointer to the message to sign or verify.
 * @message_length: [in] Length in bytes of the message.
 * @signature:
 *  - [in] Pointer to the signature buffer to verify.
 *  - [out] Pointer to the signature buffer generated.
 * @signature_length:
 *  - [in] Length in bytes of the signature buffer.
 *  - [out] Length in bytes of the signature buffer generated.
 *
 * Field @context:\
 *
 *  - Is used only for multi-part operations.
 *  - Is deleted when final operation returned except under conditions detailed
 *    in the smw_sign_final() and smw_verify_final() function descriptions.
 */
struct smw_sign_verify_final_args {
	unsigned char version;
	struct smw_op_context *context;
	unsigned char *message;
	unsigned int message_length;
	unsigned char *signature;
	unsigned int signature_length;
};

/**
 * smw_sign() - Generate a signature.
 * @args: Pointer to the structure that contains the sign arguments.
 *
 * This function generates a signature using a key present in
 * the Secure Subsystem storage identified by the key descriptor identifier
 * or a plaintext key value filled in the key descriptor private data buffer.
 *
 * To query the required signature buffer length, set @args->signature to
 * NULL. The function will then set the required signature buffer length in
 * @args->signature_length and return SMW_STATUS_OK. In this condition, the
 * input message can be omitted.
 *
 * On operation completion, the @args->signature_length is updated to the
 * correct value when:\
 *
 *  - Signature buffer length is bigger than expected. In this case, operation
 *    succeeds.
 *  - Signature buffer length is shorter than expected. In this case, operation
 *    fails and returns SMW_STATUS_OUTPUT_TOO_SHORT.
 *
 * Return:
 *  - SMW_STATUS_OK:
 *      Operation succeeded.
 *  - SMW_STATUS_INVALID_PARAM:
 *      - @args is NULL.
 *      - @args->key_descriptor is NULL.
 *      - @args->message is NULL.
 *      - @args->message_length is 0.
 *      - @args->signature is not NULL and @args->signature_length is 0.
 *      - Signature algorithm is not an asymmetric signature algorithm.
 *      - In case of using plaintext key, private buffer is NULL or length is 0.
 *      - Additional invalid parameters returned by the subsystem.
 *  - Other error code from &enum smw_status_code
 */
enum smw_status_code smw_sign(struct smw_sign_verify_args *args);

/**
 * smw_sign_init() - Signature generation multi-part initialization.
 * @args: Pointer to the structure that contains the signature multi-part
 *        initialization arguments.
 *
 * This function executes a signature generation multi-part initialization
 * using a key present in the Secure Subsystem storage identified by the key
 * descriptor identifier or a plaintext key value filled in the key descriptor
 * private data buffer.
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
 *      - @args->key_descriptor is NULL.
 *      - @args->context is NULL.
 *      - @args->message is NULL and @args->message_length is not 0.
 *      - @args->message is not NULL and @args->message_length is 0.
 *      - Signature algorithm is not an asymmetric signature algorithm.
 *      - In case of using plaintext key, private buffer is NULL or length is 0.
 *      - Additional invalid parameters returned by the subsystem.
 *  - Other error code from &enum smw_status_code
 */
enum smw_status_code smw_sign_init(struct smw_sign_verify_init_args *args);

/**
 * smw_sign_update() - Signature generation multi-part update.
 * @args: Pointer to the structure that contains the signature multi-part update
 *        arguments.
 *
 * This function executes a signature generation multi-part update operation.
 *
 * The context used must be initialized by the signature generation
 * multi-part initialization smw_sign_init() API or updated by a previous
 * smw_sign_update() call.
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
 *      - @args->message is NULL
 *      - @args->message_length is not 0.
 *      - Additional invalid parameters returned by the subsystem.
 *  - Other error code from &enum smw_status_code
 */
enum smw_status_code smw_sign_update(struct smw_sign_verify_update_args *args);

/**
 * smw_sign_final() - Signature generation multi-part final.
 * @args: Pointer to the structure that contains the signature multi-part final
 *        arguments.
 *
 * This function executes a signature generation multi-part final operation.
 *
 * The context used must be initialized by the signature generation
 * multi-part initialization smw_sign_init() API or updated by a previous
 * smw_sign_update() call.
 *
 * Input message field of @args can be a NULL pointer if no additional data are
 * used.
 *
 * To query the required signature buffer length, set @args->signature to NULL.
 * The function will then set the required signature buffer length in
 * @args->signature_length and return SMW_STATUS_OK. In this condition, the
 * input data can be omitted and the context remains valid.
 *
 * On operation completion, the @args->signature_length is updated to the
 * correct value when:\
 *
 *  - Signature buffer length is bigger than expected. In this case, operation
 *    succeeds.
 *  - Signature buffer length is shorter than expected. In this case, operation
 *    fails and returns SMW_STATUS_OUTPUT_TOO_SHORT.
 *
 * The **context** remains valid after this operation if return error code is:\
 *
 *  - SMW_STATUS_OK in case signature buffer is set to NULL.
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
 *      - @args->message is NULL and @args->message_length is not 0.
 *      - @args->message is not NULL and @args->message_length is 0.
 *      - @args->signature is not NULL and @args->signature_length is 0.
 *      - Additional invalid parameters returned by the subsystem.
 *  - Other error code from &enum smw_status_code
 */
enum smw_status_code smw_sign_final(struct smw_sign_verify_final_args *args);

/**
 * smw_verify() - Verify a signature.
 * @args: Pointer to the structure that contains the verify arguments.
 *
 * This function verifies a signature using a key present in
 * the Secure Subsystem storage identified by the key descriptor identifier
 * or a plaintext key value filled in the key descriptor public data buffer.
 *
 * Return:
 *  - SMW_STATUS_OK:
 *      Operation succeeded.
 *  - SMW_STATUS_INVALID_PARAM:
 *      - @args is NULL.
 *      - @args->key_descriptor is NULL.
 *      - @args->message is NULL.
 *      - @args->message_length is 0.
 *      - @args->signature is NULL.
 *      - @args->signature is not NULL and @args->signature_length is 0.
 *      - Signature algorithm is not an asymmetric signature algorithm.
 *      - In case of using plaintext key, public buffer is NULL or length is 0.
 *      - Additional invalid parameters returned by the subsystem.
 *  - Other error code from &enum smw_status_code
 */
enum smw_status_code smw_verify(struct smw_sign_verify_args *args);

/**
 * smw_verify_init() - Signature verification multi-part initialization.
 * @args: Pointer to the structure that contains the signature multi-part
 *        initialization arguments.
 *
 * This function executes a signature verification multi-part initialization
 * using a key present in the Secure Subsystem storage identified by the key
 * descriptor identifier or a plaintext key value filled in the key descriptor
 * public data buffer.
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
 *      - @args->key_descriptor is NULL.
 *      - @args->context is NULL.
 *      - @args->message is NULL and @args->message_length is not 0.
 *      - @args->message is not NULL and @args->message_length is 0.
 *      - Signature algorithm is not an asymmetric signature algorithm.
 *      - In case of using plaintext key, private buffer is NULL or length is 0.
 *      - Additional invalid parameters returned by the subsystem.
 *  - Other error code from &enum smw_status_code
 */
enum smw_status_code smw_verify_init(struct smw_sign_verify_init_args *args);

/**
 * smw_verify_update() - Signature verification multi-part update.
 * @args: Pointer to the structure that contains the signature multi-part update
 *        arguments.
 *
 * This function executes a signature verification multi-part update operation.
 *
 * The context used must be initialized by the signature verification
 * multi-part initialization.
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
 *      - @args->message is NULL
 *      - @args->message_length is not 0.
 *      - Additional invalid parameters returned by the subsystem.
 *  - Other error code from &enum smw_status_code
 */
enum smw_status_code
smw_verify_update(struct smw_sign_verify_update_args *args);

/**
 * smw_verify_final() - Signature verification multi-part final.
 * @args: Pointer to the structure that contains the signature multi-part final
 *        arguments.
 *
 * This function executes a signature verification multi-part final operation.
 *
 * The context used must be initialized by the signature generation
 * multi-part initialization.
 *
 * Input message field of @args can be a NULL pointer if no additional data are
 * used.
 *
 * Input signature field of @args must be set with a correct length to perform
 * the signature verification of message given in all multi-part steps.
 *
 * The **context** remains valid after this operation if return error code is:\
 *
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
 *      - @args->message is NULL and @args->message_length is not 0.
 *      - @args->message is not NULL and @args->message_length is 0.
 *      - @args->signature is NULL.
 *      - @args->signature is not NULL and @args->signature_length is 0.
 *      - Additional invalid parameters returned by the subsystem.
 *  - Other error code from &enum smw_status_code
 */
enum smw_status_code smw_verify_final(struct smw_sign_verify_final_args *args);

#endif /* __SMW_CRYPTO_SIGN_H__ */
