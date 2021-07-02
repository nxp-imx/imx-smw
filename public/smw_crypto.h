/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2021 NXP
 */

#ifndef __SMW_CRYPTO_H__
#define __SMW_CRYPTO_H__

#include "smw_strings.h"

/* Default TLS 1.2 verify data length for Finished message */
#define TLS12_MAC_FINISH_DEFAULT_LEN 12

/**
 * struct smw_hash_args - Hash arguments
 * @version: Version of this structure
 * @subsystem_name: Secure Subsystem name. See &typedef smw_subsystem_t
 * @algo_name: Algorithm name. See &typedef smw_hash_algo_t
 * @input: Location of the stream to be hashed
 * @input_length: Length of the stream to be hashed
 * @output: Location where the digest has to be written
 * @output_length: Length of the digest
 *
 * @subsystem_name designates the Secure Subsystem to be used.
 * If this field is NULL, the default configured Secure Subsystem is used.
 */
struct smw_hash_args {
	/* Inputs */
	unsigned char version;
	smw_subsystem_t subsystem_name;
	smw_hash_algo_t algo_name;
	unsigned char *input;
	unsigned int input_length;
	/* Outputs */
	unsigned char *output;
	unsigned int output_length;
};

/**
 * struct smw_sign_verify_args - Sign or verify arguments
 * @version: Version of this structure
 * @subsystem_name: Secure Subsystem name. See &typedef smw_subsystem_t
 * @key_descriptor: Pointer to a Key descriptor object.
 *		    See &struct smw_key_descriptor
 * @algo_name: Hash algorithm name. See &typedef smw_hash_algo_t
 * @message: Location of the message
 * @message_length: Length of the message
 * @signature: Location of the signature
 * @signature_length: Length of the signature
 * @attributes_list: Sign Verify attributes list
 * @attributes_list_length: @attributes_list length in bytes
 *
 * @subsystem_name designates the Secure Subsystem to be used.
 * If this field is NULL, the default configured Secure Subsystem is used.
 */
struct smw_sign_verify_args {
	/* Inputs */
	unsigned char version;
	smw_subsystem_t subsystem_name;
	struct smw_key_descriptor *key_descriptor;
	smw_hash_algo_t algo_name;
	unsigned char *message;
	unsigned int message_length;
	unsigned char *signature;
	unsigned int signature_length;
	const unsigned char *attributes_list;
	unsigned int attributes_list_length;
};

/**
 * struct smw_hmac_args - HMAC arguments
 * @version: Version of this structure
 * @subsystem_name: Secure Subsystem name. See &typedef smw_subsystem_t
 * @key_descriptor: Pointer to a Key descriptor object.
 *		    See &struct smw_key_descriptor
 * @algo_name: Hash algorithm name. See &typedef smw_hash_algo_t
 * @input: Location of the stream to be hash-mac'ed
 * @input_length: Length of the stream to be hashed
 * @output: Location where the MAC has to be written
 * @output_length: Length of the MAC
 *
 * @subsystem_name designates the Secure Subsystem to be used.
 * If this field is NULL, the default configured Secure Subsystem is used.
 */
struct smw_hmac_args {
	/* Inputs */
	unsigned char version;
	smw_subsystem_t subsystem_name;
	struct smw_key_descriptor *key_descriptor;
	smw_hash_algo_t algo_name;
	unsigned char *input;
	unsigned int input_length;
	/* Outputs */
	unsigned char *output;
	unsigned int output_length;
};

/**
 * struct smw_rng_args - Random number generator arguments
 * @version: Version of this structure
 * @subsystem_name: Secure Subsystem name. See &typedef smw_subsystem_t
 * @output: Location where the random number has to be written
 * @output_length: Length of the random number
 *
 * @subsystem_name designates the Secure Subsystem to be used.
 * If this field is NULL, the default configured Secure Subsystem is used.
 */
struct smw_rng_args {
	/* Inputs */
	unsigned char version;
	smw_subsystem_t subsystem_name;
	/* Outputs */
	unsigned char *output;
	unsigned int output_length;
};

/**
 * struct smw_op_context - SMW cryptographic operation context
 * @handle: Pointer to operation handle
 * @reserved: Reserved data
 *
 * Parameters @handle and @reserved are set by SMW. They must not be modified by
 * the application
 */
struct smw_op_context {
	/* Outputs */
	void *handle;
	void *reserved;
};

/**
 * struct smw_cipher_init_args - Cipher multi-part initialization arguments
 * @version: Version of this structure
 * @subsystem_name: Secure Subsystem name. See &typedef smw_subsystem_t
 * @keys_desc: Pointer to an array of pointers to key descriptors.
 *	       See &struct smw_key_descriptor
 * @nb_keys: Number of entries of @keys_desc
 * @mode_name: Cipher mode name. See &typedef smw_cipher_mode_t.
 * @operation_name: Cipher operation name. See &typedef smw_cipher_operation_t
 * @iv: Pointer to initialization vector
 * @iv_length: @iv length in bytes
 * @context: Pointer to operation context. See &struct smw_op_context
 *
 * Switch @mode, @iv is optional and represents:
 *	- Initialization Vector (CBC, CTS)
 *	- Initial Counter Value (CTR)
 *	- Tweak Value (XTS)
 */
struct smw_cipher_init_args {
	/* Inputs */
	unsigned char version;
	smw_subsystem_t subsystem_name;
	struct smw_key_descriptor **keys_desc;
	unsigned int nb_keys;
	smw_cipher_mode_t mode_name;
	smw_cipher_operation_t operation_name;
	unsigned char *iv;
	unsigned int iv_length;
	/* Outputs */
	struct smw_op_context *context;
};

/**
 * struct smw_cipher_data_args - Cipher data arguments
 * @version: Version of this structure
 * @context: Pointer to operation context. See &struct smw_op_context
 * @input: Input data buffer
 * @input_length: @input length in bytes
 * @output: Output data buffer
 * @output_length: @output length in bytes
 *
 * In case of final operation, @input and @input_length are optional.
 */
struct smw_cipher_data_args {
	/* Inputs */
	unsigned char version;
	struct smw_op_context *context;
	unsigned char *input;
	unsigned int input_length;
	/* Outputs */
	unsigned char *output;
	unsigned int output_length;
};

/**
 * struct smw_cipher_args - Cipher one-shot arguments
 * @init: Initialization arguments. See &struct smw_cipher_init_args
 * @data: Data arguments. See &struct smw_cipher_data_args
 *
 * Field @context present in @init and @data is ignored.
 */
struct smw_cipher_args {
	struct smw_cipher_init_args init;
	struct smw_cipher_data_args data;
};

/**
 * smw_hash() - Compute hash.
 * @args: Pointer to the structure that contains the Hash arguments.
 *
 * This function computes a hash.
 *
 * Return:
 * See &enum smw_status_code
 *	- Common return codes
 */
enum smw_status_code smw_hash(struct smw_hash_args *args);

/**
 * smw_sign() - Generate a signature.
 * @args: Pointer to the structure that contains the Sign arguments.
 *
 * This function generates a signature.
 * When TLS_MAC_FINISH attribute is set, the key type must be TLS_MASTER_KEY.
 *
 * Return:
 * &enum smw_status_code
 *	- Common return codes
 *	- Specific return codes - Signature
 */
enum smw_status_code smw_sign(struct smw_sign_verify_args *args);

/**
 * smw_verify() - Verify a signature.
 * @args: Pointer to the structure that contains the Verify arguments.
 *
 * This function verifies a sigature.
 *
 * Return:
 * See &enum smw_status_code
 *	- Common return codes
 *	- Specific return codes - Signature
 */
enum smw_status_code smw_verify(struct smw_sign_verify_args *args);

/**
 * smw_hmac() - Compute a HASH-MAC.
 * @args: Pointer to the structure that contains the HMAC arguments.
 *
 * This function computes a Keyed-Hash Message Authentication Code.
 *
 * Return:
 * See &enum smw_status_code
 *	- Common return codes
 */
enum smw_status_code smw_hmac(struct smw_hmac_args *args);

/**
 * smw_rng() - Compute a random number.
 * @args: Pointer to the structure that contains the RNG arguments.
 *
 * This function computes a random number.
 *
 * Return:
 * See &enum smw_status_code
 *	- Common return codes
 */
enum smw_status_code smw_rng(struct smw_rng_args *args);

/**
 * smw_cipher() - Cipher one-shot
 * @args: Pointer to the structure that contains the cipher arguments.
 *
 * This function executes a cipher encryption or decryption.
 *
 * Output data field of @args can be a NULL pointer to get the required output
 * buffer length. If this feature succeed, returned error code is SMW_STATUS_OK.
 *
 * Output length @args field is updated to the correct value when:
 *  - Output length is bigger than expected. In this case operation succeeded.
 *  - Output length is shorter than expected. In this case operation failed and
 *    returned SMW_STATUS_OUTPUT_TOO_SHORT.
 *
 * Keys used can be defined as buffer and as key ID.
 * All key types must be identical and must be linked to the same subystem.
 * If at least one key ID is set, subsystem name field of @args is optional. If
 * set it must be coherent with the key ID.
 *
 * Return:
 * See &enum smw_status_code
 *	- Common return codes
 */
enum smw_status_code smw_cipher(struct smw_cipher_args *args);

/**
 * smw_cipher_init() - Cipher multi-part initialization
 * @args: Pointer to the structure that contains the cipher multi-part
 *        initialization arguments.
 *
 * This function executes a cipher multi-part encryption or decryption
 * initialization.
 *
 * Keys used can be defined as buffer and as key ID.
 * All key types must be identical and must be linked to the same subystem.
 * If at least one key ID is set, subsystem name field of @args is optional. If
 * set it must be coherent with the key ID.
 *
 * Context structure presents in @args must be allocated by the application.
 *
 * Return:
 * See &enum smw_status_code
 *	- Common return codes
 */
enum smw_status_code smw_cipher_init(struct smw_cipher_init_args *args);

/**
 * smw_cipher_update() - Cipher multi-part update
 * @args: Pointer to the structure that contains the cipher multi-part update
 *        arguments.
 *
 * This function executes a cipher multi-part encryption or decryption update
 * operation.
 *
 * The context used must be initialized by the cipher multi-part initialization.
 *
 * Output length @args field is updated to the correct value when:
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
enum smw_status_code smw_cipher_update(struct smw_cipher_data_args *args);

/**
 * smw_cipher_final() - Cipher multi-part final
 * @args: Pointer to the structure that contains the cipher multi-part final
 *        arguments.
 *
 * This function executes a cipher multi-part encryption or decryption final
 * operation.
 *
 * The context used must be initialized by the cipher multi-part initialization.
 *
 * Input data field of @args can be a NULL pointer if no additional data are
 * used.
 *
 * Output data field of @args can be a NULL pointer to get the required output
 * buffer length. If this feature succeed, returned error code is SMW_STATUS_OK
 * and the operation is no terminated (context remains valid) unless required
 * output buffer length is 0.
 *
 * Output length @args field is updated to the correct value when:
 *  - Output length is bigger than expected. In this case operation succeeded.
 *  - Output length is shorter than expected. In this case operation failed and
 *    returned SMW_STATUS_OUTPUT_TOO_SHORT.
 *
 * If the returned error code is SMW_STATUS_INVALID_PARAM,
 * SMW_STATUS_VERSION_NOT_SUPPORTED or SMW_STATUS_OUTPUT_TOO_SHORT the operation
 * is not terminated and the context remains valid.
 *
 * Return:
 * See &enum smw_status_code
 *	- Common return codes
 */
enum smw_status_code smw_cipher_final(struct smw_cipher_data_args *args);

/**
 * smw_cancel_operation() - Cancel on-going cryptographic multi-part operation
 * @args: Pointer to operation context.
 *
 * If function succeeds, @args handle field is set to NULL.
 *
 * Return:
 * See &enum smw_status_code
 *	- Common return codes
 */
enum smw_status_code smw_cancel_operation(struct smw_op_context *args);

/**
 * smw_copy_context() - Copy an operation context
 * @dst: Pointer to destination operation context.
 * @src: Pointer to source operation context.
 *
 * This function copies an initialized or updated source context to a new
 * created destination context.
 * Parameter @dst must be allocated by caller.
 *
 * Return:
 * See &enum smw_status_code
 *	- Common return codes
 */
enum smw_status_code smw_copy_context(struct smw_op_context *dst,
				      struct smw_op_context *src);

#endif /* __SMW_CRYPTO_H__ */
