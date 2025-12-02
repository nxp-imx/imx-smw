/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2025-2026 NXP
 */

#ifndef __SMW_CRYPTO_ASYMMETRIC_ENCRYPTION_H__
#define __SMW_CRYPTO_ASYMMETRIC_ENCRYPTION_H__

/**
 * struct smw_asymmetric_encryption_args - Asymmetric encryption and decryption
 *                                         arguments structure
 * @version: [in] Version of this structure
 * @subsystem_name:  [in] Secure Subsystem name. See &typedef smw_subsystem_t.
 * @key_descriptor: [in]  Pointer to a Key descriptor object.
 *		    See &struct smw_key_descriptor.
 * @algo: [in] Encryption/decryption algorithm and attributes.
 *          See &typedef smw_attr_algo_t.
 * @input: [in] Pointer to input data buffer.
 * @input_length: [in] Length in bytes of the input data buffer.
 * @output: [out] Pointer to output buffer
 * @output_length: [out] Length in bytes if te output buffer.
 * @salt: [in] (**optional**) Pointer to salt or label buffer
 * @salt_length: [in] (**optional**) Length in bytes of the salt buffer length.
 *
 * The @subsystem_name designates the Secure Subsystem to be used.
 * If this field is :ref:`SMW_SUBSYSTEM_NAME_NONE <smw_subsystem_t>`,
 * the Secure Subsystem is the default one defined in the library configuration
 * or it's the one handling the key is key identifier is defined.
 */
struct smw_asymmetric_encryption_args {
	unsigned char version;
	smw_subsystem_t subsystem_name;
	struct smw_key_descriptor *key_descriptor;
	smw_attr_algo_t algo;
	unsigned char *input;
	unsigned int input_length;
	unsigned char *output;
	unsigned int output_length;
	unsigned char *salt;
	unsigned int salt_length;
};

/**
 * smw_asymmetric_encrypt() - Encrypt a message.
 * @args: Pointer to asymmetric encryption and decryption arguments structure.
 *
 * This function encrypts a message using a RSA key present in the Secure
 * Subsystem storage identified by the key descriptor identifier or a plaintext
 * key value filled in the key descriptor RSA public buffers; modulus and
 * public data.
 *
 * To query the required asymmetric encryption result output buffer length,
 * set @args->output to NULL. The function will then set the required output
 * buffer length in @args->output_length and return SMW_STATUS_OK.
 *
 * On operation completion, the @args->output_length is updated to the correct
 * value when:\
 *
 *  - Output length is bigger than expected. In this case, operation succeeds.
 *  - Output length is shorter than expected. In this case, operation fails and
 *    returns SMW_STATUS_OUTPUT_TOO_SHORT.
 *
 * Return:
 *  - SMW_STATUS_OK:
 *      Operation succeeded.
 *  - SMW_STATUS_INVALID_PARAM:
 *      - @args is NULL.
 *      - @args->key_descriptor is NULL.
 *      - @args->input is NULL.
 *      - @args->input_length is 0.
 *      - @args->output is not NULL and @args->output_length is 0.
 *      - @args->salt is NULL and @args->salt_length is not 0, OEAP encryption.
 *      - @args->salt is not NULL and @args->salt_length is 0, OEAP encryption.
 *      - If key descriptor is not correctly defined. No key id and no key
 *        buffer or not a RSA key type.
 *      - In case of using plaintext key, modulus and public buffer are NULL or
 *        corresponding length are 0.
 *      - Signature algorithm is not an asymmetric encryption algorithm.
 *      - Additional invalid parameters returned by the subsystem.
 *  - Other error code from &enum smw_status_code
 */
enum smw_status_code
smw_asymmetric_encrypt(struct smw_asymmetric_encryption_args *args);

/**
 * smw_asymmetric_decrypt() - Decrypt a message
 * @args: Pointer to asymmetric encryption and decryption arguments structure.
 *
 * This function decrypts a message using a RSA key present in the Secure
 * Subsystem storage identified by the key descriptor identifier or a plaintext
 * key value filled in the key descriptor RSA private buffers; modulus and
 * private data.
 *
 * On operation completion, the @args->output_length is updated to the correct
 * value when:\
 *
 *  - Output length is bigger than expected. In this case, operation succeeds.
 *  - Output length is shorter than expected. In this case, operation fails and
 *    returns SMW_STATUS_OUTPUT_TOO_SHORT.
 *
 * Return:
 *  - SMW_STATUS_OK:
 *      Operation succeeded.
 *  - SMW_STATUS_INVALID_PARAM:
 *      - @args is NULL.
 *      - @args->key_descriptor is NULL.
 *      - @args->input is NULL.
 *      - @args->input_length is 0.
 *      - @args->output is NULL.
 *      - @args->output is not NULL and @args->output_length is 0.
 *      - @args->salt is NULL and @args->salt_length is not 0, OEAP encryption.
 *      - @args->salt is not NULL and @args->salt_length is 0, OEAP encryption.
 *      - If key descriptor is not correctly defined. No key id and no key
 *        buffer or not a RSA key type.
 *      - In case of using plaintext key, modulus and private buffer are NULL or
 *        corresponding length are 0.
 *      - Signature algorithm is not an asymmetric encryption algorithm.
 *      - Additional invalid parameters returned by the subsystem.
 *  - Other error code from &enum smw_status_code
 */
enum smw_status_code
smw_asymmetric_decrypt(struct smw_asymmetric_encryption_args *args);

#endif /* __SMW_CRYPTO_ASYMMETRIC_ENCRYPTION_H__ */
