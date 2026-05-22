/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2022-2026 NXP
 */

#ifndef __PSA_CRYPTO_ASYMMETRIC_ENCRYPTION_H__
#define __PSA_CRYPTO_ASYMMETRIC_ENCRYPTION_H__

/**
 * psa_asymmetric_encrypt() - Encrypt a short message with a public key.
 * @key: [in] Identifier of the key to use for the operation. It must be a
 *            public key or an asymmetric key pair. It must allow the usage
 *            PSA_KEY_USAGE_ENCRYPT.
 * @alg: [in] An asymmetric encryption algorithm such that the
 *            :c:macro:`PSA_ALG_IS_ASYMMETRIC_ENCRYPTION` is true.
 * @input: [in] The message to encrypt.
 * @input_length: [in] Size of the @input buffer in bytes.
 * @salt: [in] A salt or label, if supported by the encryption algorithm. If the
 *             algorithm does not support a salt, pass NULL. If the algorithm
 *             supports an optional salt, pass NULL to indicate that there is
 *             no salt.
 * @salt_length: [in] Size of the @salt buffer in bytes. If salt is NULL,
 *                    pass 0.
 * @output: [out] Buffer where the encrypted message is to be written.
 * @output_size: [in] Size of the @output buffer in bytes.
 * @output_length: [out] On success, the number of bytes that make up the
 *                       returned output.
 *
 * For PSA_ALG_RSA_PKCS1V15_CRYPT, no salt is supported.
 *
 * The @output_size parameter must be appropriate for the selected algorithm
 * and key\:
 *
 *  - The required output size is :c:macro:`PSA_ASYMMETRIC_ENCRYPT_OUTPUT_SIZE`
 *    where key_type and key_bits are the type and bit-size respectively of
 *    @key.
 *  - :c:macro:`PSA_ASYMMETRIC_ENCRYPT_OUTPUT_MAX_SIZE` evaluates to the maximum
 *    output size of any supported asymmetric encryption.
 *
 * Return:
 *  - PSA_SUCCESS:
 *      Success.
 *  - PSA_ERROR_INVALID_HANDLE:
 *      @key is not a valid key identifier.
 *  - PSA_ERROR_NOT_PERMITTED:
 *      The key does not have the PSA_KEY_USAGE_ENCRYPT flag, or it does not
 *      permit the requested algorithm.
 *  - PSA_ERROR_BUFFER_TOO_SMALL:
 *      The size of the @output buffer is too small.
 *      :c:macro:`PSA_ASYMMETRIC_ENCRYPT_OUTPUT_SIZE` or
 *      :c:macro:`PSA_ASYMMETRIC_ENCRYPT_OUTPUT_MAX_SIZE` can be used to
 *      determine the required buffer size.
 *  - PSA_ERROR_INVALID_ARGUMENT:
 *      - @alg is not an asymmetric encryption algorithm.
 *      - @key is not a public key or asymmetric key pair, that is compatible
 *        with @alg.
 *      - @input_length is not valid for the algorithm and key type.
 *      - @salt_length is not valid for the algorithm and key type.
 *  - PSA_ERROR_NOT_SUPPORTED:
 *      - @alg is not supported.
 *      - @key is not supported for use with @alg.
 *      - @input_length or @salt_length are too large.
 *  - PSA_ERROR_INSUFFICIENT_MEMORY
 *  - PSA_ERROR_COMMUNICATION_FAILURE
 *  - PSA_ERROR_CORRUPTION_DETECTED
 *  - PSA_ERROR_STORAGE_FAILURE
 *  - PSA_ERROR_DATA_CORRUPT
 *  - PSA_ERROR_DATA_INVALID
 *  - PSA_ERROR_INSUFFICIENT_ENTROPY
 *  - PSA_ERROR_BAD_STATE:
 *      The library has not been previously initialized by psa_crypto_init().
 */
psa_status_t psa_asymmetric_encrypt(psa_key_id_t key, psa_algorithm_t alg,
				    const uint8_t *input, size_t input_length,
				    const uint8_t *salt, size_t salt_length,
				    uint8_t *output, size_t output_size,
				    size_t *output_length);

/**
 * psa_asymmetric_decrypt() - Decrypt a short message with a private key.
 * @key: [in] Identifier of the key to use for the operation. It must be an
 *            asymmetric key pair. It must allow the usage
 *            PSA_KEY_USAGE_DECRYPT.
 * @alg: [in] An asymmetric encryption algorithm that is compatible with the
 *            type of key.
 * @input: [in] The message to decrypt.
 * @input_length: [in] Size of the @input buffer in bytes.
 * @salt: [in] A salt or label, if supported by the encryption algorithm. If the
 *             algorithm does not support a salt, pass NULL. If the algorithm
 *             supports an optional salt, pass NULL to indicate that there is
 *             no salt.
 * @salt_length: [in] Size of the @salt buffer in bytes. If @salt is NULL,
 *                    pass 0.
 * @output: [out] Buffer where the decrypted message is to be written.
 * @output_size: [in] Size of the @output buffer in bytes.
 * @output_length: [out] On success, the number of bytes that make up the
 *                       returned output.
 *
 * For PSA_ALG_RSA_PKCS1V15_CRYPT, no salt is supported.
 *
 * The @output_size parameter must be appropriate for the selected algorithm
 * and key\:
 *
 *  - The required output size is :c:macro:`PSA_ASYMMETRIC_DECRYPT_OUTPUT_SIZE`
 *    where key_type and key_bits are the type and bit-size respectively of
 *    @key.
 *  - :c:macro:`PSA_ASYMMETRIC_DECRYPT_OUTPUT_MAX_SIZE` evaluates to the maximum
 *    output size of any supported asymmetric decryption.
 *
 * Return:
 *  - PSA_SUCCESS:
 *      Success.
 *  - PSA_ERROR_INVALID_HANDLE:
 *      @key is not a valid key identifier.
 *  - PSA_ERROR_NOT_PERMITTED:
 *      The key does not have the PSA_KEY_USAGE_DECRYPT flag, or it does not
 *      permit the requested algorithm.
 *  - PSA_ERROR_BUFFER_TOO_SMALL:
 *      The size of the @output buffer is too small.
 *      :c:macro:`PSA_ASYMMETRIC_DECRYPT_OUTPUT_SIZE` or
 *      :c:macro:`PSA_ASYMMETRIC_DECRYPT_OUTPUT_MAX_SIZE` can be used to
 *      determine the required buffer size.
 *  - PSA_ERROR_INVALID_ARGUMENT:
 *      - @alg is not an asymmetric encryption algorithm.
 *      - @key is not an asymmetric key pair, that is compatible with @alg.
 *      - @input_length is not valid for the algorithm and key type.
 *      - @salt_length is not valid for the algorithm and key type.
 *  - PSA_ERROR_NOT_SUPPORTED:
 *      - @alg is not supported.
 *      - @key is not supported for use with @alg.
 *      - @input_length or @salt_length are too large.
 *  - PSA_ERROR_INSUFFICIENT_MEMORY
 *  - PSA_ERROR_COMMUNICATION_FAILURE
 *  - PSA_ERROR_CORRUPTION_DETECTED
 *  - PSA_ERROR_STORAGE_FAILURE
 *  - PSA_ERROR_DATA_CORRUPT
 *  - PSA_ERROR_DATA_INVALID
 *  - PSA_ERROR_INSUFFICIENT_ENTROPY
 *  - PSA_ERROR_INVALID_PADDING
 *  - PSA_ERROR_BAD_STATE:
 *      The library has not been previously initialized by psa_crypto_init().
 */
psa_status_t psa_asymmetric_decrypt(psa_key_id_t key, psa_algorithm_t alg,
				    const uint8_t *input, size_t input_length,
				    const uint8_t *salt, size_t salt_length,
				    uint8_t *output, size_t output_size,
				    size_t *output_length);

#endif /* __PSA_CRYPTO_ASYMMETRIC_ENCRYPTION_H__ */
