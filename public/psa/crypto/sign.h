/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2022-2026 NXP
 */

#ifndef __PSA_CRYPTO_SIGN_H__
#define __PSA_CRYPTO_SIGN_H__

/**
 * psa_sign_message() - Sign a message with a private key. For hash-and-sign
 *                      algorithms, this includes the hashing step.
 * @key: [in] Identifier of the key to use for the operation. It must be an
 *            asymmetric key pair. The key must allow the usage
 *            PSA_KEY_USAGE_SIGN_MESSAGE.
 * @alg: [in] An asymmetric signature algorithm such that
 *            :c:macro:`PSA_ALG_IS_SIGN_MESSAGE` is true.
 * @input: [in] The input message to sign.
 * @input_length: [in] Size of the @input buffer in bytes.
 * @signature: [out] Buffer where the signature is to be written.
 * @signature_size: [in] Size of the @signature buffer in bytes.
 * @signature_length: [out] On success, the number of bytes that make up the
 *                          returned signature value.
 *
 * The @signature_size parameter must be appropriate for the selected algorithm
 * and key\:
 *
 *  - The required signature size is :c:macro:`PSA_SIGN_OUTPUT_SIZE` where
 *    key_type and key_bits are the type and bit-size respectively of key.
 *  - :c:macro:`PSA_SIGNATURE_MAX_SIZE` evaluates to the maximum signature size
 *    of any supported signature algorithm.
 *
 * Return:
 *  - PSA_SUCCESS
 *      Success.
 *  - PSA_ERROR_INVALID_HANDLE
 *      @key is not a valid key identifier.
 *  - PSA_ERROR_NOT_PERMITTED:
 *      The @key does not have the PSA_KEY_USAGE_SIGN_MESSAGE flag, or it does
 *      not permit the requested algorithm.
 *  - PSA_ERROR_BUFFER_TOO_SMALL:
 *      The size of the signature buffer is too small.
 *      :c:macro:`PSA_SIGN_OUTPUT_SIZE` or :c:macro:`PSA_SIGNATURE_MAX_SIZE`
 *      can be used to determine the required buffer size.
 *  - PSA_ERROR_NOT_SUPPORTED:
 *      - @alg is not supported, or is not an asymmetric signature algorithm
 *        that permits signing a message.
 *      - @key is not supported for use with @alg.
 *      - @input_length is too large.
 *  - PSA_ERROR_INVALID_ARGUMENT:
 *      - @alg is not an asymmetric signature algorithm that permits signing a
 *        message.
 *      - @key is not an asymmetric key pair, that is compatible with @alg.
 *      - @input_length is too large for the algorithm and key type.
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
psa_status_t psa_sign_message(psa_key_id_t key, psa_algorithm_t alg,
			      const uint8_t *input, size_t input_length,
			      uint8_t *signature, size_t signature_size,
			      size_t *signature_length);

/**
 * psa_verify_message() - Verify the signature of a message with a public key.
 *                        For hash-and-sign verification algorithm, this
 *                        includes the hashing step.
 * @key: [in] Identifier of the key to use for the operation. It must be a
 *            public key or an asymmetric key pair. The key must allow the usage
 *            PSA_KEY_USAGE_VERIFY_MESSAGE.
 * @alg: [in] An asymmetric signature algorithm such that
 *            :c:macro:`PSA_ALG_IS_SIGN_MESSAGE` is true.
 * @input: [in] The message whose signature is to be verified.
 * @input_length: [in] Size of the @input buffer in bytes.
 * @signature: [in] Buffer containing the signature to verify.
 * @signature_length: [in] Size of the @signature buffer in bytes.
 *
 * Return:
 *  - PSA_SUCCESS:
 *      Success. The signature is valid.
 *  - PSA_ERROR_INVALID_HANDLE
 *      @key is not a valid key identifier.
 *  - PSA_ERROR_NOT_PERMITTED:
 *      The key does not have the PSA_KEY_USAGE_VERIFY_MESSAGE flag, or it does
 *      not permit the requested algorithm.
 *  - PSA_ERROR_INVALID_SIGNATURE:
 *      The calculated signature of the message does not match the value in
 *      @signature.
 *  - PSA_ERROR_NOT_SUPPORTED:
 *      - @alg is not supported, or is not an asymmetric signature algorithm
 *        that permits verifying a message.
 *      - @key is not supported for use with @alg.
 *      - @input_length is too large.
 *  - PSA_ERROR_INVALID_ARGUMENT:
 *      - @alg is not an asymmetric signature algorithm that permits verifying
 *        a message.
 *      - @key is not an asymmetric key pair, that is compatible with @alg.
 *      - @input_length is too large for the algorithm and key type.
 *  - PSA_ERROR_INSUFFICIENT_MEMORY
 *  - PSA_ERROR_COMMUNICATION_FAILURE
 *  - PSA_ERROR_CORRUPTION_DETECTED
 *  - PSA_ERROR_STORAGE_FAILURE
 *  - PSA_ERROR_DATA_CORRUPT
 *  - PSA_ERROR_DATA_INVALID
 *  - PSA_ERROR_BAD_STATE:
 *      The library has not been previously initialized by psa_crypto_init().
 */
psa_status_t psa_verify_message(psa_key_id_t key, psa_algorithm_t alg,
				const uint8_t *input, size_t input_length,
				const uint8_t *signature,
				size_t signature_length);

/**
 * psa_sign_hash() - Sign a pre-computed hash with a private key.
 * @key: [in] Identifier of the key to use for the operation. It must be an
 *            asymmetric key pair. The key must allow the usage
 *            PSA_KEY_USAGE_SIGN_HASH.
 * @alg: [in] An asymmetric signature algorithm that separates the hash and sign
 *            operations such that :c:macro:`PSA_ALG_IS_SIGN_HASH` is true.
 * @hash: [in] The input to sign. This is usually the hash of a message.
 * @hash_length: [in] Size of the hash buffer in bytes.
 * @signature: [out] Buffer where the signature is to be written.
 * @signature_size: [in] Size of the @signature buffer in bytes.
 * @signature_length: [out] On success, the number of bytes that make up the
 *                          returned signature value.
 *
 * For hash-and-sign signature algorithms, the hash input to this function is
 * the hash of the message to sign. The algorithm used to calculate this hash
 * is encoded in the signature algorithm. For such algorithms, @hash_length
 * must equal the length of the hash output\:
 *
 *   .. code-block:: c
 *
 *      hash_length == PSA_HASH_LENGTH(PSA_ALG_GET_HASH(alg))
 *
 * Specialized signature algorithms can apply a padding or encoding to the hash.
 * In such cases, the encoded hash must be passed to this function. For example,
 * see PSA_ALG_RSA_PKCS1V15_SIGN_RAW.
 *
 * The @signature_size parameter must be appropriate for the selected algorithm
 * and key\:
 *
 *  - The required signature size is :c:macro:`PSA_SIGN_OUTPUT_SIZE` where
 *    key_type and key_bits are the type and bit-size respectively of @key.
 *  - :c:macro:`PSA_SIGNATURE_MAX_SIZE` evaluates to the maximum signature size
 *    of any supported signature algorithm.
 *
 * Return:
 *  - PSA_SUCCESS
 *      Success.
 *  - PSA_ERROR_INVALID_HANDLE
 *      @key is not a valid key identifier.
 *  - PSA_ERROR_NOT_PERMITTED:
 *      The key does not have the PSA_KEY_USAGE_SIGN_HASH flag, or it does not
 *      permit the requested algorithm.
 *  - PSA_ERROR_BUFFER_TOO_SMALL:
 *      The size of the @signature buffer is too small.
 *      :c:macro:`PSA_SIGN_OUTPUT_SIZE` or :c:macro:`PSA_SIGNATURE_MAX_SIZE`
 *      can be used to determine the required buffer size.
 *  - PSA_ERROR_NOT_SUPPORTED:
 *      - @alg is not supported, or is not an asymmetric signature algorithm
 *        that permits signing a pre-computed hash.
 *      - @key is not supported for use with @alg.
 *  - PSA_ERROR_INVALID_ARGUMENT:
 *      - @alg is not an asymmetric signature algorithm that permits signing a
 *        pre-computed hash.
 *      - @key is not an asymmetric key pair, that is compatible with @alg.
 *      - @hash_length is not valid for the algorithm and key type.
 *      - @hash is not a valid input value for the algorithm and key type.
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
psa_status_t psa_sign_hash(psa_key_id_t key, psa_algorithm_t alg,
			   const uint8_t *hash, size_t hash_length,
			   uint8_t *signature, size_t signature_size,
			   size_t *signature_length);

/**
 * psa_verify_hash() - Verify the signature of a pre-computed hash using a
 *                     public key.
 * @key: [in] Identifier of the key to use for the operation. It must be a
 *            public key or an asymmetric key pair. The key must allow the usage
 *            PSA_KEY_USAGE_VERIFY_HASH.
 * @alg: [in] An asymmetric signature algorithm that separates the hash and sign
 *            operations such that :c:macro:`PSA_ALG_IS_SIGN_HASH` is true.
 * @hash: [in] The input whose signature is to be verified. T
 * @hash_length: [in] Size of the @hash buffer in bytes.
 * @signature: [in] Buffer containing the signature to verify.
 * @signature_length: [in] Size of the signature buffer in bytes.
 *
 * For hash-and-sign signature algorithms, the hash input to this function is
 * the hash of the message to verify. The algorithm used to calculate this hash
 * is encoded in the signature algorithm. For such algorithms, @hash_length
 * must equal the length of the hash output\:
 *
 *   .. code-block:: c
 *
 *      hash_length == PSA_HASH_LENGTH(PSA_ALG_GET_HASH(alg))
 *
 * Specialized signature algorithms can apply a padding or encoding to the hash.
 * In such cases, the encoded hash must be passed to this function. For example,
 * see PSA_ALG_RSA_PKCS1V15_SIGN_RAW.
 *
 * Return:
 *  - PSA_SUCCESS:
 *      Success. The signature is valid.
 *  - PSA_ERROR_INVALID_HANDLE
 *      @key is not a valid key identifier.
 *  - PSA_ERROR_NOT_PERMITTED:
 *      The key does not have the PSA_KEY_USAGE_VERIFY_HASH flag, or it does
 *      not permit the requested algorithm.
 *  - PSA_ERROR_INVALID_SIGNATURE:
 *      The calculated signature of the hash does not match the @signature.
 *  - PSA_ERROR_NOT_SUPPORTED:
 *      - @alg is not supported, or is not an asymmetric signature algorithm
 *        that permits verifying a pre-computed hash.
 *      - @key is not supported for use with @alg.
 *  - PSA_ERROR_INVALID_ARGUMENT:
 *      - @alg is not an asymmetric signature algorithm that permits verifying
 *        a pre-computed hash.
 *      - @key is not an asymmetric key pair, that is compatible with @alg.
 *      - @hash_length is not valid for the algorithm and key type.
 *      - @hash is not a valid input value for the algorithm and key type.
 *  - PSA_ERROR_INSUFFICIENT_MEMORY
 *  - PSA_ERROR_COMMUNICATION_FAILURE
 *  - PSA_ERROR_CORRUPTION_DETECTED
 *  - PSA_ERROR_STORAGE_FAILURE
 *  - PSA_ERROR_DATA_CORRUPT
 *  - PSA_ERROR_DATA_INVALID
 *  - PSA_ERROR_BAD_STATE:
 *      The library has not been previously initialized by psa_crypto_init().
 */
psa_status_t psa_verify_hash(psa_key_id_t key, psa_algorithm_t alg,
			     const uint8_t *hash, size_t hash_length,
			     const uint8_t *signature, size_t signature_length);

#endif /* __PSA_CRYPTO_SIGN_H__ */