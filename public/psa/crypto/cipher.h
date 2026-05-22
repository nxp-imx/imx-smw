/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2022-2026 NXP
 */

#ifndef __PSA_CRYPTO_CIPHER_H__
#define __PSA_CRYPTO_CIPHER_H__

/**
 * typedef psa_cipher_operation_t - The type of the state object for multi-part
 *                                  cipher operations.
 *
 * Before calling any function on a cipher operation object, the application
 * must initialize it by any of the following means\:
 *
 *  - Set the object to all-bits-zero, for example\:
 *
 *    .. code-block:: c
 *
 *       psa_cipher_operation_t operation;
 *       memset(&operation, 0, sizeof(operation));
 *
 *  - Initialize the object to logical zero values by declaring the object as
 *    static or global without an explicit initializer, for example\:
 *
 *    .. code-block:: c
 *
 *       static psa_cipher_operation_t operation;
 *
 *  - Initialize the object to the initializer
 *    :c:macro:`PSA_CIPHER_OPERATION_INIT`, for example\:
 *
 *    .. code-block:: c
 *
 *       psa_cipher_operation_t operation = PSA_CIPHER_OPERATION_INIT;
 *
 *  - Assign the result of the function :c:func:`psa_cipher_operation_init` to
 *    the object, for example\:
 *
 *    .. code-block:: c
 *
 *       psa_cipher_operation_t operation;
 *       operation = psa_cipher_operation_init();
 */
typedef struct psa_cipher_operation_s psa_cipher_operation_t;

/**
 * psa_cipher_operation_init() - Return an initial value for a cipher operation
 *                               object.
 *
 * Return:
 * Initialized value of cipher operation object.
 */
static psa_cipher_operation_t psa_cipher_operation_init(void);

/**
 * psa_cipher_encrypt() - Encrypt a message using a symmetric cipher.
 * @key: [in] Identifier of the key to use for the operation. It must allow the
 *            usage PSA_KEY_USAGE_ENCRYPT.
 * @alg: [in] The cipher algorithm to compute such that
 *            :c:macro:`PSA_ALG_IS_CIPHER` is true.
 * @input: [in] Buffer containing the message to encrypt.
 * @input_length: [in] Size of the @input buffer in bytes.
 * @output: [out] Buffer where the output is to be written. The output contains
 *                the IV followed by the ciphertext proper.
 * @output_size: [in] Size of the @output buffer in bytes.
 * @output_length: [out] On success, the number of bytes that make up the
 *                       output.
 *
 * This function encrypts a message with a random initialization vector (IV).
 * The length of the IV is :c:macro:`PSA_CIPHER_IV_LENGTH` where key_type is
 * the type of @key. The output of psa_cipher_encrypt() is the IV followed by
 * the ciphertext.
 *
 * Use the multi-part operation interface with a &typedef psa_cipher_operation_t
 * object to provide other forms of IV or to manage the IV and ciphertext
 * independently.
 *
 * The @output_size parameter must be appropriate for the selected algorithm
 * and key\:
 *
 *  - A sufficient output size is :c:macro:`PSA_CIPHER_ENCRYPT_OUTPUT_SIZE`
 *    where key_type is the type of @key.
 *  - :c:macro:`PSA_CIPHER_ENCRYPT_OUTPUT_MAX_SIZE` evaluates to the maximum
 *    output size of any supported cipher encryption.
 *
 * Return:
 *  - PSA_SUCCESS:
 *      Success.
 *  - PSA_ERROR_INVALID_HANDLE:
 *      @key is not a valid key identifier.
 *  - PSA_ERROR_NOT_PERMITTED:
 *      The key does not have the PSA_KEY_USAGE_ENCRYPT flag, or it does not
 *      permit the requested algorithm.
 *  - PSA_ERROR_INVALID_ARGUMENT:
 *      - @alg is not a cipher algorithm.
 *      - @key is not compatible with @alg.
 *      - @input_length is not valid for the algorithm and key type. The length
 *        must be a multiple of block size.
 *  - PSA_ERROR_NOT_SUPPORTED:
 *      - @alg is not supported.
 *      - @key is not supported for use with @alg.
 *      - @input_length is too large.
 *  - PSA_ERROR_BUFFER_TOO_SMALL:
 *      The @output_size is too small. :c:macro:`PSA_CIPHER_ENCRYPT_OUTPUT_SIZE`
 *      or :c:macro:`PSA_CIPHER_ENCRYPT_OUTPUT_MAX_SIZE` can be used to
 *      determine the required buffer size.
 *  - PSA_ERROR_INSUFFICIENT_MEMORY
 *  - PSA_ERROR_COMMUNICATION_FAILURE
 *  - PSA_ERROR_CORRUPTION_DETECTED
 *  - PSA_ERROR_STORAGE_FAILURE
 *  - PSA_ERROR_DATA_CORRUPT
 *  - PSA_ERROR_DATA_INVALID
 *  - PSA_ERROR_BAD_STATE:
 *      The library has not been previously initialized by psa_crypto_init().
 */
psa_status_t psa_cipher_encrypt(psa_key_id_t key, psa_algorithm_t alg,
				const uint8_t *input, size_t input_length,
				uint8_t *output, size_t output_size,
				size_t *output_length);

/**
 * psa_cipher_decrypt() - Decrypt a message using a symmetric cipher.
 * @key: [in] Identifier of the key to use for the operation. It must remain
 *            valid until the operation terminates. It must allow the usage
 *            PSA_KEY_USAGE_DECRYPT.
 * @alg: [in] The cipher algorithm to compute such that
 *            :c:macro:`PSA_ALG_IS_CIPHER` is true.
 * @input: [in] Buffer containing the message to decrypt. This consists of the
 *              IV followed by the ciphertext proper.
 * @input_length: [in] Size of the @input buffer in bytes.
 * @output: [out] Buffer where the plaintext is to be written.
 * @output_size: [in] Size of the @output buffer in bytes.
 * @output_length: [out] On success, the number of bytes that make up the
 *                       output.
 *
 * This function decrypts a message encrypted with a symmetric cipher.
 *
 * The input to this function must contain the IV followed by the ciphertext,
 * as output by psa_cipher_encrypt(). The IV must be
 * :c:macro:`PSA_CIPHER_IV_LENGTH` bytes in length, where key_type is the type
 * of @key.
 *
 * Use the multi-part operation interface with a &typedef psa_cipher_operation_t
 * object to decrypt data which is not in the expected input format.
 *
 * The @output_size parameter must be appropriate for the selected algorithm
 * and key\:
 *
 *  - A sufficient output size is :c:macro:`PSA_CIPHER_DECRYPT_OUTPUT_SIZE`
 *    where key_type is the type of @key.
 *  - :c:macro:`PSA_CIPHER_DECRYPT_OUTPUT_MAX_SIZE` evaluates to the maximum
 *    output size of any supported cipher decryption.
 *
 * Return:
 *  - PSA_SUCCESS:
 *      Success.
 *  - PSA_ERROR_INVALID_HANDLE:
 *      @key is not a valid key identifier.
 *  - PSA_ERROR_NOT_PERMITTED:
 *      The key does not have the PSA_KEY_USAGE_DECRYPT flag, or it does not
 *      permit the requested algorithm.
 *  - PSA_ERROR_INVALID_ARGUMENT:
 *      - @alg is not a cipher algorithm.
 *      - @key is not compatible with @alg.
 *      - @input_length is not valid for the algorithm and key type. The length
 *        must be a multiple of block size.
 *  - PSA_ERROR_NOT_SUPPORTED:
 *      - @alg is not supported.
 *      - @key is not supported for use with @alg.
 *      - @input_length is too large.
 *  - PSA_ERROR_BUFFER_TOO_SMALL:
 *      The @output_size is too small. :c:macro:`PSA_CIPHER_DECRYPT_OUTPUT_SIZE`
 *      or :c:macro:`PSA_CIPHER_DECRYPT_OUTPUT_MAX_SIZE` can be used to
 *      determine the required buffer size.
 *  - PSA_ERROR_INSUFFICIENT_MEMORY
 *  - PSA_ERROR_COMMUNICATION_FAILURE
 *  - PSA_ERROR_STORAGE_FAILURE
 *  - PSA_ERROR_DATA_CORRUPT
 *  - PSA_ERROR_DATA_INVALID
 *  - PSA_ERROR_CORRUPTION_DETECTED
 *  - PSA_ERROR_BAD_STATE:
 *      The library has not been previously initialized by psa_crypto_init().
 */
psa_status_t psa_cipher_decrypt(psa_key_id_t key, psa_algorithm_t alg,
				const uint8_t *input, size_t input_length,
				uint8_t *output, size_t output_size,
				size_t *output_length);

/**
 * psa_cipher_encrypt_setup() - Set the key for a multi-part symmetric
 *                              encryption operation.
 * @operation: [in] The operation object to set up. It must have been
 *                  initialized as per the documentation for
 *                  &typedef psa_cipher_operation_t and not yet in use.
 * @key: [in] Identifier of the key to use for the operation. It must remain
 *            valid until the operation terminates. It must allow the usage
 *            PSA_KEY_USAGE_ENCRYPT.
 * @alg: [in] The cipher algorithm to compute such that
 *            :c:macro:`PSA_ALG_IS_CIPHER` is true.
 *
 * .. warning::
 *    Not supported.
 *
 * After a successful call to psa_cipher_encrypt_setup(), the application must
 * eventually terminate the operation. The following events terminate an
 * operation:
 *
 *  - A successful call to psa_cipher_finish().
 *  - A call to psa_cipher_abort().
 *
 * If psa_cipher_encrypt_setup() returns an error, the operation object is
 * unchanged. If a subsequent function call with an active operation returns an
 * error, the operation enters an error state.
 *
 * To abandon an active operation, or reset an operation in an error state,
 * call psa_cipher_abort().
 *
 * Return:
 *  - PSA_SUCCESS:
 *      Success. The operation is now active.
 *  - PSA_ERROR_INVALID_HANDLE:
 *      @key is not a valid key identifier.
 *  - PSA_ERROR_NOT_PERMITTED:
 *      The key does not have the PSA_KEY_USAGE_ENCRYPT flag, or it does not
 *      permit the requested algorithm.
 *  - PSA_ERROR_INVALID_ARGUMENT:
 *      - @alg is not a cipher algorithm.
 *      - @key is not compatible with @alg.
 *  - PSA_ERROR_NOT_SUPPORTED:
 *      - @alg is not supported.
 *      - @key is not supported for use with @alg.
 *  - PSA_ERROR_INSUFFICIENT_MEMORY
 *  - PSA_ERROR_COMMUNICATION_FAILURE
 *  - PSA_ERROR_CORRUPTION_DETECTED
 *  - PSA_ERROR_STORAGE_FAILURE
 *  - PSA_ERROR_DATA_CORRUPT
 *  - PSA_ERROR_DATA_INVALID
 *  - PSA_ERROR_BAD_STATE:
 *      - The operation state is not valid: it must be inactive.
 *      - The library has not been previously initialized by psa_crypto_init().
 */
psa_status_t psa_cipher_encrypt_setup(psa_cipher_operation_t *operation,
				      psa_key_id_t key, psa_algorithm_t alg);

/**
 * psa_cipher_decrypt_setup() - Set the key for a multi-part symmetric
 *                              decryption operation.
 * @operation: [in] The operation object to set up. It must have been
 *                  initialized as per the documentation for
 *                  &typedef psa_cipher_operation_t and not yet in use.
 * @key: [in] Identifier of the key to use for the operation. It must remain
 *            valid until the operation terminates. It must allow the usage
 *            PSA_KEY_USAGE_DECRYPT.
 * @alg: [in] The cipher algorithm to compute such that
 *            :c:macro:`PSA_ALG_IS_CIPHER` is true.
 *
 * .. warning::
 *    Not supported.
 *
 * After a successful call to psa_cipher_decrypt_setup(), the application must
 * eventually terminate the operation. The following events terminate an
 * operation\:
 *
 *  - A successful call to psa_cipher_finish().
 *  - A call to psa_cipher_abort().
 *
 * If psa_cipher_decrypt_setup() returns an error, the operation object is
 * unchanged. If a subsequent function call with an active operation returns
 * an error, the operation enters an error state.
 *
 * To abandon an active operation, or reset an operation in an error state,
 * call psa_cipher_abort().
 *
 * Return:
 *  - PSA_SUCCESS:
 *      Success. The operation is now active.
 *  - PSA_ERROR_INVALID_HANDLE
 *  - PSA_ERROR_NOT_PERMITTED:
 *      The key does not have the PSA_KEY_USAGE_DECRYPT flag, or it does not
 *      permit the requested algorithm.
 *  - PSA_ERROR_INVALID_ARGUMENT:
 *      - @alg is not a cipher algorithm.
 *      - @key is not compatible with @alg.
 *  - PSA_ERROR_NOT_SUPPORTED:
 *      - @alg is not supported.
 *      - @key is not supported for use with @alg.
 *  - PSA_ERROR_INSUFFICIENT_MEMORY
 *  - PSA_ERROR_COMMUNICATION_FAILURE
 *  - PSA_ERROR_CORRUPTION_DETECTED
 *  - PSA_ERROR_STORAGE_FAILURE
 *  - PSA_ERROR_DATA_CORRUPT
 *  - PSA_ERROR_DATA_INVALID
 *  - PSA_ERROR_BAD_STATE:
 *      - The operation state is not valid: it must be inactive.
 *      - The library has not been previously initialized by psa_crypto_init().
 */
psa_status_t psa_cipher_decrypt_setup(psa_cipher_operation_t *operation,
				      psa_key_id_t key, psa_algorithm_t alg);

/**
 * psa_cipher_generate_iv() - Generate an initialization vector (IV) for a
 *                            symmetric encryption operation.
 * @operation: [in] Active cipher operation.
 * @iv: [out] Buffer where the generated IV is to be written.
 * @iv_size: [in] Size of the @iv buffer in bytes. This must be at least
 *           :c:macro:`PSA_CIPHER_IV_LENGTH` where key_type and alg are type of
 *           key and the algorithm respectively that were used to set up the
 *           cipher operation.
 * @iv_length: [out] On success, the number of bytes of the generated IV.
 *
 * .. warning::
 *    Not supported.
 *
 * This function generates a random IV, nonce or initial counter value for the
 * encryption operation as appropriate for the chosen algorithm, key type and
 * key size.
 *
 * The generated IV is always the default length for the key and algorithm, the
 * :c:macro:`PSA_CIPHER_IV_LENGTH`, where key_type is the type of @key and alg
 * is the algorithm that were used to set up the operation can be used to
 * get the length. To generate different lengths of IV, use
 * psa_generate_random() and psa_cipher_set_iv().
 *
 * If the cipher algorithm does not use an IV, calling this function returns a
 * PSA_ERROR_BAD_STATE error. For these algorithms,
 * :c:macro:`PSA_CIPHER_IV_LENGTH` will be zero.
 *
 * The application must call psa_cipher_encrypt_setup() before calling this
 * function.
 *
 * If this function returns an error status, the operation enters an error state
 * and must be aborted by calling psa_cipher_abort().
 *
 * Return:
 *  - PSA_SUCCESS:
 *      Success.
 *  - PSA_ERROR_BUFFER_TOO_SMALL:
 *      The size of the @iv buffer is too small. :c:macro:`PSA_CIPHER_IV_LENGTH`
 *      or :c:macro:`PSA_CIPHER_IV_MAX_SIZE` can be used to determine the
 *      required buffer size.
 *  - PSA_ERROR_INSUFFICIENT_MEMORY
 *  - PSA_ERROR_COMMUNICATION_FAILURE
 *  - PSA_ERROR_CORRUPTION_DETECTED
 *  - PSA_ERROR_STORAGE_FAILURE
 *  - PSA_ERROR_DATA_CORRUPT
 *  - PSA_ERROR_DATA_INVALID
 *      - The cipher algorithm does not use an IV.
 *      - The operation state is not valid: it must be active, with no IV set.
 *      - The library has not been previously initialized by psa_crypto_init().
 */
psa_status_t psa_cipher_generate_iv(psa_cipher_operation_t *operation,
				    uint8_t *iv, size_t iv_size,
				    size_t *iv_length);

/**
 * psa_cipher_set_iv() - Set the initialization vector (IV) for a symmetric
 *                       encryption or decryption operation.
 * @operation: [in] Active cipher operation.
 * @iv: [in] Buffer containing the IV to use.
 * @iv_length: [in] Size of the IV in bytes.
 *
 * .. warning::
 *    Not supported.
 *
 * This function sets the IV, nonce or initial counter value for the encryption
 * or decryption operation.
 *
 * If the cipher algorithm does not use an IV, calling this function returns a
 * PSA_ERROR_BAD_STATE error. For these algorithms,
 * :c:macro:`PSA_CIPHER_IV_LENGTH` will be zero.
 *
 * The application must call psa_cipher_encrypt_setup() or
 * psa_cipher_decrypt_setup() before calling this function.
 *
 * If this function returns an error status, the operation enters an error state
 * and must be aborted by calling psa_cipher_abort().
 *
 * .. note::
 *    When encrypting, psa_cipher_generate_iv() is recommended instead of using
 *    this function, unless implementing a protocol that requires a non-random
 *    IV.
 *
 * Return:
 *  - PSA_SUCCESS:
 *      Success.
 *  - PSA_ERROR_INVALID_ARGUMENT:
 *      - The chosen algorithm does not use an IV.
 *      - @iv_length is not valid for the chosen algorithm.
 *  - PSA_ERROR_NOT_SUPPORTED:
 *      The @iv_length is not supported for use with the operation’s algorithm
 *      and key.
 *  - PSA_ERROR_INSUFFICIENT_MEMORY
 *  - PSA_ERROR_COMMUNICATION_FAILURE
 *  - PSA_ERROR_CORRUPTION_DETECTED
 *  - PSA_ERROR_STORAGE_FAILURE
 *  - PSA_ERROR_DATA_CORRUPT
 *  - PSA_ERROR_DATA_INVALID
 *  - PSA_ERROR_BAD_STATE:
 *      - The cipher algorithm does not use an IV.
 *      - The operation state is not valid: it must be an active cipher encrypt
 *        operation, with no IV set.
 *      - The library has not been previously initialized by psa_crypto_init().
 */
psa_status_t psa_cipher_set_iv(psa_cipher_operation_t *operation,
			       const uint8_t *iv, size_t iv_length);

/**
 * psa_cipher_update() - Encrypt or decrypt a message fragment in an active
 *                       cipher operation.
 * @operation: [in] Active cipher operation.
 * @input: [in] Buffer containing the message fragment to encrypt or decrypt.
 * @input_length: [in] Size of the @input buffer in bytes.
 * @output: [out] Buffer where the output is to be written.
 * @output_size: [in] Size of the @output buffer in bytes.
 * @output_length: [out] On success, the number of bytes that make up the
 *                       returned output.
 *
 * .. warning::
 *    Not supported.
 *
 * The @output_size parameter must be appropriate for the selected algorithm
 * and key\:
 *
 *  - A sufficient output size is :c:macro:`PSA_CIPHER_UPDATE_OUTPUT_SIZE`
 *    where key_type is the type of @key and alg is the algorithm that were used
 *    to set up the operation.
 *  - :c:macro:`PSA_CIPHER_UPDATE_OUTPUT_MAX_SIZE` evaluates to the maximum
 *    output size of any supported cipher algorithm.
 *
 * The following must occur before calling this function\:
 *
 *  #. Call either psa_cipher_encrypt_setup() or psa_cipher_decrypt_setup().
 *     The choice of setup function determines whether this function encrypts or
 *     decrypts its input.
 *  #. If the algorithm requires an IV, call psa_cipher_generate_iv() or
 *     psa_cipher_set_iv(). psa_cipher_generate_iv() is recommended when
 *     encrypting.
 *
 * If this function returns an error status, the operation enters an error state
 * and must be aborted by calling psa_cipher_abort().
 *
 * Return:
 *  - PSA_SUCCESS:
 *      Success.
 *  - PSA_ERROR_BUFFER_TOO_SMALL:
 *      The size of the @output buffer is too small.
 *      :c:macro:`PSA_CIPHER_UPDATE_OUTPUT_SIZE` or
 *      :c:macro:`PSA_CIPHER_UPDATE_OUTPUT_MAX_SIZE` can be used to determine
 *      the required buffer size.
 *  - PSA_ERROR_INVALID_ARGUMENT:
 *      The total input size passed to this operation is too large for this
 *      particular algorithm.
 *  - PSA_ERROR_NOT_SUPPORTED:
 *      The total input size passed to this operation is too large.
 *  - PSA_ERROR_INSUFFICIENT_MEMORY
 *  - PSA_ERROR_COMMUNICATION_FAILURE
 *  - PSA_ERROR_CORRUPTION_DETECTED
 *  - PSA_ERROR_STORAGE_FAILURE
 *  - PSA_ERROR_DATA_CORRUPT
 *  - PSA_ERROR_DATA_INVALID
 *  - PSA_ERROR_BAD_STATE:
 *      - The operation state is not valid: it must be active, with an IV set
 *        if required for the algorithm.
 *      - The library has not been previously initialized by psa_crypto_init().
 */
psa_status_t psa_cipher_update(psa_cipher_operation_t *operation,
			       const uint8_t *input, size_t input_length,
			       uint8_t *output, size_t output_size,
			       size_t *output_length);

/**
 * psa_cipher_finish() - Finish encrypting or decrypting a message in a cipher
 *                       operation.
 * @operation: [in] Active cipher operation.
 * @output: [out] Buffer where the output is to be written.
 * @output_size: [in] Size of the @output buffer in bytes.
 * @output_length: [out] On success, the number of bytes that make up the
 *                       returned output.
 *
 * .. warning::
 *    Not supported.
 *
 * The @output_size parameter must be appropriate for the selected algorithm
 * and key\:
 *
 *  - A sufficient output size is :c:macro:`PSA_CIPHER_FINISH_OUTPUT_SIZE`
 *    where key_type is the type of key and alg is the algorithm that were used
 *    to set up the operation.
 *  - :c:macro:`PSA_CIPHER_FINISH_OUTPUT_MAX_SIZE` evaluates to the maximum
 *    output size of any supported cipher algorithm.
 *
 * The application must call psa_cipher_encrypt_setup() or
 * psa_cipher_decrypt_setup() before calling this function. The choice of setup
 * function determines whether this function encrypts or decrypts its input.
 *
 * This function finishes the encryption or decryption of the message formed by
 * concatenating the inputs passed to preceding calls to psa_cipher_update().
 *
 * When this function returns successfully, the operation becomes inactive. If
 * this function returns an error status, the operation enters an error state
 * and must be aborted by calling psa_cipher_abort().
 *
 * Return:
 *  - PSA_SUCCESS:
 *      Success.
 *  - PSA_ERROR_INVALID_ARGUMENT:
 *      The total input size passed to this operation is not valid for this
 *      particular algorithm. The total input size is not a multiple of the
 *      block size.
 *  - PSA_ERROR_INVALID_PADDING:
 *      This is a decryption operation for an algorithm that includes padding,
 *      and the ciphertext does not contain valid padding.
 *  - PSA_ERROR_BUFFER_TOO_SMALL:
 *      The size of the @output buffer is too small.
 *      :c:macro:`PSA_CIPHER_FINISH_OUTPUT_SIZE` or
 *      :c:macro:`PSA_CIPHER_FINISH_OUTPUT_MAX_SIZE` can be used to determine
 *      the required buffer size.
 *  - PSA_ERROR_INSUFFICIENT_MEMORY
 *  - PSA_ERROR_COMMUNICATION_FAILURE
 *  - PSA_ERROR_CORRUPTION_DETECTED
 *  - PSA_ERROR_STORAGE_FAILURE
 *  - PSA_ERROR_DATA_CORRUPT
 *  - PSA_ERROR_DATA_INVALID
 *  - PSA_ERROR_BAD_STATE:
 *      - The operation state is not valid: it must be active, with an IV set
 *        if required for the algorithm.
 *      - The library has not been previously initialized by psa_crypto_init().
 */
psa_status_t psa_cipher_finish(psa_cipher_operation_t *operation,
			       uint8_t *output, size_t output_size,
			       size_t *output_length);

/**
 * psa_cipher_abort() - Abort a cipher operation.
 * @operation: [in] Initialized cipher operation.
 *
 * .. warning::
 *    Not supported.
 *
 * Aborting an operation frees all associated resources except for the
 * @operation object itself. Once aborted, the operation object can be reused
 * for another operation by calling psa_cipher_encrypt_setup() or
 * psa_cipher_decrypt_setup() again.
 *
 * This function can be called any time after the operation object has been
 * initialized as described in &typedef psa_cipher_operation_t.
 *
 * In particular, calling psa_cipher_abort() after the operation has been
 * terminated by a call to psa_cipher_abort() or psa_cipher_finish() is safe
 * and has no effect.
 *
 * Return:
 *  - PSA_SUCCESS:
 *      Success. The operation object can now be discarded or reused.
 *  - PSA_ERROR_COMMUNICATION_FAILURE
 *  - PSA_ERROR_CORRUPTION_DETECTED
 *  - PSA_ERROR_BAD_STATE:
 *      The library has not been previously initialized by psa_crypto_init().
 */
psa_status_t psa_cipher_abort(psa_cipher_operation_t *operation);

#endif /* __PSA_CRYPTO_CIPHER_H__ */
