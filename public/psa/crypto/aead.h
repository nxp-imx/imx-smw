/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2022-2026 NXP
 */

#ifndef __PSA_CRYPTO_AEAD_H__
#define __PSA_CRYPTO_AEAD_H__

/**
 * typedef psa_aead_operation_t - The type of the state object for multi-part
 *                                AEAD operations.
 *
 * Before calling any function on an AEAD operation object, the application must
 * initialize it by any of the following means\:
 *
 *  - Set the object to all-bits-zero, for example\:
 *
 *    .. code-block:: c
 *
 *       psa_aead_operation_t operation;
 *       memset(&operation, 0, sizeof(operation));
 *
 *  - Initialize the object to logical zero values by declaring the object as
 *    static or global without an explicit initializer, for example\:
 *
 *    .. code-block:: c
 *
 *       static psa_aead_operation_t operation;
 *
 *  - Initialize the object to the initializer
 *    :c:macro:`PSA_AEAD_OPERATION_INIT`, for example\:
 *
 *    .. code-block:: c
 *
 *       psa_aead_operation_t operation = PSA_AEAD_OPERATION_INIT;
 *
 *  - Assign the result of the function :c:func:`psa_aead_operation_init` to the
 *    object, for example\:
 *
 *    .. code-block:: c
 *
 *       psa_aead_operation_t operation;
 *
 */
typedef struct psa_aead_operation_s psa_aead_operation_t;

/**
 * psa_aead_operation_init() - Return an initial value for an AEAD operation
 *                             object.
 *
 * .. warning::
 *     Not supported.
 *
 * Return:
 * Return an initial value for an AEAD operation object.
 */
static psa_aead_operation_t psa_aead_operation_init(void);

/**
 * psa_aead_encrypt() - Process an authenticated encryption operation.
 * @key: [in] Identifier of the key to use for the operation. It must allow
 *            the usage PSA_KEY_USAGE_ENCRYPT.
 * @alg: [in] The AEAD algorithm to compute such that :c:macro:`PSA_ALG_IS_AEAD`
 *            is true.
 * @nonce: [in] Nonce or IV to use.
 * @nonce_length: [in] Size of the @nonce buffer in bytes. This must be
 *                     appropriate for the selected algorithm. The default nonce
 *                     size is :c:macro:`PSA_AEAD_NONCE_LENGTH` where key_type
 *                     is the type of @key.
 * @additional_data: [in] Additional data that will be authenticated but not
 *                        encrypted.
 * @additional_data_length: [in] Size of @additional_data in bytes.
 * @plaintext: [in] Data that will be authenticated and encrypted.
 * @plaintext_length: [in] Size of plaintext in bytes.
 * @ciphertext: [out] Output buffer for the authenticated and encrypted data.
 * @ciphertext_size: [in] Size of the @ciphertext buffer in bytes.
 * @ciphertext_length: [out] On success, the size of the output in the
 *                           ciphertext buffer.
 *
 * The @ciphertext_size parameter must be appropriate for the selected algorithm
 * and key\:
 *
 *  - A sufficient output size is :c:macro:`PSA_AEAD_ENCRYPT_OUTPUT_SIZE`
 *    where key_type is the type of @key.
 *  - :c:macro:`PSA_AEAD_ENCRYPT_OUTPUT_MAX_SIZE` evaluates to the maximum
 *    ciphertext size of any supported AEAD encryption.
 *
 * The @ciphertext output parameters does not contain the additional data. For
 * algorithms where the encrypted data and the authentication tag are defined
 * as separate outputs, the authentication tag is appended to the encrypted data.
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
 *      - @alg is not an AEAD algorithm.
 *      - @key is not compatible with @alg.
 *      - @nonce_length is not valid for use with @alg and @key.
 *      - @additional_data_length or @plaintext_length are too large for @alg.
 *  - PSA_ERROR_NOT_SUPPORTED:
 *      - @alg is not supported or is not an AEAD algorithm.
 *      - @key is not supported for use with @alg.
 *      - @nonce_length is not supported for use with @alg and @key.
 *      - @additional_data_length or @plaintext_length are too large.
 *  - PSA_ERROR_INSUFFICIENT_MEMORY
 *  - PSA_ERROR_BUFFER_TOO_SMALL:
 *      The @ciphertext_size is too small.
 *      :c:macro:`PSA_AEAD_ENCRYPT_OUTPUT_SIZE`
 *      or :c:macro:`PSA_AEAD_ENCRYPT_OUTPUT_MAX_SIZE` can be used to determine
 *      the required buffer size.
 *  - PSA_ERROR_COMMUNICATION_FAILURE
 *  - PSA_ERROR_CORRUPTION_DETECTED
 *  - PSA_ERROR_STORAGE_FAILURE
 *  - PSA_ERROR_DATA_CORRUPT
 *  - PSA_ERROR_DATA_INVALID
 *  - PSA_ERROR_BAD_STATE:
 *      The library has not been previously initialized by psa_crypto_init().
 */
psa_status_t psa_aead_encrypt(psa_key_id_t key, psa_algorithm_t alg,
			      const uint8_t *nonce, size_t nonce_length,
			      const uint8_t *additional_data,
			      size_t additional_data_length,
			      const uint8_t *plaintext, size_t plaintext_length,
			      uint8_t *ciphertext, size_t ciphertext_size,
			      size_t *ciphertext_length);

/**
 * psa_aead_decrypt() - Process an authenticated decryption operation.
 * @key: [in] Identifier of the key to use for the operation. It must allow the
 *            usage PSA_KEY_USAGE_DECRYPT.
 * @alg: [in] The AEAD algorithm to compute such that :c:macro:`PSA_ALG_IS_AEAD`
 *            is true.
 * @nonce: [in] Nonce or IV to use.
 * @nonce_length: [in] Size of the @nonce buffer in bytes. This must be
 *                     appropriate for the selected algorithm. The default nonce
 *                     size is :c:macro:`PSA_AEAD_NONCE_LENGTH` where
 *                     key_type is the type of @key.
 * @additional_data: [in] Additional data that has been authenticated but not
 *                        encrypted.
 * @additional_data_length: [in] Size of @additional_data in bytes.
 * @ciphertext: [in] Data that has been authenticated and encrypted.
 * @ciphertext_length: [in] Size of ciphertext in bytes.
 * @plaintext: [out] Output buffer for the decrypted data.
 * @plaintext_size: [in] Size of the @plaintext buffer in bytes.
 * @plaintext_length: [out] On success, the size of the output in the plaintext
 *                          buffer.
 *
 * The @plaintext_size parameter must be appropriate for the selected algorithm
 * and key\:
 *
 *  - A sufficient output size is :c:macro:`PSA_AEAD_DECRYPT_OUTPUT_SIZE`
 *    where key_type is the type of @key.
 *  - :c:macro:`PSA_AEAD_DECRYPT_OUTPUT_MAX_SIZE` evaluates to the maximum
 *    plaintext size of any supported AEAD encryption.
 *
 * The @ciphertext input parameters does not contain the additional data. For
 * algorithms where the encrypted data and the authentication tag are defined
 * as separate inputs, the authentication tag is appended to the encrypted data.
 *
 * Return:
 *  - PSA_SUCCESS:
 *      Success.
 *  - PSA_ERROR_INVALID_HANDLE:
 *      @key is not a valid key identifier.
 *  - PSA_ERROR_INVALID_SIGNATURE:
 *      The ciphertext is not authentic.
 *  - PSA_ERROR_NOT_PERMITTED:
 *      The key does not have the PSA_KEY_USAGE_DECRYPT flag, or it does not
 *      permit the requested algorithm.
 *  - PSA_ERROR_INVALID_ARGUMENT:
 *      - @alg is not an AEAD algorithm.
 *      - @key is not compatible with @alg.
 *      - @nonce_length is not valid for use with @alg and @key.
 *      - @additional_data_length or @ciphertext_length are too large for @alg.
 *  - PSA_ERROR_NOT_SUPPORTED:
 *      - @alg is not supported or is not an AEAD algorithm.
 *      - @key is not supported for use with @alg.
 *      - @nonce_length is not supported for use with @alg and @key.
 *      - @additional_data_length or @ciphertext_length are too large.
 *  - PSA_ERROR_INSUFFICIENT_MEMORY
 *  - PSA_ERROR_BUFFER_TOO_SMALL:
 *      The @plaintext_size is too small. :c:macro:`PSA_AEAD_DECRYPT_OUTPUT_SIZE`
 *      or :c:macro:`PSA_AEAD_DECRYPT_OUTPUT_MAX_SIZE` can be used to determine
 *      the required buffer size.
 *  - PSA_ERROR_COMMUNICATION_FAILURE
 *  - PSA_ERROR_CORRUPTION_DETECTED
 *  - PSA_ERROR_STORAGE_FAILURE
 *  - PSA_ERROR_DATA_CORRUPT
 *  - PSA_ERROR_DATA_INVALID
 *  - PSA_ERROR_BAD_STATE:
 *      The library has not been previously initialized by psa_crypto_init().
 */
psa_status_t psa_aead_decrypt(psa_key_id_t key, psa_algorithm_t alg,
			      const uint8_t *nonce, size_t nonce_length,
			      const uint8_t *additional_data,
			      size_t additional_data_length,
			      const uint8_t *ciphertext,
			      size_t ciphertext_length, uint8_t *plaintext,
			      size_t plaintext_size, size_t *plaintext_length);

/**
 * psa_aead_encrypt_setup() - Set the key for a multi-part authenticated
 *                            encryption operation.
 * @operation: [in] The operation object to set up. It must have been
 *                  initialized as per the documentation for
 *                  &typedef psa_aead_operation_t and not yet in use.
 * @key: [in] Identifier of the key to use for the operation. It must remain
 *            valid until the operation terminates. It must allow the usage
 *            PSA_KEY_USAGE_ENCRYPT.
 * @alg: [in] The AEAD algorithm to compute such that :c:macro:`PSA_ALG_IS_AEAD`
 *            is true.
 *
 * .. warning::
 *    Not supported.
 *
 * After a successful call to psa_aead_encrypt_setup(), the operation is active,
 * and the application must eventually terminate the operation. The following
 * events terminate an operation\:
 *
 *  - A successful call to psa_aead_finish().
 *  - A call to psa_aead_abort().
 *
 * If psa_aead_encrypt_setup() returns an error, the operation object is
 * unchanged. If a subsequent function call with an active operation returns an
 * error, the operation enters an error state.
 *
 * To abandon an active operation, or reset an operation in an error state,
 * call psa_aead_abort().
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
 *      - @alg is not an AEAD algorithm.
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
psa_status_t psa_aead_encrypt_setup(psa_aead_operation_t *operation,
				    psa_key_id_t key, psa_algorithm_t alg);

/**
 * psa_aead_decrypt_setup() - Set the key for a multi-part authenticated
 *                            decryption operation.
 * @operation: [in] The operation object to set up. It must have been
 *                  initialized as per the documentation for
 *                  &typedef psa_aead_operation_t and not yet in use.
 * @key: [in] Identifier of the key to use for the operation. It must remain
 *            valid until the operation terminates. It must allow the usage
 *            PSA_KEY_USAGE_DECRYPT.
 * @alg: [in] The AEAD algorithm to compute such that :c:macro:`PSA_ALG_IS_AEAD`
 *            is true.
 *
 * .. warning::
 *    Not supported.
 *
 * After a successful call to psa_aead_decrypt_setup(), the operation is active,
 * and the application must eventually terminate the operation. The following
 * events terminate an operation\:
 *
 *  - A successful call to psa_aead_verify().
 *  - A call to psa_aead_abort().
 *
 * If psa_aead_decrypt_setup() returns an error, the operation object is
 * unchanged. If a subsequent function call with an active operation returns an
 * error, the operation enters an error state.
 *
 * To abandon an active operation, or reset an operation in an error state,
 * call psa_aead_abort().
 *
 * Return:
 *  - PSA_SUCCESS:
 *      Success. The operation is now active.
 *  - PSA_ERROR_INVALID_HANDLE:
 *       @key is not a valid key identifier.
 *  - PSA_ERROR_NOT_PERMITTED:
 *      The key does not have the PSA_KEY_USAGE_DECRYPT flag, or it does not
 *      permit the requested algorithm.
 *  - PSA_ERROR_INVALID_ARGUMENT:
 *      @alg is not an AEAD algorithm.
 *      @key is not compatible with @alg.
 *  - PSA_ERROR_NOT_SUPPORTED:
 *      @alg is not supported or is not an AEAD algorithm.
 *      @key is not supported for use with @alg.
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
psa_status_t psa_aead_decrypt_setup(psa_aead_operation_t *operation,
				    psa_key_id_t key, psa_algorithm_t alg);

/**
 * psa_aead_set_lengths() - Declare the lengths of the message and additional
 *                          data for AEAD.
 * @operation: [in] Active AEAD operation.
 * @ad_length: [in] Size of the non-encrypted additional authenticated data in
 *                  bytes.
 * @plaintext_length: [in] Size of the plaintext to encrypt in bytes.
 *
 * .. warning::
 *     Not supported.
 *
 * The application must call this function before calling psa_aead_set_nonce()
 * or psa_aead_generate_nonce(), if the algorithm for the operation requires it.
 * If the algorithm does not require it, calling this function is optional.
 *
 *  - For PSA_ALG_CCM, calling this function is required.
 *  - For the other AEAD algorithms defined in this specification, calling this
 *    function is not required.
 *  - For vendor-defined algorithm, refer to the vendor documentation.
 *
 * If this function returns an error status, the operation enters an error state
 * and must be aborted by calling psa_aead_abort().
 *
 * Return:
 *  - PSA_SUCCESS:
 *      Success.
 *  - PSA_ERROR_INVALID_ARGUMENT:
 *      @ad_length or @plaintext_length are too large for the chosen algorithm.
 *  - PSA_ERROR_NOT_SUPPORTED:
 *      @ad_length or @plaintext_length are too large.
 *  - PSA_ERROR_INSUFFICIENT_MEMORY
 *  - PSA_ERROR_COMMUNICATION_FAILURE
 *  - PSA_ERROR_CORRUPTION_DETECTED
 *  - PSA_ERROR_BAD_STATE:
 *      - The operation state is not valid: it must be active, and
 *        psa_aead_set_nonce() and psa_aead_generate_nonce() must not have been
 *        called yet.
 *      - The library has not been previously initialized by psa_crypto_init().
 */
psa_status_t psa_aead_set_lengths(psa_aead_operation_t *operation,
				  size_t ad_length, size_t plaintext_length);

/**
 * psa_aead_generate_nonce() - Generate a random nonce for an authenticated
 *                             encryption operation.
 * @operation: [in] Active AEAD operation.
 * @nonce: [out] Buffer where the generated nonce is to be written.
 * @nonce_size: [in] Size of the @nonce buffer in bytes.
 * @nonce_length: [out] On success, the number of bytes of the generated nonce.
 *
 * .. warning::
 *     Not supported.
 *
 * This function generates a random nonce for the authenticated encryption
 * operation with an appropriate size for the chosen algorithm, key type and key
 * size.
 *
 * The @nonce_size parameter must be set appropriate for the selected algorithm
 * and key\:
 *
 *  - A sufficient output size is :c:macro:`PSA_AEAD_NONCE_LENGTH` where
 *    key_type is the type of key and alg is the algorithm that were used to
 *    set up the operation.
 *  - :c:macro:`PSA_AEAD_NONCE_MAX_SIZE` evaluates to a sufficient output size
 *    for any supported AEAD algorithm.
 *
 * The application must call psa_aead_encrypt_setup() before calling this
 * function. If applicable for the algorithm, the application must call
 * psa_aead_set_lengths() before calling this function.
 *
 * If this function returns an error status, the operation enters an error state
 * and must be aborted by calling psa_aead_abort().
 *
 * Return:
 *  - PSA_SUCCESS:
 *      Success.
 *  - PSA_ERROR_BUFFER_TOO_SMALL:
 *      The size of the @nonce buffer is too small.
 *      :c:macro:`PSA_AEAD_NONCE_LENGTH` or :c:macro:`PSA_AEAD_NONCE_MAX_SIZE`
 *      can be used to determine the required buffer size.
 *  - PSA_ERROR_INSUFFICIENT_MEMORY
 *  - PSA_ERROR_COMMUNICATION_FAILURE
 *  - PSA_ERROR_CORRUPTION_DETECTED
 *  - PSA_ERROR_STORAGE_FAILURE
 *  - PSA_ERROR_DATA_CORRUPT
 *  - PSA_ERROR_DATA_INVALID
 *  - PSA_ERROR_BAD_STATE:
 *      - The operation state is not valid: it must be an active AEAD
 *        encryption operation, with no nonce set.
 *      - The operation state is not valid: this is an algorithm which requires
 *        psa_aead_set_lengths() to be called before setting the nonce.
 *      - The library has not been previously initialized by psa_crypto_init().
 */
psa_status_t psa_aead_generate_nonce(psa_aead_operation_t *operation,
				     uint8_t *nonce, size_t nonce_size,
				     size_t *nonce_length);

/**
 * psa_aead_set_nonce() - Set the nonce for an authenticated encryption or
 *                        decryption operation.
 * @operation: [in] Active AEAD operation.
 * @nonce: [in] Buffer containing the nonce to use.
 * @nonce_length: [in] Size of the nonce in bytes. This must be a valid nonce
 *                     size for the chosen algorithm. The default nonce size is
 *                     :c:macro:`PSA_AEAD_NONCE_LENGTH` where key_type and alg
 *                     are type of key and the algorithm respectively that were
 *                     used to set up the AEAD operation.
 *
 * .. warning::
 *     Not supported.
 *
 * This function sets the nonce for the authenticated encryption or decryption
 * operation.
 *
 * The application must call psa_aead_encrypt_setup() or
 * psa_aead_decrypt_setup() before calling this function. If applicable for the
 * algorithm, the application must call psa_aead_set_lengths() before calling
 * this function.
 *
 * If this function returns an error status, the operation enters an error state
 * and must be aborted by calling psa_aead_abort().
 *
 * .. note::
 *    When encrypting, psa_aead_generate_nonce() is recommended instead of using
 *    this function, unless implementing a protocol that requires a non-random
 *    IV.
 *
 * Return:
 *  - PSA_SUCCESS:
 *      Success.
 *  - PSA_ERROR_INVALID_ARGUMENT:
 *      @nonce_length is not valid for the chosen algorithm.
 *  - PSA_ERROR_NOT_SUPPORTED:
 *      @nonce_length is not supported for use with the operation’s algorithm
 *      and key.
 *  - PSA_ERROR_INSUFFICIENT_MEMORY
 *  - PSA_ERROR_COMMUNICATION_FAILURE
 *  - PSA_ERROR_CORRUPTION_DETECTED
 *  - PSA_ERROR_STORAGE_FAILURE
 *  - PSA_ERROR_DATA_CORRUPT
 *  - PSA_ERROR_DATA_INVALID
 *  - PSA_ERROR_BAD_STATE:
 *      - The operation state is not valid: it must be active, with no nonce
 *        set.
 *      - The operation state is not valid: this is an algorithm which requires
 *        psa_aead_set_lengths() to be called before setting the nonce.
 *      - The library has not been previously initialized by psa_crypto_init().
 */
psa_status_t psa_aead_set_nonce(psa_aead_operation_t *operation,
				const uint8_t *nonce, size_t nonce_length);

/**
 * psa_aead_update_ad() - Pass additional data to an active AEAD operation.
 * @operation: [in] Active AEAD operation.
 * @input: [in] Buffer containing the fragment of additional data.
 * @input_length: [in] Size of the @input buffer in bytes.
 *
 * .. warning::
 *     Not supported.
 *
 * Additional data is authenticated, but not encrypted.
 *
 * This function can be called multiple times to pass successive fragments of
 * the additional data. This function must not be called after passing data to
 * encrypt or decrypt with psa_aead_update().
 *
 * The following must occur before calling this function\:
 *
 *  #. Call either psa_aead_encrypt_setup() or psa_aead_decrypt_setup().
 *  #. Set the nonce with psa_aead_generate_nonce() or psa_aead_set_nonce().
 *
 * If this function returns an error status, the operation enters an error state
 * and must be aborted by calling psa_aead_abort().
 *
 * Return:
 *  - PSA_SUCCESS:
 *      Success.
 *  - PSA_ERROR_INVALID_ARGUMENT:
 *      Excess additional data: the total input length to psa_aead_update_ad()
 *      is greater than the additional data length that was previously specified
 *      with psa_aead_set_lengths(), or is too large for the chosen AEAD
 *      algorithm.
 *  - PSA_ERROR_NOT_SUPPORTED:
 *      The total additional data length is too large.
 *  - PSA_ERROR_INSUFFICIENT_MEMORY
 *  - PSA_ERROR_COMMUNICATION_FAILURE
 *  - PSA_ERROR_CORRUPTION_DETECTED
 *  - PSA_ERROR_STORAGE_FAILURE
 *  - PSA_ERROR_DATA_CORRUPT
 *  - PSA_ERROR_DATA_INVALID
 *  - PSA_ERROR_BAD_STATE:
 *      - The operation state is not valid: it must be active, have a nonce set,
 *        have lengths set if required by the algorithm, and psa_aead_update()
 *        must not have been called yet.
 *      - The library has not been previously initialized by psa_crypto_init().
 */
psa_status_t psa_aead_update_ad(psa_aead_operation_t *operation,
				const uint8_t *input, size_t input_length);

/**
 * psa_aead_update() - Encrypt or decrypt a message fragment in an active AEAD
 *                     operation.
 * @operation: [in] Active AEAD operation.
 * @input: [in] Buffer containing the message fragment to encrypt or decrypt.
 * @input_length: [in] Size of the @input buffer in bytes.
 * @output: [out] Buffer where the output is to be written.
 * @output_size: [in] Size of the @output buffer in bytes.
 * @output_length: [out] On success, the number of bytes that make up the
 *                       returned output.
 *
 * .. warning::
 *     Not supported.
 *
 * The @output_size parameter must be appropriate for the selected algorithm and
 * key\:
 *
 *  - A sufficient output size is :c:macro:`PSA_AEAD_UPDATE_OUTPUT_SIZE` where
 *    key_type is the type of @key and alg is the algorithm that were used to
 *    set up the operation.
 *  - :c:macro:`PSA_AEAD_UPDATE_OUTPUT_MAX_SIZE` evaluates to the maximum output
 *    size of any supported AEAD algorithm.
 *
 * The following must occur before calling this function\:
 *
 *  #. Call either psa_aead_encrypt_setup() or psa_aead_decrypt_setup(). The
 *     choice of setup function determines whether this function encrypts or
 *     decrypts its input.
 *  #. Set the nonce with psa_aead_generate_nonce() or psa_aead_set_nonce().
 *  #. Call psa_aead_update_ad() to pass all the additional data.
 *
 * If this function returns an error status, the operation enters an error state
 * and must be aborted by calling psa_aead_abort().
 *
 * .. note::
 *    This function does not require the input to be aligned to any particular
 *    block boundary. If the implementation can only process a whole block at a
 *    time, it must consume all the input provided, but it might delay the end
 *    of the corresponding output until a subsequent call to psa_aead_update(),
 *    psa_aead_finish() or psa_aead_verify() provides sufficient input. The
 *    amount of data that can be delayed in this way is bounded by
 *    :c:macro:`PSA_AEAD_UPDATE_OUTPUT_SIZE`,
 *    :c:macro:`PSA_AEAD_FINISH_OUTPUT_SIZE`, or
 *    :c:macro:`PSA_AEAD_VERIFY_OUTPUT_SIZE`.
 *
 * Return:
 *  - PSA_SUCCESS:
 *      Success.
 *  - PSA_ERROR_BUFFER_TOO_SMALL:
 *      - The size of the @output buffer is too small.
 *        :c:macro:`PSA_AEAD_UPDATE_OUTPUT_SIZE` or
 *        :c:macro:`PSA_AEAD_UPDATE_OUTPUT_MAX_SIZE` can be used to determine
 *        the required buffer size.
 *  - PSA_ERROR_INVALID_ARGUMENT:
 *      - Incomplete additional data: the total length of input to
 *        psa_aead_update_ad() is less than the additional data length that was
 *        previously specified with psa_aead_set_lengths().
 *      - Excess input data: the total length of input to psa_aead_update() is
 *        greater than the plaintext length that was previously specified with
 *        psa_aead_set_lengths(), or is too large for the specific AEAD
 *        algorithm.
 *  - PSA_ERROR_NOT_SUPPORTED:
 *      The total input length is too large.
 *  - PSA_ERROR_INSUFFICIENT_MEMORY
 *  - PSA_ERROR_COMMUNICATION_FAILURE
 *  - PSA_ERROR_HARDWARE_FAILURE
 *  - PSA_ERROR_CORRUPTION_DETECTED
 *  - PSA_ERROR_STORAGE_FAILURE
 *  - PSA_ERROR_DATA_CORRUPT
 *  - PSA_ERROR_DATA_INVALID
 *  - PSA_ERROR_BAD_STATE:
 *      - The operation state is not valid: it must be active, have a nonce set,
 *        and have lengths set if required by the algorithm.
 *      - The library has not been previously initialized by psa_crypto_init().
 */
psa_status_t psa_aead_update(psa_aead_operation_t *operation,
			     const uint8_t *input, size_t input_length,
			     uint8_t *output, size_t output_size,
			     size_t *output_length);

/**
 * psa_aead_finish() - Finish encrypting a message in an AEAD operation.
 * @operation: [in] Active AEAD operation.
 * @ciphertext: [out] Buffer where the last part of the ciphertext is to be
 *                    written.
 * @ciphertext_size: [in] Size of the @ciphertext buffer in bytes.
 * @ciphertext_length: [out] On success, the number of bytes of returned
 *                           ciphertext.
 * @tag: [out] Buffer where the authentication tag is to be written.
 * @tag_size: [in] Size of the @tag buffer in bytes.
 * @tag_length: [out] On success, the number of bytes that make up the returned
 *                    tag.
 *
 * .. warning::
 *    Not supported.
 *
 * The operation must have been set up with psa_aead_encrypt_setup().
 *
 * This function finishes the authentication of the additional data formed by
 * concatenating the inputs passed to preceding calls to psa_aead_update_ad()
 * with the plaintext formed by concatenating the inputs passed to preceding
 * calls to psa_aead_update().
 *
 * This function has two output buffers\:
 *
 *  - @ciphertext contains trailing ciphertext that was buffered from preceding
 *    calls to psa_aead_update().
 *  - @tag contains the authentication tag.
 *
 * The @ciphertext_size parameter must be appropriate for the selected algorithm
 * and key\:
 *
 *  - A sufficient output size is :c:macro:`PSA_AEAD_FINISH_OUTPUT_SIZE` where
 *    key_type is the type of key and alg is the algorithm that were used to set
 *    up the operation.
 *  - :c:macro:`PSA_AEAD_FINISH_OUTPUT_MAX_SIZE` evaluates to the maximum output
 *    size of any supported AEAD algorithm.
 *
 * The @tag_size parameter must be appropriate for the selected algorithm and
 * key\:
 *
 *  - The exact tag size is :c:macro:`PSA_AEAD_TAG_LENGTH` where key_type and
 *    key_bits are the type and bit-size of the key, and alg is the algorithm
 *    that were used in the call to psa_aead_encrypt_setup().
 *  - :c:macro:`PSA_AEAD_TAG_MAX_SIZE` evaluates to the maximum tag size of any
 *    supported AEAD algorithm.
 *
 * When this function returns successfully, the operation becomes inactive. If
 * this function returns an error status, the operation enters an error state
 * and must be aborted by calling psa_aead_abort().
 *
 * Return:
 *  - PSA_SUCCESS:
 *      Success.
 *  - PSA_ERROR_BUFFER_TOO_SMALL:
 *      The size of the @ciphertext or @tag buffer is too small.
 *      :c:macro:`PSA_AEAD_FINISH_OUTPUT_SIZE` or
 *      :c:macro:`PSA_AEAD_FINISH_OUTPUT_MAX_SIZE` can be used to determine the
 *      required ciphertext buffer size. :c:macro:`PSA_AEAD_TAG_LENGTH` or
 *      :c:macro:`PSA_AEAD_TAG_MAX_SIZE` can be used to determine the required
 *      @tag buffer size.
 *  - PSA_ERROR_INVALID_ARGUMENT:
 *      - Incomplete additional data: the total length of input to
 *        psa_aead_update_ad() is less than the additional data length that was
 *        previously specified with psa_aead_set_lengths().
 *      - Incomplete plaintext: the total length of input to psa_aead_update()
 *        is less than the plaintext length that was previously specified with
 *        psa_aead_set_lengths().
 *  - PSA_ERROR_INSUFFICIENT_MEMORY
 *  - PSA_ERROR_COMMUNICATION_FAILURE
 *  - PSA_ERROR_HARDWARE_FAILURE
 *  - PSA_ERROR_CORRUPTION_DETECTED
 *  - PSA_ERROR_STORAGE_FAILURE
 *  - PSA_ERROR_DATA_CORRUPT
 *  - PSA_ERROR_DATA_INVALID
 *  - PSA_ERROR_BAD_STATE:
 *      - The operation state is not valid: it must be an active encryption
 *        operation with a nonce set.
 *      - The library has not been previously initialized by psa_crypto_init().
 */
psa_status_t psa_aead_finish(psa_aead_operation_t *operation,
			     uint8_t *ciphertext, size_t ciphertext_size,
			     size_t *ciphertext_length, uint8_t *tag,
			     size_t tag_size, size_t *tag_length);

/**
 * psa_aead_verify() - Finish authenticating and decrypting a message in an
 *                     AEAD operation.
 * @operation: [in] Active AEAD operation.
 * @plaintext: [out] Buffer where the last part of the plaintext is to be
 *                   written. This is the remaining data from previous calls to
 *                   psa_aead_update() that could not be processed until the
 *                   end of the input.
 * @plaintext_size: [in] Size of the @plaintext buffer in bytes.
 * @plaintext_length: [out] On success, the number of bytes of returned plaintext.
 * @tag: [in] Buffer containing the authentication tag.
 * @tag_length: [in] Size of the @tag buffer in bytes.
 *
 * .. warning::
 *     Not supported.
 *
 * The operation must have been set up with psa_aead_decrypt_setup().
 *
 * This function finishes the authenticated decryption of the message
 * components\:
 *
 *  - The additional data consisting of the concatenation of the inputs passed
 *    to preceding calls to psa_aead_update_ad().
 *  - The ciphertext consisting of the concatenation of the inputs passed to
 *    preceding calls to psa_aead_update().
 *  - The tag passed to this function call.
 *
 * The @plaintext_size parameter must be appropriate for the selected algorithm
 * and key\:
 *
 *  - A sufficient output size is :c:macro:`PSA_AEAD_VERIFY_OUTPUT_SIZE` where
 *    key_type is the type of key and alg is the algorithm that were used to set
 *    up the operation.
 *  - :c:macro:`PSA_AEAD_VERIFY_OUTPUT_MAX_SIZE` evaluates to the maximum output
 *    size of any supported AEAD algorithm.
 *
 * If the authentication tag is correct, this function outputs any remaining
 * plaintext and reports success. If the authentication tag is not correct, this
 * function returns PSA_ERROR_INVALID_SIGNATURE.
 *
 * When this function returns successfully, the operation becomes inactive.
 * If this function returns an error status, the operation enters an error state
 * and must be aborted by calling psa_aead_abort().
 *
 * Return:
 *  - PSA_SUCCESS:
 *      Success.
 *  - PSA_ERROR_INVALID_SIGNATURE:
 *      The calculated authentication tag does not match the value in @tag.
 *  - PSA_ERROR_BUFFER_TOO_SMALL:
 *      The size of the @plaintext buffer is too small.
 *      :c:macro:`PSA_AEAD_VERIFY_OUTPUT_SIZE` or
 *      :c:macro:`PSA_AEAD_VERIFY_OUTPUT_MAX_SIZE` can be used to determine the
 *      required buffer size.
 *  - PSA_ERROR_INVALID_ARGUMENT:
 *      - Incomplete additional data: the total length of input to
 *        psa_aead_update_ad() is less than the additional data length that was
 *        previously specified with psa_aead_set_lengths().
 *      - Incomplete ciphertext: the total length of input to psa_aead_update()
 *        is less than the plaintext length that was previously specified with
 *        psa_aead_set_lengths().
 *  - PSA_ERROR_INSUFFICIENT_MEMORY
 *  - PSA_ERROR_COMMUNICATION_FAILURE
 *  - PSA_ERROR_CORRUPTION_DETECTED
 *  - PSA_ERROR_STORAGE_FAILURE
 *  - PSA_ERROR_DATA_CORRUPT
 *  - PSA_ERROR_DATA_INVALID
 *  - PSA_ERROR_BAD_STATE:
 *      - The operation state is not valid: it must be an active decryption
 *        operation with a nonce set.
 *      - The library has not been previously initialized by psa_crypto_init().
 */
psa_status_t psa_aead_verify(psa_aead_operation_t *operation,
			     uint8_t *plaintext, size_t plaintext_size,
			     size_t *plaintext_length, const uint8_t *tag,
			     size_t tag_length);

/**
 * psa_aead_abort() - Abort an AEAD operation.
 * @operation: Initialized AEAD operation.
 *
 * .. warning::
 *    Not supported.
 *
 * Aborting an operation frees all associated resources except for the operation
 * object itself. Once aborted, the operation object can be reused for another
 * operation by calling psa_aead_encrypt_setup() or psa_aead_decrypt_setup()
 * again.
 *
 * This function can be called any time after the operation object has been
 * initialized as described in &typedef psa_aead_operation_t.
 *
 * In particular, calling psa_aead_abort() after the operation has been
 * terminated by a call to psa_aead_abort(), psa_aead_finish() or
 * psa_aead_verify() is safe and has no effect.
 *
 * Return:
 *  - PSA_SUCCESS
 *      Success. The operation object can now be discarded or reused.
 *  - PSA_ERROR_COMMUNICATION_FAILURE
 *  - PSA_ERROR_HARDWARE_FAILURE
 *  - PSA_ERROR_CORRUPTION_DETECTED
 *  - PSA_ERROR_BAD_STATE:
 *	- The library has not been previously initialized by psa_crypto_init().
 */
psa_status_t psa_aead_abort(psa_aead_operation_t *operation);

#endif /* __PSA_CRYPTO_AEAD_H__ */
