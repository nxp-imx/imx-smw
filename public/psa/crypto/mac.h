/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2022-2026 NXP
 */

#ifndef __PSA_CRYPTO_MAC_H__
#define __PSA_CRYPTO_MAC_H__

/**
 * typedef psa_mac_operation_t - The type of the state object for multi-part
 *                               MAC operations.
 *
 * Before calling any function on a MAC operation object, the application must
 * initialize it by any of the following means\:
 *
 *  - Set the object to all-bits-zero, for example\:
 *
 *    .. code-block:: c
 *
 *       psa_mac_operation_t operation;
 *       memset(&operation, 0, sizeof(operation));
 *
 *  - Initialize the object to logical zero values by declaring the object as
 *    static or global without an explicit initializer, for example\:
 *
 *    .. code-block:: c
 *
 *       static psa_mac_operation_t operation;
 *
 *  - Initialize the object to the initializer
 *    :c:macro:`PSA_MAC_OPERATION_INIT`, for example\:
 *
 *    .. code-block:: c
 *
 *       psa_mac_operation_t operation = PSA_MAC_OPERATION_INIT;
 *
 *  - Assign the result of the function :c:func:`psa_mac_operation_init` to the
 *    object, for example\:
 *
 *    .. code-block:: c
 *
 *       psa_mac_operation_t operation;
 *       operation = psa_mac_operation_init();
 */
typedef struct psa_mac_operation_s psa_mac_operation_t;

/**
 * psa_mac_operation_init() - Return an initial value for a MAC operation
 *                            object.
 *
 * Return:
 * Initialized value of mac operation object.
 */
static psa_mac_operation_t psa_mac_operation_init(void);

/**
 * psa_mac_compute() - Calculate the message authentication code (MAC) of a
 *                     message.
 * @key: [in] Identifier of the key to use for the operation. It must allow the
 *            usage PSA_KEY_USAGE_SIGN_MESSAGE.
 * @alg: [in] The MAC algorithm to compute such that :c:macro:`PSA_ALG_IS_MAC`
 *            is true.
 * @input: [in] Buffer containing the input message.
 * @input_length: [in] Size of the @input buffer in bytes.
 * @mac: [out] Buffer where the MAC value is to be written.
 * @mac_size: [in] Size of the @mac buffer in bytes.
 * @mac_length: [out] On success, the number of bytes that make up the MAC
 *                    value.
 *
 * .. note::
 *    To verify the MAC of a message against an expected value, use
 *    psa_mac_verify() instead.
 *
 * The @mac_size parameter must be appropriate for the selected algorithm and
 * key\:
 *
 *  - The exact MAC size is :c:macro:`PSA_MAC_LENGTH` where `key_type` and
 *    `key_bits are` attributes of the key used to compute the MAC.
 *  - :c:macro:`PSA_MAC_MAX_SIZE` evaluates to the maximum MAC size of any
 *    supported MAC algorithm.
 *
 * Return:
 *  - PSA_SUCCESS:
 *      Success.
 *  - PSA_ERROR_INVALID_HANDLE:
 *      @key is not a valid key identifier.
 *  - PSA_ERROR_NOT_PERMITTED:
 *      The @key does not have the PSA_KEY_USAGE_SIGN_MESSAGE flag, or it does
 *      not permit the requested algorithm.
 *  - PSA_ERROR_INVALID_ARGUMENT:
 *      - @alg is not a MAC algorithm.
 *      - @key is not compatible with @alg.
 *      - @input_length is too large for @alg.
 *  - PSA_ERROR_NOT_SUPPORTED:
 *      - @alg is not supported.
 *      - @key is not supported for use with @alg.
 *      - @input_length is too large.
 *  - PSA_ERROR_BUFFER_TOO_SMALL:
 *      The size of the @mac buffer is too small. :c:macro:`PSA_MAC_LENGTH` or
 *      :c:macro:`PSA_MAC_MAX_SIZE` can be used to determine the required buffer
 *      size.
 *  - PSA_ERROR_INSUFFICIENT_MEMORY
 *  - PSA_ERROR_COMMUNICATION_FAILURE
 *  - PSA_ERROR_CORRUPTION_DETECTED
 *  - PSA_ERROR_STORAGE_FAILURE:
 *  - PSA_ERROR_DATA_CORRUPT:
 *  - PSA_ERROR_DATA_INVALID:
 *  - PSA_ERROR_BAD_STATE:
 *      The library has not been previously initialized by psa_crypto_init().
 */
psa_status_t psa_mac_compute(psa_key_id_t key, psa_algorithm_t alg,
			     const uint8_t *input, size_t input_length,
			     uint8_t *mac, size_t mac_size, size_t *mac_length);

/**
 * psa_mac_verify() - Calculate the MAC of a message and compare it with a
 *                    reference value.
 * @key: [in] Identifier of the key to use for the operation. It must allow the
 *            usage PSA_KEY_USAGE_VERIFY_MESSAGE.
 * @alg: [in] The MAC algorithm to compute such that :c:macro:`PSA_ALG_IS_MAC`
 *            is true.
 * @input: [in] Buffer containing the input message.
 * @input_length: [in] Size of the @input buffer in bytes.
 * @mac: [in] Buffer containing the expected MAC value.
 * @mac_length: [in] Size of the @mac buffer in bytes.
 *
 * Return:
 *  - PSA_SUCCESS:
 *      Success. The expected MAC is identical to the actual MAC of the input.
 *  - PSA_ERROR_INVALID_SIGNATURE:
 *      The calculated MAC of the message does not match the expected value.
 *  - PSA_ERROR_INVALID_HANDLE:
 *      @key is not a valid key identifier.
 *  - PSA_ERROR_NOT_PERMITTED:
 *      The @key does not have the PSA_KEY_USAGE_VERIFY_MESSAGE flag, or it
 *      does not permit the requested algorithm.
 *  - PSA_ERROR_INVALID_ARGUMENT:
 *      - @alg is not a MAC algorithm.
 *      - @key is not compatible with @alg.
 *      - @input_length is too large for @alg.
 *  - PSA_ERROR_NOT_SUPPORTED:
 *      - @alg is not supported.
 *      - @key is not supported for use with @alg.
 *      - @input_length is too large.
 *  - PSA_ERROR_INSUFFICIENT_MEMORY
 *  - PSA_ERROR_COMMUNICATION_FAILURE
 *  - PSA_ERROR_CORRUPTION_DETECTED
 *  - PSA_ERROR_STORAGE_FAILURE:
 *  - PSA_ERROR_DATA_CORRUPT:
 *  - PSA_ERROR_DATA_INVALID:
 *  - PSA_ERROR_BAD_STATE:
 *      The library has not been previously initialized by psa_crypto_init().
 */
psa_status_t psa_mac_verify(psa_key_id_t key, psa_algorithm_t alg,
			    const uint8_t *input, size_t input_length,
			    const uint8_t *mac, size_t mac_length);

/**
 * psa_mac_sign_setup() - Set up a multi-part MAC calculation operation.
 * @operation: [in] The operation object to set up. It must have been
 *                  initialized as per the documentation for
 *                  &typedef psa_mac_operation_t and not yet in use.
 * @key: [in] Identifier of the key to use for the operation. It must remain
 *            valid until the operation terminates. It must allow the usage
 *            PSA_KEY_USAGE_SIGN_MESSAGE.
 * @alg: [in] The MAC algorithm to compute such that :c:macro:`PSA_ALG_IS_MAC`
 *            is true.
 *
 * .. warning::
 *     Not supported.
 *
 * This function sets up the calculation of the message authentication code
 * (MAC) of a byte string. To verify the MAC of a message against an expected
 * value, use psa_mac_verify_setup() instead.
 *
 * After a successful call to psa_mac_sign_setup(), the operation is active,
 * and the application must eventually terminate the operation through one of
 * the following methods\:
 *
 *  - A successful call to psa_mac_sign_finish().
 *  - A call to psa_mac_abort().
 *
 * If psa_mac_sign_setup() returns an error, the operation object is unchanged.
 * If a subsequent function call with an active operation returns an error, the
 * operation enters an error state.
 *
 * To abandon an active operation, or reset an operation in error state, call
 * psa_mac_abort().
 *
 * Return:
 *  - PSA_SUCCESS:
 *      Success. The operation is now active.
 *  - PSA_ERROR_INVALID_HANDLE
 *      @key is not a valid key identifier.
 *  - PSA_ERROR_NOT_PERMITTED:
 *      The key does not have the PSA_KEY_USAGE_SIGN_MESSAGE flag, or it does
 *      not permit the requested algorithm.
 *  - PSA_ERROR_INVALID_ARGUMENT:
 *      - @alg is not a MAC algorithm.
 *      - @key is not compatible with @alg.
 *  - PSA_ERROR_NOT_SUPPORTED:
 *      - @alg is not supported.
 *      - @key is not supported for use with @alg.
 *  - PSA_ERROR_INSUFFICIENT_MEMORY
 *  - PSA_ERROR_COMMUNICATION_FAILURE
 *  - PSA_ERROR_CORRUPTION_DETECTED
 *  - PSA_ERROR_STORAGE_FAILURE:
 *  - PSA_ERROR_DATA_CORRUPT:
 *  - PSA_ERROR_DATA_INVALID:
 *  - PSA_ERROR_BAD_STATE:
 *      - The operation state is not valid: it must be inactive.
 *      - The library has not been previously initialized by psa_crypto_init().
 */
psa_status_t psa_mac_sign_setup(psa_mac_operation_t *operation,
				psa_key_id_t key, psa_algorithm_t alg);

/**
 * psa_mac_verify_setup() - Set up a multi-part MAC verification operation.
 * @operation: [in] The operation object to set up. It must have been
 *                  initialized as per the documentation for
 *                  &typedef psa_mac_operation_t and not yet in use.
 * @key: [in] Identifier of the key to use for the operation. It must remain
 *            valid until the operation terminates. It must allow the usage
 *            PSA_KEY_USAGE_VERIFY_MESSAGE.
 * @alg: [in] The MAC algorithm to compute such that :c:macro:`PSA_ALG_IS_MAC`
 *            is true.
 *
 * .. warning::
 *     Not supported.
 *
 * This function sets up the verification of the message authentication code
 * (MAC) of a byte string against an expected value.
 *
 * After a successful call to psa_mac_verify_setup(), the application must
 * eventually terminate the operation through one of the following methods\:
 *
 *  - A successful call to psa_mac_verify_finish().
 *  - A call to psa_mac_abort().
 *
 * If psa_mac_verify_setup() returns an error, the operation object is
 * unchanged. If a subsequent function call with an active operation returns
 * an error, the operation enters an error state.
 *
 * To abandon an active operation, or reset an operation in an error state,
 * call psa_mac_abort().
 *
 * Return:
 *  - PSA_SUCCESS:
 *      Success. The operation is now active.
 *  - PSA_ERROR_INVALID_HANDLE:
 *      @key is not a valid key identifier.
 *  - PSA_ERROR_NOT_PERMITTED:
 *      The key does not have the PSA_KEY_USAGE_VERIFY_MESSAGE flag, or it does
 *      not permit the requested algorithm.
 *  - PSA_ERROR_INVALID_ARGUMENT:
 *      - @alg is not a MAC algorithm.
 *      - @key is not compatible with @alg.
 *  - PSA_ERROR_NOT_SUPPORTED:
 *      - @alg is not supported.
 *      - @key is not supported for use with @alg.
 *  - PSA_ERROR_INSUFFICIENT_MEMORY
 *  - PSA_ERROR_COMMUNICATION_FAILURE
 *  - PSA_ERROR_CORRUPTION_DETECTED
 *  - PSA_ERROR_STORAGE_FAILURE:
 *  - PSA_ERROR_DATA_CORRUPT:
 *  - PSA_ERROR_DATA_INVALID:
 *  - PSA_ERROR_BAD_STATE:
 *      - The operation state is not valid: it must be inactive.
 *      - The library has not been previously initialized by psa_crypto_init().
 */
psa_status_t psa_mac_verify_setup(psa_mac_operation_t *operation,
				  psa_key_id_t key, psa_algorithm_t alg);

/**
 * psa_mac_update() - Add a message fragment to a multi-part MAC operation.
 * @operation: [in] Active MAC operation.
 * @input: [in] Buffer containing the message fragment to add to the MAC
 *              calculation.
 * @input_length: [in] Size of the @input buffer in bytes.
 *
 * .. warning::
 *     Not supported.
 *
 * The application must call psa_mac_sign_setup() or psa_mac_verify_setup()
 * before calling this function.
 *
 * If this function returns an error status, the operation enters an error state
 * and must be aborted by calling psa_mac_abort().
 *
 * Return:
 *  - PSA_SUCCESS:
 *      Success.
 *  - PSA_ERROR_INVALID_ARGUMENT:
 *      The total input for the operation is too large for the MAC algorithm.
 *  - PSA_ERROR_NOT_SUPPORTED:
 *      The total input for the operation is not supported.
 *  - PSA_ERROR_INSUFFICIENT_MEMORY
 *  - PSA_ERROR_COMMUNICATION_FAILURE
 *  - PSA_ERROR_HARDWARE_FAILURE
 *  - PSA_ERROR_CORRUPTION_DETECTED
 *  - PSA_ERROR_STORAGE_FAILURE
 *  - PSA_ERROR_DATA_CORRUPT
 *  - PSA_ERROR_DATA_INVALID
 *  - PSA_ERROR_BAD_STATE:
 *      - The operation state is not valid: it must be active.
 *      - The library has not been previously initialized by psa_crypto_init().
 */
psa_status_t psa_mac_update(psa_mac_operation_t *operation,
			    const uint8_t *input, size_t input_length);

/**
 * psa_mac_sign_finish() - Finish the calculation of the MAC of a message.
 * @operation: [in] Active MAC operation.
 * @mac: [in] Buffer where the MAC value is to be written.
 * @mac_size: [in] Size of the @mac buffer in bytes.
 * @mac_length: [out] On success, the number of bytes that make up the MAC
 *                    value.
 *
 * .. warning::
 *     Not supported.
 *
 * The application must call psa_mac_sign_setup() before calling this function.
 * This function calculates the MAC of the message formed by concatenating the
 * inputs passed to preceding calls to psa_mac_update().
 *
 * When this function returns successfully, the operation becomes inactive. If
 * this function returns an error status, the operation enters an error state
 * and must be aborted by calling psa_mac_abort().
 *
 * .. warning:::
 *    It is not recommended to use this function when a specific value is
 *    expected for the MAC. Call psa_mac_verify_finish() instead with the
 *    expected MAC value.
 *
 * The @mac_size parameter must be appropriate for the selected algorithm and
 * key\:
 *
 *  - The exact MAC size is :c:macro:`PSA_MAC_LENGTH` where key_type and
 *    key_bits are attributes of the key, and alg is the algorithm used to
 *    compute the MAC.
 *  - :c:macro:`PSA_MAC_MAX_SIZE` evaluates to the maximum MAC size of any
 *    supported MAC algorithm.
 *
 * Return:
 *  - PSA_SUCCESS:
 *      Success.
 *  - PSA_ERROR_BUFFER_TOO_SMALL:
 *      The size of the @mac buffer is too small. :c:macro:`PSA_MAC_LENGTH` or
 *      :c:macro:`PSA_MAC_MAX_SIZE` can be used to determine the required
 *      buffer size.
 *  - PSA_ERROR_INSUFFICIENT_MEMORY
 *  - PSA_ERROR_COMMUNICATION_FAILURE
 *  - PSA_ERROR_CORRUPTION_DETECTED
 *  - PSA_ERROR_STORAGE_FAILURE
 *  - PSA_ERROR_DATA_CORRUPT
 *  - PSA_ERROR_DATA_INVALID
 *  - PSA_ERROR_BAD_STATE:
 *      - The operation state is not valid: it must be an active mac sign
 *        operation.
 *      - The library has not been previously initialized by psa_crypto_init().
 */
psa_status_t psa_mac_sign_finish(psa_mac_operation_t *operation, uint8_t *mac,
				 size_t mac_size, size_t *mac_length);

/**
 * psa_mac_verify_finish() - Finish the calculation of the MAC of a message and
 *                           compare it with an expected value.
 * @operation: [in] Active MAC operation.
 * @mac: [in] Buffer containing the expected MAC value.
 * @mac_length: [in] Size of the @mac buffer in bytes.
 *
 * .. warning::
 *     Not supported.
 *
 * The application must call psa_mac_verify_setup() before calling this
 * function. This function calculates the MAC of the message formed by
 * concatenating the inputs passed to preceding calls to psa_mac_update(). It
 * then compares the calculated MAC with the expected MAC passed as a parameter
 * to this function.
 *
 * When this function returns successfully, the operation becomes inactive. If
 * this function returns an error status, the operation enters an error state
 * and must be aborted by calling psa_mac_abort().
 *
 * Return:
 *  - PSA_SUCCESS:
 *      Success. The expected MAC is identical to the actual MAC of the message.
 *  - PSA_ERROR_INVALID_SIGNATURE:
 *      The calculated MAC of the message does not match the value in @mac.
 *  - PSA_ERROR_INSUFFICIENT_MEMORY
 *  - PSA_ERROR_COMMUNICATION_FAILURE
 *  - PSA_ERROR_CORRUPTION_DETECTED
 *  - PSA_ERROR_STORAGE_FAILURE
 *  - PSA_ERROR_DATA_CORRUPT
 *  - PSA_ERROR_DATA_INVALID
 *  - PSA_ERROR_BAD_STATE:
 *      - The operation state is not valid: it must be an active mac verify
 *        operation.
 *      - The library has not been previously initialized by psa_crypto_init().
 */
psa_status_t psa_mac_verify_finish(psa_mac_operation_t *operation,
				   const uint8_t *mac, size_t mac_length);

/**
 * psa_mac_abort() - Abort a MAC operation.
 * @operation: [in] Initialized MAC operation.
 *
 * .. warning::
 *     Not supported.
 *
 * Aborting an operation frees all associated resources except for the operation
 * object itself. Once aborted, the operation object can be reused for another
 * operation by calling psa_mac_sign_setup() or psa_mac_verify_setup() again.
 *
 * This function can be called any time after the operation object has been
 * initialized by one of the methods described in &typedef psa_mac_operation_t.
 *
 * In particular, calling psa_mac_abort() after the operation has been
 * terminated by a call to psa_mac_abort(), psa_mac_sign_finish() or
 * psa_mac_verify_finish() is safe and has no effect.
 *
 * Return:
 *  - PSA_SUCCESS
 *    Success. The operation object can now be discarded or reused.
 *  - PSA_ERROR_COMMUNICATION_FAILURE
 *  - PSA_ERROR_CORRUPTION_DETECTED
 *  - PSA_ERROR_BAD_STATE:
 *      The library has not been previously initialized by psa_crypto_init().
 */
psa_status_t psa_mac_abort(psa_mac_operation_t *operation);

#endif /* __PSA_CRYPTO_MAC_H__ */
