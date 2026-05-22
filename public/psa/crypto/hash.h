/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2022-2026 NXP
 */

#ifndef __PSA_CRYPTO_HASH_H__
#define __PSA_CRYPTO_HASH_H__

/**
 * typedef psa_hash_operation_t - The type of the state object for multi-part
 *                                hash operations.
 *
 * Before calling any function on a hash operation object, the application must
 * initialize it by any of the following means\:
 *
 *  - Set the object to all-bits-zero, for example\:
 *
 *    .. code-block:: c
 *
 *       psa_hash_operation_t operation;
 *       memset(&operation, 0, sizeof(operation));
 *
 *  - Initialize the object to logical zero values by declaring the object as
 *    static or global without an explicit initializer, for example\:
 *
 *    .. code-block:: c
 *
 *       static psa_hash_operation_t operation;
 *
 *  - Initialize the object to the initializer
 *    :c:macro:`PSA_HASH_OPERATION_INIT`, for example\:
 *
 *    .. code-block:: c
 *
 *       psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;
 *
 *  - Assign the result of the function psa_hash_operation_init() to the object,
 *    for example\:
 *
 *    .. code-block:: c
 *
 *       psa_hash_operation_t operation;
 *       operation = psa_hash_operation_init();
 */
typedef struct psa_hash_operation_s psa_hash_operation_t;

/**
 * psa_hash_operation_init() - Return an initial value for a hash operation
 *                             object.
 *
 * Return:
 * Initialized value of hash operation object.
 */
static psa_hash_operation_t psa_hash_operation_init(void);

/**
 * psa_hash_compute() - Calculate the hash (digest) of a message.
 * @alg: [in] The hash algorithm to compute such that :c:macro:`PSA_ALG_IS_HASH`
 *            is true.
 * @input: [in] Buffer containing the message to hash.
 * @input_length: [in] Size of the @input buffer in bytes.
 * @hash: [out] Buffer where the hash is to be written.
 * @hash_size: [in] Size of the @hash buffer in bytes. This must be at least
 *                  :c:macro:`PSA_HASH_LENGTH`.
 * @hash_length: [out] On success, the number of bytes that make up the hash
 *                     value.
 *
 * .. note::
 *    To verify the hash of a message against an expected value, use
 *    psa_hash_compare() instead.
 *
 * Return:
 *  - PSA_SUCCESS:
 *      Success.
 *  - PSA_ERROR_NOT_SUPPORTED:
 *      - @alg is not supported.
 *      - @input_length is too large.
 *  - PSA_ERROR_INVALID_ARGUMENT:
 *      - @alg is not a hash algorithm.
 *      - @input_length is too large for @alg.
 *  - PSA_ERROR_BUFFER_TOO_SMALL:
 *      The @hash_size is too small. :c:macro:`PSA_HASH_LENGTH` can be used to
 *      determine the required buffer size.
 *  - PSA_ERROR_INSUFFICIENT_MEMORY
 *  - PSA_ERROR_COMMUNICATION_FAILURE
 *  - PSA_ERROR_CORRUPTION_DETECTED
 *  - PSA_ERROR_BAD_STATE:
 *      The library has not been previously initialized by psa_crypto_init().
 */
psa_status_t psa_hash_compute(psa_algorithm_t alg, const uint8_t *input,
			      size_t input_length, uint8_t *hash,
			      size_t hash_size, size_t *hash_length);

/**
 * psa_hash_compare() - Calculate the hash (digest) of a message and compare it
 *                      with a reference value.
 * @alg: [in] The hash algorithm to compute such that :c:macro:`PSA_ALG_IS_HASH`
 *            is true.
 * @input: [in] Buffer containing the message to hash.
 * @input_length: [in] Size of the @input buffer in bytes.
 * @hash: [in] Buffer containing the expected hash value.
 * @hash_length: [in] Size of the @hash buffer in bytes.
 *
 * Return:
 *  - PSA_SUCCESS:
 *      The expected hash is identical to the actual hash of the input.
 *  - PSA_ERROR_INVALID_SIGNATURE:
 *      The calculated hash of the message does not match the value in @hash.
 *  - PSA_ERROR_NOT_SUPPORTED:
 *      - @alg is not supported.
 *      - @input_length is too large.
 *  - PSA_ERROR_INVALID_ARGUMENT:
 *      - @alg is not a hash algorithm.
 *      - @input_length is too large for @alg.
 *  - PSA_ERROR_INSUFFICIENT_MEMORY
 *  - PSA_ERROR_COMMUNICATION_FAILURE
 *  - PSA_ERROR_HARDWARE_FAILURE
 *  - PSA_ERROR_CORRUPTION_DETECTED
 *  - PSA_ERROR_BAD_STATE:
 *      The library has not been previously initialized by psa_crypto_init().
 */
psa_status_t psa_hash_compare(psa_algorithm_t alg, const uint8_t *input,
			      size_t input_length, const uint8_t *hash,
			      size_t hash_length);

/**
 * psa_hash_setup() - Set up a multi-part hash operation.
 * @operation: [in] The operation object to set up. It must have been
 *                  initialized as per the documentation for
 *                  &typedef psa_hash_operation_t and not yet in use.
 * @alg: [in] The hash algorithm to compute such that :c:macro:`PSA_ALG_IS_HASH`
 *            is true.
 *
 * After a successful call to psa_hash_setup(), the application must eventually
 * terminate the operation. The following events terminate an operation\:
 *
 *  - A successful call to psa_hash_finish() or psa_hash_verify() or
 *    psa_hash_suspend().
 *  - A call to psa_hash_abort().
 *
 * If psa_hash_setup() returns an error, the operation object is unchanged. If
 * a subsequent function call with an active operation returns an error, the
 * operation enters an error state.
 *
 * To abandon an active operation, or reset an operation in an error state,
 * call psa_hash_abort().
 *
 * Return:
 *  - PSA_SUCCESS:
 *      Success.
 *  - PSA_ERROR_NOT_SUPPORTED:
 *      @alg is not a supported hash algorithm.
 *  - PSA_ERROR_INVALID_ARGUMENT:
 *      @alg is not a hash algorithm.
 *  - PSA_ERROR_INSUFFICIENT_MEMORY
 *  - PSA_ERROR_COMMUNICATION_FAILURE
 *  - PSA_ERROR_CORRUPTION_DETECTED
 *  - PSA_ERROR_BAD_STATE:
 *      - The operation state is not valid: it must be inactive.
 *      - The library has not been previously initialized by psa_crypto_init().
 */
psa_status_t psa_hash_setup(psa_hash_operation_t *operation,
			    psa_algorithm_t alg);

/**
 * psa_hash_update() - Add a message fragment to a multi-part hash operation.
 * @operation: [in] Active hash operation.
 * @input: [in] Buffer containing the message fragment to hash.
 * @input_length: [in] Size of the @input buffer in bytes.
 *
 * The application must call psa_hash_setup() or psa_hash_resume() before
 * calling this function.
 *
 * If this function returns an error status, the operation enters an error
 * state and must be aborted by calling psa_hash_abort().
 *
 * Return:
 *  - PSA_SUCCESS:
 *      Success.
 *  - PSA_ERROR_INSUFFICIENT_MEMORY
 *  - PSA_ERROR_COMMUNICATION_FAILURE
 *  - PSA_ERROR_CORRUPTION_DETECTED
 *  - PSA_ERROR_BAD_STATE:
 *      - The operation state is not valid: it must be active.
 *      - The library has not been previously initialized by psa_crypto_init().
 */
psa_status_t psa_hash_update(psa_hash_operation_t *operation,
			     const uint8_t *input, size_t input_length);

/**
 * psa_hash_finish() - Finish the calculation of the hash of a message.
 * @operation: [in] Active hash operation.
 * @hash: [out] Buffer where the hash is to be written.
 * @hash_size: [in] Size of the @hash buffer in bytes. This must be at least
 *                  :c:macro:`PSA_HASH_LENGTH` where alg is the algorithm that
 *                  the operation performs.
 * @hash_length: [out] On success, the number of bytes that make up the hash
 *                     value.
 *
 * The application must call psa_hash_setup() or psa_hash_resume() before
 * calling this function. This function calculates the hash of the message
 * formed by concatenating the inputs passed to preceding calls to
 * psa_hash_update().
 *
 * When this function returns successfully, the operation becomes inactive.
 * If this function returns an error status, the operation enters an error state
 * and must be aborted by calling psa_hash_abort().
 *
 * .. warning::
 *    It is not recommended to use this function when a specific value is
 *    expected for the hash. Call psa_hash_verify() instead with the expected
 *    hash value.
 *
 * Return:
 *  - PSA_SUCCESS:
 *      Success.
 *  - PSA_ERROR_BUFFER_TOO_SMALL:
 *  -    The size of the @hash buffer is too small. :c:macro`PSA_HASH_LENGTH`
 *       can be used to determine the required buffer size.
 *  - PSA_ERROR_INSUFFICIENT_MEMORY
 *  - PSA_ERROR_COMMUNICATION_FAILURE
 *  - PSA_ERROR_CORRUPTION_DETECTED
 *  - PSA_ERROR_BAD_STATE:
 *      - The operation state is not valid: it must be active.
 *      - The library has not been previously initialized by psa_crypto_init().
 */
psa_status_t psa_hash_finish(psa_hash_operation_t *operation, uint8_t *hash,
			     size_t hash_size, size_t *hash_length);

/**
 * psa_hash_verify() - Finish the calculation of the hash of a message and
 *                     compare it with an expected value.
 * @operation: [in] Active hash operation.
 * @hash: [in] Buffer containing the expected hash value.
 * @hash_length: [in] Size of the @hash buffer in bytes.
 *
 * The application must call psa_hash_setup() before calling this function.
 * This function calculates the hash of the message formed by concatenating the
 * inputs passed to preceding calls to psa_hash_update(). It then compares the
 * calculated hash with the expected hash passed as a parameter to this
 * function.
 *
 * When this function returns successfully, the operation becomes inactive. If
 * this function returns an error status, the operation enters an error state
 * and must be aborted by calling psa_hash_abort().
 *
 * Return:
 *  - PSA_SUCCESS:
 *      Success. The expected hash is identical to the actual hash of the
 *      message.
 *  - PSA_ERROR_INVALID_SIGNATURE:
 *      The calculated hash of the message doesn't match the value in @hash.
 *  - PSA_ERROR_INSUFFICIENT_MEMORY
 *  - PSA_ERROR_COMMUNICATION_FAILURE
 *  - PSA_ERROR_CORRUPTION_DETECTED
 *  - PSA_ERROR_BAD_STATE:
 *      - The operation state is not valid: it must be active.
 *      - The library has not been previously initialized by psa_crypto_init().
 */
psa_status_t psa_hash_verify(psa_hash_operation_t *operation,
			     const uint8_t *hash, size_t hash_length);

/**
 * psa_hash_abort() - Abort a hash operation.
 * @operation: [in] Initialized hash operation.
 *
 * Aborting an operation frees all associated resources except for the operation
 * object itself. Once aborted, the operation object can be reused for another
 * operation by calling psa_hash_setup() again.
 *
 * This function can be called any time after the operation object has been
 * initialized by one of the methods described in &typedef psa_hash_operation_t.
 *
 * In particular, calling psa_hash_abort() after the operation has been
 * terminated by a call to psa_hash_abort(), psa_hash_finish() or
 * psa_hash_verify() is safe and has no effect.
 *
 * Return:
 *  - PSA_SUCCESS
 *  - PSA_ERROR_COMMUNICATION_FAILURE
 *  - PSA_ERROR_HARDWARE_FAILURE
 *  - PSA_ERROR_CORRUPTION_DETECTED
 *  - PSA_ERROR_BAD_STATE:
 *      The library has not been previously initialized by psa_crypto_init().
 */
psa_status_t psa_hash_abort(psa_hash_operation_t *operation);

/**
 * psa_hash_clone() - Clone a hash operation.
 * @source_operation: [in] The active hash operation to clone.
 * @target_operation: [out] The operation object to set up. It must be
 *                          initialized but not active.
 *
 * This function copies the state of an ongoing hash operation to a new
 * operation object. In other words, this function is equivalent to calling
 * psa_hash_setup() on @target_operation with the same algorithm that
 * @source_operation was set up for, then psa_hash_update() on
 * @target_operation with the same input that was passed to @source_operation.
 * After this function returns, the two objects are independent, i.e.
 * subsequent calls involving one of the objects do not affect the other
 * object.
 *
 * Return:
 *  - PSA_SUCCESS
 *      Success. @target_operation is ready to continue the same hash operation
 *      as @source_operation.
 *  - PSA_ERROR_COMMUNICATION_FAILURE
 *  - PSA_ERROR_CORRUPTION_DETECTED
 *  - PSA_ERROR_INSUFFICIENT_MEMORY
 *  - PSA_ERROR_BAD_STATE:
 *      - The @source_operation state is not valid: it must be active.
 *      - The @target_operation state is not valid: it must be inactive.
 *      - The library has not been previously initialized by psa_crypto_init().
 */
psa_status_t psa_hash_clone(const psa_hash_operation_t *source_operation,
			    psa_hash_operation_t *target_operation);

/**
 * psa_hash_suspend() - Halt the hash operation and extract the intermediate
 *                      state of the hash computation.
 * @operation: [in] Active hash operation.
 * @hash_state: [out] Buffer where the hash suspend state is to be written.
 * @hash_state_size: [in] Size of the @hash_state buffer in bytes.
 * @hash_state_length: [out] On success, the number of bytes that make up the
 *                           hash suspend state.
 *
 * .. warning::
 *    Not supported.
 *
 * The application must call psa_hash_setup() or psa_hash_resume() before
 * calling this function. This function extracts an intermediate state of the
 * hash computation of the message formed by concatenating the inputs passed to
 * preceding calls to psa_hash_update().
 *
 * This function can be used to halt a hash operation, and then resume the hash
 * operation at a later time, or in another application, by transferring the
 * extracted hash suspend state to a call to psa_hash_resume().
 *
 * The @hash_state_size must be appropriate for the selected algorithm\:
 *
 *  - A sufficient output size is PSA_HASH_SUSPEND_OUTPUT_SIZE(alg) where alg
 *    is the algorithm that was used to set up the operation.
 *  - PSA_HASH_SUSPEND_OUTPUT_MAX_SIZE evaluates to the maximum output size of
 *    any supported hash algorithm.
 *
 * When this function returns successfully, the operation becomes inactive. If
 * this function returns an error status, the operation enters an error state
 * and must be aborted by calling psa_hash_abort().
 *
 * Hash suspend and resume is not defined for the SHA3 family of hash
 * algorithms. Hash suspend state defines the format of the output from
 * psa_hash_suspend().
 *
 * .. warning::
 *    Applications must not use any of the hash suspend state as if it was a
 *    hash output. Instead, the suspend state must only be used to resume a hash
 *    operation, and psa_hash_finish() or psa_hash_verify() can then calculate
 *    or verify the final hash value.
 *
 * Return:
 *  - PSA_SUCCESS:
 *      Success.
 *  - PSA_ERROR_BUFFER_TOO_SMALL:
 *      The size of the @hash_state buffer is too small.
 *      :c:macro:`PSA_HASH_SUSPEND_OUTPUT_SIZE` or
 *      :c:macro:`PSA_HASH_SUSPEND_OUTPUT_MAX_SIZE` can be used to determine
 *      the required buffer size.
 *  - PSA_ERROR_NOT_SUPPORTED:
 *      The hash algorithm being computed does not support suspend and resume.
 *  - PSA_ERROR_INSUFFICIENT_MEMORY
 *  - PSA_ERROR_COMMUNICATION_FAILURE
 *  - PSA_ERROR_CORRUPTION_DETECTED
 *  - PSA_ERROR_BAD_STATE:
 *      - The operation state is not valid: it must be active.
 *      - The library has not been previously initialized by psa_crypto_init().
 */
psa_status_t psa_hash_suspend(psa_hash_operation_t *operation,
			      uint8_t *hash_state, size_t hash_state_size,
			      size_t *hash_state_length);

/**
 * psa_hash_resume() - Set up a multi-part hash operation using the hash
 *                     suspend state from a previously suspended hash operation.
 * @operation: [in] The operation object to set up. It must have been
 *                  initialized as per the documentation for
 *                  &typedef psa_hash_operation_t and not yet in use.
 * @hash_state: [in] A buffer containing the suspended hash state which is to
 *                   be resumed. This must be in the format output by
 *                   psa_hash_suspend().
 * @hash_state_length: [in] Length of @hash_state in bytes.
 *
 * .. warning::
 *     Not supported.
 *
 * After a successful call to psa_hash_resume(), the application must eventually
 * terminate the operation. The following events terminate an operation\:
 *
 *  - A successful call to psa_hash_finish(), psa_hash_verify() or
 *    psa_hash_suspend().
 *  - A call to psa_hash_abort().
 *
 * Return:
 *  - PSA_SUCCESS:
 *      Success.
 *  - PSA_ERROR_NOT_SUPPORTED:
 *      The provided hash suspend state is for an algorithm that is not
 *      supported.
 *  - PSA_ERROR_INVALID_ARGUMENT:
 *      @hash_state does not correspond to a valid hash suspend state. See Hash suspend state format
 *      for the definition.
 *  - PSA_ERROR_INSUFFICIENT_MEMORY
 *  - PSA_ERROR_COMMUNICATION_FAILURE
 *  - PSA_ERROR_HARDWARE_FAILURE
 *  - PSA_ERROR_CORRUPTION_DETECTED
 *  - PSA_ERROR_BAD_STATE:
 *      - The operation state is not valid: it must be inactive.
 *      - The library has not been previously initialized by psa_crypto_init().
 */
psa_status_t psa_hash_resume(psa_hash_operation_t *operation,
			     const uint8_t *hash_state,
			     size_t hash_state_length);

#endif /* __PSA_CRYPTO_HASH_H__ */
