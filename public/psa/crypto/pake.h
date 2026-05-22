/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2022-2026 NXP
 */

#ifndef __PSA_CRYPTO_PAKE_H__
#define __PSA_CRYPTO_PAKE_H__

/**
 * typedef psa_pake_operation_t - The type of the state object for PAKE
 *                                operations.
 *
 * Before calling any function on a PAKE operation object,
 * the application must initialize it by any of the following means\:
 *
 *  - Set the object to all-bits-zero, for example\:
 *
 *    .. code-block:: c
 *
 *       psa_pake_operation_t operation;
 *       memset(&operation, 0, sizeof(operation));
 *
 *  - Initialize the object to logical zero values by declaring the object as
 *    static or global without an explicit initializer, for example\:
 *
 *    .. code-block:: c
 *
 *       static psa_pake_operation_t operation;
 *
 *  - Initialize the object to the initializer
 *    :c:macro:`PSA_PAKE_OPERATION_INIT`, for example\:
 *
 *    .. code-block:: c
 *
 *       psa_pake_operation_t operation = PSA_PAKE_OPERATION_INIT;
 *
 *  - Assign the result of the function :c:func:`psa_pake_operation_init` to
 *    the object, for example\:
 *
 *    .. code-block:: c
 *
 *       psa_pake_operation_t operation;
 *       operation = psa_pake_operation_init();
 */
typedef struct psa_pake_operation_s psa_pake_operation_t;

/**
 * typedef psa_pake_cipher_suite_t - The type of an object describing a PAKE
 *                                   cipher suite.
 *
 * Before calling any function on a PAKE cipher suite object,
 * the application must initialize it by any of the following means\:
 *
 *  - Set the object to all-bits-zero, for example\:
 *
 *    .. code-block:: c
 *
 *       psa_pake_cipher_suite_t cipher_suite;
 *       memset(&cipher_suite, 0, sizeof(cipher_suite));
 *
 *  - Initialize the object to logical zero values by declaring the object as
 *    static or global without an explicit initializer, for example\:
 *
 *    .. code-block:: c
 *
 *       static psa_pake_cipher_suite_t cipher_suite;
 *
 *  - Initialize the object to the initializer
 *    :c:macro:`PSA_PAKE_CIPHER_SUITE_INIT`, for example\:
 *
 *    .. code-block:: c
 *
 *       psa_pake_cipher_suite_t cipher_suite = PSA_PAKE_CIPHER_SUITE_INIT;
 *
 *  - Assign the result of the function :c:func:`psa_pake_cipher_suite_init` to
 *    the object, for example\:
 *
 *    .. code-block:: c
 *
 *       psa_pake_cipher_suite_t cipher_suite;
 *       cipher_suite = psa_pake_cipher_suite_init();
 */
typedef struct psa_pake_cipher_suite_s psa_pake_cipher_suite_t;

/**
 * psa_pake_operation_init() - Return an initial value for a PAKE operation
 *                             object.
 *
 * Return:
 * Initialized value of PAKE operation object.
 */
static psa_pake_operation_t psa_pake_operation_init(void);

/**
 * psa_pake_cipher_suite_init() - Return an initial value for a PAKE cipher
 *                                suite object.
 *
 * Return:
 * Initialized value of PAKE cipher suite object.
 */
static psa_pake_cipher_suite_t psa_pake_cipher_suite_init(void);

/**
 * psa_pake_cs_get_algorithm() - Retrieve the PAKE algorithm from a PAKE cipher
 *                               suite.
 * @cipher_suite: [in] The cipher suite object to query.
 *
 * .. warning::
 *    Not supported.
 *
 * Return:
 * The PAKE algorithm stored in the cipher suite object.
 */
psa_algorithm_t
psa_pake_cs_get_algorithm(const psa_pake_cipher_suite_t *cipher_suite);

/**
 * psa_pake_cs_set_algorithm() - Declare the PAKE algorithm for the cipher
 *                               suite.
 * @cipher_suite: [in/out] The cipher suite object to write to.
 * @alg: [in] The PAKE algorithm to write such that
 *            :c:macro:`PSA_ALG_IS_PAKE` is true.
 *
 * .. warning::
 *    Not supported.
 *
 * This function overwrites any PAKE algorithm previously set in @cipher_suite.
 *
 * Return:
 * void
 */
void psa_pake_cs_set_algorithm(psa_pake_cipher_suite_t *cipher_suite,
			       psa_algorithm_t alg);

/**
 * psa_pake_cs_get_primitive() - Retrieve the primitive from a PAKE cipher
 *                               suite.
 * @cipher_suite: [in] The cipher suite object to query.
 *
 * .. warning::
 *    Not supported.
 *
 * Return:
 * The primitive stored in the cipher suite object.
 */
psa_pake_primitive_t
psa_pake_cs_get_primitive(const psa_pake_cipher_suite_t *cipher_suite);

/**
 * psa_pake_cs_set_primitive() - Declare the primitive for a PAKE cipher suite.
 * @cipher_suite: [in/out] The cipher suite object to write to.
 * @primitive: [in] The PAKE primitive to write: a value of
 *                  &typedef psa_pake_primitive_t. If this is 0, the primitive
 *                  type in cipher_suite becomes unspecified.
 *
 * .. warning::
 *    Not supported.
 *
 * This function overwrites any primitive previously set in @cipher_suite.
 *
 * Return:
 * void
 */
void psa_pake_cs_set_primitive(psa_pake_cipher_suite_t *cipher_suite,
			       psa_pake_primitive_t primitive);

/**
 * psa_pake_cs_get_key_confirmation() - Retrieve the key confirmation from a
 *                                      PAKE cipher suite.
 * @cipher_suite: [in] The cipher suite object to query.
 *
 * .. warning::
 *    Not supported.
 *
 * Return:
 * A key confirmation value: either :c:macro:`PSA_PAKE_CONFIRMED_KEY` or
 * :c:macro:`PSA_PAKE_UNCONFIRMED_KEY`.
 */
psa_pake_primitive_t
psa_pake_cs_get_key_confirmation(const psa_pake_cipher_suite_t *cipher_suite);

/**
 * psa_pake_cs_set_key_confirmation() - Declare the key confirmation from a PAKE
 *                                      cipher suite.
 * @cipher_suite: [in/out] The cipher suite object to write to.
 * @key_confirmation: [in] The key confirmation value to write:
 *                    either :c:macro:`PSA_PAKE_CONFIRMED_KEY` or
 *                    :c:macro:`PSA_PAKE_UNCONFIRMED_KEY`.
 *
 * .. warning::
 *    Not supported.
 *
 * This function overwrites any key confirmation previously set in
 * @cipher_suite.
 *
 * The documentation of individual PAKE algorithms specifies which key
 * confirmation values are valid for the algorithm.
 *
 * Return:
 * void
 */
void psa_pake_cs_set_key_confirmation(psa_pake_cipher_suite_t *cipher_suite,
				      uint32_t key_confirmation);

/**
 * psa_pake_setup() - Setup a password-authenticated key exchange.
 * @operation: [in] The operation object to set up. It must have been
 *                  initialized as per the documentation for
 *                  &typedef psa_pake_operation_t and not yet in use.
 * @password_key: [in] Identifier of the key holding the password or a value
 *                     derived from the password. It must remain valid until the
 *                     operation terminates. The key must permit the usage
 *                     PSA_KEY_USAGE_DERIVE.
 * @cipher_suite: [in] The cipher suite to use. A PAKE cipher suite fully
 *                     characterizes a PAKE algorithm, including the PAKE
 *                     algorithm.
 *
 * .. warning::
 *    Not supported.
 *
 * After a successful call to psa_pake_setup(), the operation is active,
 * and the application must eventually terminate the operation. The following
 * events terminate an operation\:
 *
 *  - A successful call to psa_pake_get_shared_key().
 *  - A call to psa_pake_abort().
 *
 * If psa_pake_setup() returns an error, the operation object is unchanged.
 * If a subsequent function call with an active operation returns an error,
 * the operation enters an error state.
 *
 * To abandon an active operation, or reset an operation in an error state,
 * call psa_pake_abort().
 *
 * Return:
 *  - PSA_SUCCESS:
 *      Success. The operation is now active.
 *  - PSA_ERROR_INVALID_HANDLE:
 *      @password_key is not a valid key identifier.
 *  - PSA_ERROR_NOT_PERMITTED:
 *      @password_key does not have the PSA_KEY_USAGE_DERIVE flag, or it does
 *      not permit the algorithm in @cipher_suite.
 *  - PSA_ERROR_INVALID_ARGUMENT:
 *      - The algorithm in @cipher_suite is not a PAKE algorithm, or encodes an
 *        invalid hash algorithm.
 *      - The PAKE primitive in @cipher_suite is not compatible with the PAKE
 *        algorithm.
 *      - The key confirmation value in @cipher_suite is not compatible with
 *        the PAKE algorithm and primitive.
 *      - The key type or key size of @password_key is not compatible with
 *        @cipher_suite.
 *  - PSA_ERROR_NOT_SUPPORTED:
 *      - The algorithm in @cipher_suite is not a supported PAKE algorithm,
 *        or encodes an unsupported hash algorithm.
 *      - The PAKE primitive in @cipher_suite is not supported or not compatible
 *        with the PAKE algorithm.
 *      - The key confirmation value in @cipher_suite is not supported, or not
 *        compatible, with the PAKE algorithm and primitive.
 *      - The key type or key size of password_key is not supported with
 *        @cipher suite.
 *  - PSA_ERROR_COMMUNICATION_FAILURE
 *  - PSA_ERROR_CORRUPTION_DETECTED
 *  - PSA_ERROR_STORAGE_FAILURE
 *  - PSA_ERROR_DATA_CORRUPT
 *  - PSA_ERROR_DATA_INVALID
 *  - PSA_ERROR_BAD_STATE:
 *      - The operation state is not valid: it must be inactive.
 *      - The library has not been previously initialized by psa_crypto_init().
 */
psa_status_t psa_pake_setup(psa_pake_operation_t *operation,
			    psa_key_id_t password_key,
			    const psa_pake_cipher_suite_t *cipher_suite);

/**
 * psa_pake_set_role() - Set the application role for a password-authenticated
 *                       key exchange.
 * @operation: [in] Active PAKE operation.
 * @role: [in] A value of &typedef psa_pake_role_t indicating the application
 *             role in the PAKE algorithm.
 *
 * .. warning::
 *    Not supported.
 *
 * Not all PAKE algorithms need to differentiate the communicating participants.
 * For PAKE algorithms that do not require a role to be specified, the
 * application can do either of the following\:
 *
 *  - Not call psa_pake_set_role() on the PAKE operation.
 *  - Call psa_pake_set_role() with the PSA_PAKE_ROLE_NONE role.
 *
 * Return:
 *  - PSA_SUCCESS:
 *      Success.
 *  - PSA_ERROR_INVALID_ARGUMENT:
 *      - @role is not a valid PAKE role in the operation’s algorithm.
 *      - @role is not compatible with the operation’s key type.
 *  - PSA_ERROR_NOT_SUPPORTED:
 *      - @role is not a valid PAKE role.
 *      - @role is not supported with the operation’s key type.
 *  - PSA_ERROR_COMMUNICATION_FAILURE
 *  - PSA_ERROR_CORRUPTION_DETECTED
 *  - PSA_ERROR_BAD_STATE:
 *      - The operation state is not valid: it must be active, and
 *        psa_pake_set_role(), psa_pake_input(), and psa_pake_output()
 *        must not have been called yet.
 *      - The library has not been previously initialized by psa_crypto_init().
 */
psa_status_t psa_pake_set_role(psa_pake_operation_t *operation,
			       psa_pake_role_t role);

/**
 * psa_pake_set_user() - Set the user ID for a password-authenticated key
 *                       exchange.
 * @operation: [in] Active PAKE operation.
 * @user_id: [in] The user ID to authenticate with.
 * @user_id_len: [in] Size of the @user_id buffer in bytes.
 *
 * .. warning::
 *    Not supported.
 *
 * Call this function to set the user ID. For PAKE algorithms that associate a
 * user identifier with both participants in the session, also call
 * psa_pake_set_peer() with the peer ID. For PAKE algorithms that associate a
 * single user identifier with the session, call psa_pake_set_user() only.
 *
 * Return:
 *  - PSA_SUCCESS:
 *      Success.
 *  - PSA_ERROR_INVALID_ARGUMENT:
 *      @user_id is not valid for the operation’s algorithm and cipher suite.
 *  - PSA_ERROR_NOT_SUPPORTED:
 *      @user_id is not supported.
 *  - PSA_ERROR_INSUFFICIENT_MEMORY
 *  - PSA_ERROR_COMMUNICATION_FAILURE
 *  - PSA_ERROR_CORRUPTION_DETECTED
 *  - PSA_ERROR_BAD_STATE:
 *      - The operation state is not valid: it must be active, and
 *        psa_pake_set_user(), psa_pake_input(), and psa_pake_output()
 *        must not have been called yet.
 *      - The library has not been previously initialized by psa_crypto_init().
 */
psa_status_t psa_pake_set_user(psa_pake_operation_t *operation,
			       const uint8_t *user_id, size_t user_id_len);

/**
 * psa_pake_set_peer() - Set the peer ID for a password-authenticated key
 *                       exchange.
 * @operation: [in] Active PAKE operation.
 * @peer_id: [in] The peer ID to authenticate with.
 * @peer_id_len: [in] Size of the @peer_id buffer in bytes.
 *
 * .. warning::
 *    Not supported.
 *
 * Call this function in addition to psa_pake_set_user() for PAKE algorithms
 * that associate a user identifier with both participants in the session.
 * For PAKE algorithms that associate a single user identifier with the session,
 * call psa_pake_set_user() only.
 *
 * Return:
 *  - PSA_SUCCESS:
 *       Success.
 *  - PSA_ERROR_INVALID_ARGUMENT:
 *       @peer_id is not valid for the operation’s algorithm and cipher suite.
 *  - PSA_ERROR_NOT_SUPPORTED:
 *       @peer_id is not supported for the implementation.
 *  - PSA_ERROR_INSUFFICIENT_MEMORY
 *  - PSA_ERROR_COMMUNICATION_FAILURE
 *  - PSA_ERROR_CORRUPTION_DETECTED
 *  - PSA_ERROR_BAD_STATE:
 *      - The operation state is not valid: it must be active, and
 *        psa_pake_set_peer(), psa_pake_input(), and psa_pake_output()
 *        must not have been called yet.
 *      - Calling psa_pake_set_peer() is invalid with the operation’s algorithm.
 *      - The library has not been previously initialized by psa_crypto_init().
 */
psa_status_t psa_pake_set_peer(psa_pake_operation_t *operation,
			       const uint8_t *peer_id, size_t peer_id_len);

/**
 * psa_pake_set_context() - Set the context data for a password-authenticated
 *                          key exchange.
 * @operation: [in] Active PAKE operation.
 * @context: [in] The context to authenticate with.
 * @context_len: [in] Size of the @context buffer in bytes.
 *
 * .. warning::
 *    Not supported.
 *
 * Call this function for PAKE algorithms that accept additional context data
 * as part of the protocol setup.
 *
 * Return:
 *  - PSA_SUCCESS:
 *      Success.
 *  - PSA_ERROR_INVALID_ARGUMENT:
 *      @context is not valid for the operation’s algorithm and cipher suite.
 *  - PSA_ERROR_NOT_SUPPORTED:
 *      The value of the @context is not supported.
 *  - PSA_ERROR_INSUFFICIENT_MEMORY
 *  - PSA_ERROR_COMMUNICATION_FAILURE
 *  - PSA_ERROR_CORRUPTION_DETECTED
 *  - PSA_ERROR_BAD_STATE:
 *      - The operation state is not valid: it must be active, and
 *        psa_pake_set_context(), psa_pake_input(), and psa_pake_output()
 *        must not have been called yet.
 *      - Calling psa_pake_set_context() is invalid with the operation’s
 *        algorithm.
 *      - The library has not been previously initialized by psa_crypto_init().
 */
psa_status_t psa_pake_set_context(psa_pake_operation_t *operation,
				  const uint8_t *context, size_t context_len);

/**
 * psa_pake_output() - Get output for a step of a password-authenticated key
 *                     exchange.
 * @operation: [in] Active PAKE operation.
 * @step: [in] The step of the algorithm for which the output is requested.
 * @output: [out] Buffer where the output is to be written. The format of the
 *                output depends on the step.
 * @output_size: [in] Size of the output buffer in bytes.
 * @output_length: [out] On success, the number of bytes of the returned output.
 *
 * .. warning::
 *    Not supported.
 *
 * The @output_size parameter must be appropriate for the cipher suite and
 * output step\:
 *
 *  - A sufficient output size is :c:macro:`PSA_PAKE_OUTPUT_SIZE` where alg and
 *    primitive are the PAKE algorithm and primitive in the operation’s cipher
 *    suite, and step is the output step.
 *  - :c:macro:`PSA_PAKE_OUTPUT_MAX_SIZE` evaluates to the maximum output size
 *    of any supported PAKE algorithm, primitive and step.
 *
 * Depending on the algorithm being executed, you might need to call this
 * function several times or you might not need to call this at all.
 *
 * The exact sequence of calls to perform a password-authenticated key exchange
 * depends on the algorithm in use.
 *
 * If this function returns an error status, the operation enters an error state
 * and must be aborted by calling psa_pake_abort().
 *
 * Return:
 *  - PSA_SUCCESS:
 *      Success.
 *  - PSA_ERROR_BUFFER_TOO_SMALL:
 *      The size of the @output buffer is too small.
 *      :c:macro:`PSA_PAKE_OUTPUT_SIZE` or :c:macro:`PSA_PAKE_OUTPUT_MAX_SIZE`
 *      can be used to determine a sufficient buffer size.
 *  - PSA_ERROR_INVALID_ARGUMENT:
 *      @step is not compatible with the operation’s algorithm.
 *  - PSA_ERROR_NOT_SUPPORTED:
 *      @step is not supported with the operation’s algorithm.
 *  - PSA_ERROR_INSUFFICIENT_ENTROPY
 *  - PSA_ERROR_INSUFFICIENT_MEMORY
 *  - PSA_ERROR_COMMUNICATION_FAILURE
 *  - PSA_ERROR_CORRUPTION_DETECTED
 *  - PSA_ERROR_STORAGE_FAILURE
 *  - PSA_ERROR_DATA_CORRUPT
 *  - PSA_ERROR_DATA_INVALID
 *  - PSA_ERROR_BAD_STATE:
 *      - The operation state is not valid: it must be active and fully set up,
 *        and this call must conform to the algorithm’s requirements for
 *        ordering of input and output steps.
 *      - The library has not been previously initialized by psa_crypto_init().
 */
psa_status_t psa_pake_output(psa_pake_operation_t *operation,
			     psa_pake_step_t step, uint8_t *output,
			     size_t output_size, size_t *output_length);

/**
 * psa_pake_input() - Provide input for a step of a password-authenticated key
 *                    exchange.
 * @operation: [in] Active PAKE operation.
 * @step: [in] The step for which the input is provided.
 * @input: [in] Buffer containing the input. The format of the input depends on
 *              the step.
 * @input_length: [in] Size of the input buffer in bytes.
 *
 * .. warning::
 *    Not supported.
 *
 * Depending on the algorithm being executed, you might need to call this
 * function several times or you might not need to call this at all.
 *
 * The exact sequence of calls to perform a password-authenticated key exchange
 * depends on the algorithm in use.
 *
 * :c:macro:`PSA_PAKE_INPUT_SIZE` or :c:macro:`PSA_PAKE_INPUT_MAX_SIZE` can be
 * used to allocate buffers of sufficient size to transfer inputs that are
 * received from the peer into the operation.
 *
 * If this function returns an error status, the operation enters an error state
 * and must be aborted by calling psa_pake_abort().
 *
 * Return:
 *  - PSA_SUCCESS:
 *      Success.
 *  - PSA_ERROR_INVALID_SIGNATURE:
 *      The verification fails for a PSA_PAKE_STEP_ZK_PROOF or
 *      PSA_PAKE_STEP_CONFIRM input step.
 *  - PSA_ERROR_INVALID_ARGUMENT:
 *      - @step is not compatible with the operation’s algorithm.
 *      - The input is not valid for the operation’s algorithm, cipher suite or
 *        step.
 *  - PSA_ERROR_NOT_SUPPORTED:
 *      - @step is not supported with the operation’s algorithm.
 *      - The input is not supported for the operation’s algorithm, cipher
 *        suite or step.
 *  - PSA_ERROR_INSUFFICIENT_MEMORY
 *  - PSA_ERROR_COMMUNICATION_FAILURE
 *  - PSA_ERROR_CORRUPTION_DETECTED
 *  - PSA_ERROR_STORAGE_FAILURE
 *  - PSA_ERROR_DATA_CORRUPT
 *  - PSA_ERROR_DATA_INVALID
 *  - PSA_ERROR_BAD_STATE:
 *      - The operation state is not valid: it must be active and fully set up,
 *        and this call must conform to the algorithm’s requirements for
 *        ordering of input and output steps.
 *      - The library has not been previously initialized by psa_crypto_init().
 */
psa_status_t psa_pake_input(psa_pake_operation_t *operation,
			    psa_pake_step_t step, const uint8_t *input,
			    size_t input_length);

/**
 * psa_pake_get_shared_key() - Extract the shared secret from the PAKE as a key.
 * @operation: [in] Active PAKE operation.
 * @attributes: [in] The attributes for the new key.
 * @key: [out] On success, an identifier for the newly created key.
 *             PSA_KEY_ID_NULL on failure.
 *
 * .. warning::
 *    Not supported.
 *
 * The following new key attributes are required\:
 *
 *  - The key type. All PAKE algorithms can output a key of type
 *    PSA_KEY_TYPE_DERIVE or PSA_KEY_TYPE_HMAC. PAKE algorithms that produce a
 *    pseudorandom shared secret, can also output block-cipher key types, for
 *    example PSA_KEY_TYPE_AES.
 *  - The key permitted algorithm policy.
 *  - The key usage flags.
 *
 * The following new key attributes must be set in case of a persistent key\:
 *
 *  - The key lifetime.
 *  - The key identifier.
 *
 * The following new key attributes is optional\:
 *
 *  - The key size, if nonzero, it must be equal to the size of the PAKE
 *    secret shared.
 *
 * The shared secret is retrieved as a key. Its location, policy, and type are
 * taken from @attributes.
 *
 * The size of the returned key is always the bit-size of the PAKE shared
 * secret, rounded up to a whole number of bytes. The size of the shared secret
 * is dependent on the PAKE algorithm and cipher suite.
 *
 * This is the final call in a PAKE operation, which retrieves the shared secret
 * as a key. It is recommended that this key is used as an input to a key
 * derivation operation to produce additional cryptographic keys. For some PAKE
 * algorithms, the shared secret is also suitable for use as a key in
 * cryptographic operations such as encryption.
 *
 * Depending on the key confirmation requested in the cipher suite,
 * psa_pake_get_shared_key() must be called either before or after the
 * key-confirmation output and input steps for the PAKE algorithm.
 * The key confirmation affects the guarantees that can be made about the
 * shared key\:
 *
 * **Unconfirmed key**
 *
 *   If the cipher suite used to set up the operation requested an
 *   unconfirmed key, the application must call psa_pake_get_shared_key()
 *   after the key-exchange output and input steps are completed.
 *   The PAKE algorithm provides a cryptographic guarantee that only a peer
 *   who used the same password, and identity inputs, is able to compute the
 *   same key. However, there is no guarantee that the peer is the
 *   participant it claims to be, and was able to compute the same key.
 *
 *   Since the peer is not authenticated, no action should be taken that
 *   assumes that the peer is who it claims to be. For example, do not
 *   access restricted resources on the peer’s behalf until an explicit
 *   authentication has succeeded.
 *
 * .. note::
 *       Some PAKE algorithms do not enable the output of the shared secret
 *       until it has been confirmed.
 *
 * **Confirmed key**
 *
 *   If the cipher suite used to set up the operation requested a confirmed
 *   key, the application must call psa_pake_get_shared_key() after the
 *   key-exchange and key-confirmation output and input steps are completed.
 *
 *   Following key confirmation, the PAKE algorithm provides a cryptographic
 *   guarantee that the peer used the same password and identity inputs,
 *   and has computed the identical shared secret key.
 *
 *   Since the peer is not authenticated, no action should be taken that
 *   assumes that the peer is who it claims to be. For example, do not
 *   access restricted resources on the peer’s behalf until an explicit
 *   authentication has succeeded.
 *
 * .. note::
 *       Some PAKE algorithms do not include any key-confirmation steps.
 *
 * The exact sequence of calls to perform a password-authenticated key exchange
 * depends on the algorithm in use.
 *
 * When this function returns successfully, operation becomes inactive.
 * If this function returns an error status, the operation enters an error state
 * and must be aborted by calling psa_pake_abort().
 *
 * Return:
 *  - PSA_SUCCESS:
 *      Success. If the key is persistent, the key material and the key’s
 *      metadata have been saved to persistent storage.
 *  - PSA_ERROR_NOT_PERMITTED:
 *      Creating a key with the specified attributes is not permitted.
 *  - PSA_ERROR_ALREADY_EXISTS:
 *      This is an attempt to create a persistent key, and there is already a
 *      persistent key with the given identifier.
 *  - PSA_ERROR_INVALID_ARGUMENT:
 *      - The key type is not valid for output from this operation’s algorithm.
 *      - The key size is nonzero.
 *      - The key lifetime is invalid.
 *      - The key identifier is not valid for the key lifetime.
 *      - The key usage flags include invalid values.
 *      - The key’s permitted-usage algorithm is invalid.
 *      - The key attributes, as a whole, are invalid.
 *  - PSA_ERROR_NOT_SUPPORTED:
 *      The key attributes, as a whole, are not supported for creation from a
 *      PAKE secret.
 *  - PSA_ERROR_INSUFFICIENT_MEMORY
 *  - PSA_ERROR_COMMUNICATION_FAILURE
 *  - PSA_ERROR_CORRUPTION_DETECTED
 *  - PSA_ERROR_STORAGE_FAILURE
 *  - PSA_ERROR_DATA_CORRUPT
 *  - PSA_ERROR_DATA_INVALID
 *  - PSA_ERROR_BAD_STATE:
 *      - The state of PAKE operation operation is not valid: it must be ready
 *        to return the shared secret.
 *
 *        For an unconfirmed key, this will be when the key-exchange output and
 *        input steps are complete, but prior to any key-confirmation output and
 *        input steps.
 *
 *        For a confirmed key, this will be when all key-exchange and
 *        key-confirmation output and input steps are complete.
 *      - The library has not been previously initialized by psa_crypto_init().
 */
psa_status_t psa_pake_get_shared_key(psa_pake_operation_t *operation,
				     const psa_key_attributes_t *attributes,
				     psa_key_id_t *key);

/**
 * psa_pake_abort() - Abort a PAKE operation.
 * @operation: [in] Initialized PAKE operation.
 *
 * .. warning::
 *     Not supported
 *
 * Aborting an operation frees all associated resources except for the
 * @operation object itself. Once aborted, the operation object can be reused
 * for another operation by calling psa_pake_setup() again.
 *
 * This function can be called any time after the operation object has been
 * initialized as described in &typedef psa_pake_operation_t.
 *
 * In particular, calling psa_pake_abort() after the operation has been
 * terminated by a call to psa_pake_abort() or psa_pake_get_shared_key() is
 * safe and has no effect.
 *
 * Return:
 *  - PSA_SUCCESS:
 *      Success. The operation object can now be discarded or reused.
 *  - PSA_ERROR_COMMUNICATION_FAILURE
 *  - PSA_ERROR_CORRUPTION_DETECTED
 *  - PSA_ERROR_BAD_STATE:
 *      The library has not been previously initialized by psa_crypto_init().
 */
psa_status_t psa_pake_abort(psa_pake_operation_t *operation);

#endif /* __PSA_CRYPTO_PAKE_H__ */