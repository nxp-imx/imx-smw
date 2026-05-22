/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2022-2026 NXP
 */

#ifndef __PSA_KEYMGR_H__
#define __PSA_KEYMGR_H__

/*
 * Reference
 * Documentation:
 *	PSA Cryptography API v1.3.2
 * Link:
 *	https://arm-software.github.io/psa-api/crypto/1.3/about
 */

/**
 * typedef psa_key_attributes_t - The type of an object containing key attributes.
 *
 * This is the object that represents the metadata of a key object. Metadata
 * that can be stored in attributes includes\:
 *
 *  - The location of the key in storage, indicated by its key identifier and
 *    its lifetime.
 *  - The key’s policy, comprising usage flags and a specification of the
 *    permitted algorithm(s).
 *  - Information about the key itself: the key type and its size.
 *  - Implementation specific attributes.
 *
 * The actual key material is not considered an attribute of a key. Key
 * attributes do not contain information that is generally considered highly
 * confidential.
 *
 * Each attribute of this object is set with a function psa_set_key_xxx() and
 * retrieved with a function psa_get_key_xxx().
 *
 * An attribute object can contain references to auxiliary resources, for
 * example pointers to allocated memory or indirect references to pre-calculated
 * values. In order to free such resources, the application must call
 * psa_reset_key_attributes(). As an exception, calling
 * psa_reset_key_attributes() on an attribute object is optional if the object
 * has only been modified by the following functions since it was initialized or
 * last reset with psa_reset_key_attributes()\:
 *
 *  - psa_set_key_id()
 *  - psa_set_key_lifetime()
 *  - psa_set_key_type()
 *  - psa_set_key_bits()
 *  - psa_set_key_usage_flags()
 *  - psa_set_key_algorithm()
 *
 * Before calling any function on a key attribute object, the application must
 * initialize it by any of the following means\:
 *
 *  - Set the object to all-bits-zero, for example\:
 *
 *    .. code-block:: c
 *
 *       psa_key_attributes_t attributes;
 *       memset(&attributes, 0, sizeof(attributes));
 *
 *  - Initialize the object to logical zero values by declaring the object as
 *    static or global without an explicit initializer, for example\:
 *
 *    .. code-block:: c
 *
 *       static psa_key_attributes_t attributes;
 *
 *  - Initialize the object to the initializer :c:macro:`PSA_KEY_ATTRIBUTES_INIT`,
 *    for example\:
 *
 *    .. code-block:: c
 *
 *       psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
 *
 *  - Assign the result of the function :c:func:`psa_key_attributes_init` to
 *    the object, for example\:
 *
 *    .. code-block:: c
 *
 *       psa_key_attributes_t attributes;
 *       attributes = psa_key_attributes_init();
 *
 * A freshly initialized attribute object contains the following values\:
 *
 * .. table::
 *    :class: wrap-table
 *
 *    +----------------+----------------------------------------------------------+
 *    | **Attribute**  | **Value**                                                |
 *    +================+==========================================================+
 *    | lifetime       | PSA_KEY_LIFETIME_VOLATILE.                               |
 *    +----------------+----------------------------------------------------------+
 *    | key identifier | PSA_KEY_ID_NULL - which is not a valid key identifier.   |
 *    +----------------+----------------------------------------------------------+
 *    | type           | PSA_KEY_TYPE_NONE - meaning that the type is unspecified.|
 *    +----------------+----------------------------------------------------------+
 *    | key size       | 0 - meaning that the size is unspecified.                |
 *    +----------------+----------------------------------------------------------+
 *    | usage flags    | 0 - which allows no usage except exporting a public key. |
 *    +----------------+----------------------------------------------------------+
 *    | algorithm      | PSA_ALG_NONE - which does not allow cryptographic usage, |
 *    |                | but allows exporting.                                    |
 *    +----------------+----------------------------------------------------------+
 *
 * **Usage**
 *
 * A typical sequence to create a key is as follows\:
 *
 *  #. Create and initialize an attribute object.
 *  #. If the key is persistent, call psa_set_key_id(). Also call
 *     psa_set_key_lifetime() to place the key in a non-default location.
 *  #. Set the key policy with psa_set_key_usage_flags() and
 *     psa_set_key_algorithm().
 *  #. Set the key type with psa_set_key_type(). Skip this step if copying an
 *     existing key with psa_copy_key().
 *  #. When generating a random key with psa_generate_key() or deriving a key
 *     with psa_key_derivation_output_key(), set the desired key size with
 *     psa_set_key_bits().
 *  #. Call a key creation function: psa_import_key(), psa_generate_key(),
 *     psa_key_derivation_output_key() or psa_copy_key(). This function reads
 *     the attribute object, creates a key with these attributes, and outputs
 *     an identifier for the newly created key.
 *  #. Optionally call psa_reset_key_attributes(), now that the attribute
 *     object is no longer needed. Currently this call is not required as the
 *     attributes defined in this specification do not require additional
 *     resources beyond the object itself.
 *
 * A typical sequence to query a key’s attributes is as follows\:
 *
 *  #. Call psa_get_key_attributes().
 *  #. Call psa_get_key_xxx() functions to retrieve the required attribute(s).
 *  #. Call psa_reset_key_attributes() to free any resources that can be used
 *     by the attribute object.
 *
 * Once a key has been created, it is impossible to change its attributes.
 */
typedef struct psa_key_attributes_s psa_key_attributes_t;

/**
 * typedef psa_custom_key_parameters_t - Custom production parameters for key
 *                                       generation or key derivation.
 *
 * The interpretation of this structure depends on the type of the key.
 */
typedef struct psa_custom_key_parameters_s psa_custom_key_parameters_t;

/**
 * typedef psa_key_derivation_operation_t - The type of the state object for key
 *                                          derivation operations.
 *
 * Before calling any function on a key derivation operation object, the
 * application must initialize it by any of the following means\:
 *
 *  - Set the object to all-bits-zero, for example\:
 *
 *    .. code-block:: c
 *
 *       psa_key_derivation_operation_t operation;
 *       memset(&operation, 0, sizeof(operation));
 *
 *  - Initialize the object to logical zero values by declaring the object as
 *    static or global without an explicit initializer, for example\:
 *
 *    .. code-block:: c
 *
 *       static psa_key_derivation_operation_t operation;
 *
 *  - Initialize the object to the initializer
 *    :c:macro:`PSA_KEY_DERIVATION_OPERATION_INIT`, for example\:
 *
 *    .. code-block:: c
 *
 *       psa_key_derivation_operation_t operation = PSA_KEY_DERIVATION_OPERATION_INIT;
 *
 *  - Assign the result of the function
 *    :c:func:`psa_key_derivation_operation_init` to the object, for example\:
 *
 *    .. code-block:: c
 *
 *       psa_key_derivation_operation_t operation;
 *       operation = psa_key_derivation_operation_init();
 */
typedef struct psa_key_derivation_operation_s psa_key_derivation_operation_t;

/**
 * psa_reset_key_attributes() - Reset a key attribute object to a freshly
 *                              initialized state.
 * @attributes: [in/out] The attribute object to reset.
 *
 * The attribute object must be initialized as described in the documentation
 * of the &typedef psa_key_attributes_t before calling this function. Once the
 * object has been initialized, this function can be called at any time.
 *
 * This function frees any auxiliary resources that the object might contain.
 *
 * Return:
 * void
 */
void psa_reset_key_attributes(psa_key_attributes_t *attributes);

/**
 * psa_key_attributes_init() - Return an initial value for a key attribute
 *                             object.
 *
 * Return:
 * Initialized value of a key attribute.
 */
static psa_key_attributes_t psa_key_attributes_init(void);

/**
 * psa_set_key_id() - Declare a key as persistent and set its key identifier.
 * @attributes: [in/out] The attribute object to write to.
 * @id: [in] The persistent identifier for the key.
 *
 * The application must choose a value for @id between `PSA_KEY_ID_USER_MIN`_ and
 * `PSA_KEY_ID_USER_MAX`.
 *
 * If the attribute object currently declares the key as volatile, which is the
 * default lifetime of an attribute object, this function sets the lifetime
 * attribute to PSA_KEY_LIFETIME_PERSISTENT.
 *
 * This function does not access storage, it merely stores the given value in
 * the attribute object.
 *
 * The persistent key will be written to storage when the attribute object is
 * passed to a key creation function such as psa_import_key(),
 * psa_generate_key(), psa_key_derivation_output_key(), psa_copy_key(), ...
 *
 * Return:
 * void
 */
static void psa_set_key_id(psa_key_attributes_t *attributes, psa_key_id_t id);

/**
 * psa_get_key_id() - Retrieve the key identifier from key attributes.
 * @attributes: [in] The key attribute object to query.
 *
 * Return:
 * The persistent identifier stored in the attribute object. This value is
 * unspecified if the attribute object declares the key as volatile.
 */
static psa_key_id_t psa_get_key_id(const psa_key_attributes_t *attributes);

/**
 * psa_set_key_lifetime() - Set the location of a persistent key.
 * @attributes: [in/out] The attribute object to write to.
 * @lifetime: [in] The lifetime for the key.
 *
 *
 * If this is PSA_KEY_LIFETIME_VOLATILE, the key will be volatile, and the key
 * identifier attribute is reset to PSA_KEY_ID_NULL.
 *
 * To make a key persistent, give it a persistent key identifier by
 * using psa_set_key_id(). By default, a key that has a persistent identifier
 * is stored in the default storage area identifier by
 * PSA_KEY_LIFETIME_PERSISTENT. Call this function to choose a storage area,
 * or to explicitly declare the key as volatile.
 *
 * This function does not access storage, it merely stores the given value in
 * the attribute object. The persistent key will be written to storage when the
 * attribute object is passed to a key creation function such as
 * psa_import_key(), psa_generate_key(), psa_key_derivation_output_key()
 * or psa_copy_key().
 *
 * Return:
 * void
 */
static void psa_set_key_lifetime(psa_key_attributes_t *attributes,
				 psa_key_lifetime_t lifetime);

/**
 * psa_get_key_lifetime() - Retrieve the lifetime from key attributes.
 * @attributes: [in] The key attribute object to query.
 *
 * Return:
 * The lifetime value stored in the attribute object.
 */
static psa_key_lifetime_t
psa_get_key_lifetime(const psa_key_attributes_t *attributes);

/**
 * psa_set_key_type() - Declare the type of a key.
 * @attributes: [in/out] The attribute object to write to.
 * @type: [in] The key type to write.
 *
 * This function overwrites any key type previously set in @attributes.
 *
 * If the @type is PSA_KEY_TYPE_NONE, the key type in @attributes becomes
 * unspecified.
 *
 * Return:
 * void
 */
static void psa_set_key_type(psa_key_attributes_t *attributes,
			     psa_key_type_t type);

/**
 * psa_get_key_type() - Retrieve the key type from key attributes.
 * @attributes: [in] The key attribute object to query.
 *
 * Return:
 * The key type stored in the attribute object.
 */
static psa_key_type_t psa_get_key_type(const psa_key_attributes_t *attributes);

/**
 * psa_set_key_algorithm() - Declare the permitted algorithm policy for a key.
 * @attributes: [in/out] The attribute object to write to.
 * @alg: [in] The permitted algorithm to write.
 *
 * The permitted algorithm policy of a key encodes which algorithm or algorithms
 * are permitted to be used with this key.
 *
 * This function overwrites any permitted algorithm policy previously set in
 * @attributes.
 */
static void psa_set_key_algorithm(psa_key_attributes_t *attributes,
				  psa_algorithm_t alg);

/**
 * psa_set_key_bits() - Declare the size of a key.
 * @attributes: [in/out] The attribute object to write to.
 * @bits: [in] The key size in bits. If this is 0, the key size in @attributes
 *             becomes unspecified. Keys of size 0 are not supported.
 *
 * This function overwrites any key size previously set in @attributes.
 */
static void psa_set_key_bits(psa_key_attributes_t *attributes, size_t bits);

/**
 * psa_set_key_usage_flags() - Declare usage flags for a key.
 * @attributes: [in/out] The attribute object to write to.
 * @usage_flags: [in] The usage flags to write.
 *
 * Usage flags are part of a key’s policy. They encode what kind of operations
 * are permitted on the key.
 *
 * This function overwrites any usage flags previously set in @attributes.
 *
 * Return:
 * void
 */
static void psa_set_key_usage_flags(psa_key_attributes_t *attributes,
				    psa_key_usage_t usage_flags);

/**
 * psa_get_key_usage_flags() - Retrieve the usage flags from key attributes.
 * @attributes: [in] The key attribute object to query.
 *
 * Return:
 * The usage flags stored in the attribute object.
 */
static psa_key_usage_t
psa_get_key_usage_flags(const psa_key_attributes_t *attributes);

/**
 * psa_get_key_algorithm() - Retrieve the permitted algorithm policy from key
 *                           attributes.
 * @attributes: [in] The key attribute object to query.
 *
 * Return:
 * The algorithm stored in the attribute object.
 */
static psa_algorithm_t
psa_get_key_algorithm(const psa_key_attributes_t *attributes);

/**
 * psa_get_key_bits() - Retrieve the key size from key attributes.
 * @attributes: [in] The key attribute object to query.
 *
 * Return:
 * The key size stored in the attribute object, in bits.
 */
static size_t psa_get_key_bits(const psa_key_attributes_t *attributes);

/**
 * psa_get_key_attributes() - Retrieve the attributes of a key.
 * @key: [in] Identifier of the key to query.
 * @attributes: [out] Attributes of the key.
 *
 * This function first resets the attribute object as with
 * psa_reset_key_attributes(). It then copies the key attributes retrieved
 * from the secure subsystem owning the key. If some key attributes are not
 * supported, the returned values are empty.
 *
 * On failure, it is equivalent to a freshly-initialized attribute object.
 *
 * .. note::
 *    This function clears any previous content from the attribute object and
 *    therefore expects it to be in a valid state. In particular, if this
 *    function is called on a newly allocated attribute object, the attribute
 *    object must be initialized before calling this function.
 *
 * .. note::
 *    This function might allocate memory or other resources. Once this
 *    function has been called on an attribute object,
 *    psa_reset_key_attributes() must be called to free these resources.
 *
 * Return:
 *  - PSA_SUCCESS
 *  - PSA_ERROR_INVALID_ARGUMENT:
 *      - @attributes is NULL.
 *      - @key is 0.
 *  - PSA_ERROR_INVALID_HANDLE
 *  - PSA_ERROR_INSUFFICIENT_MEMORY
 *  - PSA_ERROR_COMMUNICATION_FAILURE
 *  - PSA_ERROR_CORRUPTION_DETECTED
 *  - PSA_ERROR_STORAGE_FAILURE
 *  - PSA_ERROR_DATA_CORRUPT
 *  - PSA_ERROR_DATA_INVALID
 *  - PSA_ERROR_BAD_STATE:
 *      The library has not been previously initialized by psa_crypto_init().
 */
psa_status_t psa_get_key_attributes(psa_key_id_t key,
				    psa_key_attributes_t *attributes);

/**
 * psa_generate_key() - Generate a key or key pair.
 * @attributes: [in] The attributes for the new key.
 * @key: [out] On success, an identifier for the newly created key.
 *       PSA_KEY_ID_NULL on failure.
 *
 * The key is generated randomly. Its location, policy, type and size are taken
 * from @attributes.
 *
 * The following type-specific considerations apply:\
 *
 * - For RSA keys (PSA_KEY_TYPE_RSA_KEY_PAIR), the public exponent is 65537.
 *   The modulus is a product of two probabilistic primes between 2^{n-1} and
 *   2^n where n is the bit size specified in the attributes.
 *
 * The @attributes parameter must set the new key:\
 *
 *    - Permitted algorithm
 *    - Usage
 *    - Lifetime (if a persistent key is desired)
 *    - Key identifier (if a persistent key is desired)
 *    - Key type
 *    - Key size
 *
 * .. note::
 *     The attributes is an input parameter: it is not updated with the final
 *     key attributes. The final attributes of the new key can be queried by
 *     calling psa_get_key_attributes() with the key’s identifier.
 *
 * Return:
 *   - PSA_SUCCESS:
 *       Success. If the key is persistent, the key material and the key’s
 *       metadata have been saved to persistent storage.
 *   - PSA_ERROR_BAD_STATE:
 *       The library has not been previously initialized by psa_crypto_init().
 *   - PSA_ERROR_NOT_PERMITTED:
 *       Creating a key with the specified attributes is not permitted.
 *   - PSA_ERROR_ALREADY_EXISTS:
 *       This is an attempt to create a persistent key, and there is already a
 *       persistent key with the given identifier.
 *   - PSA_ERROR_INVALID_ARGUMENT:
 *       - The key type is invalid, or is an asymmetric public-key type.
 *       - The key size is not valid for the key type.
 *       - The key lifetime is invalid.
 *       - The key identifier is not valid for the key lifetime.
 *       - The key usage flags include invalid values.
 *       - The key’s permitted-usage algorithm is invalid.
 *       - The key attributes, as a whole, are invalid.
 *   - PSA_ERROR_NOT_SUPPORTED:
 *       The key attributes, as a whole are not supported.
 *   - PSA_ERROR_INSUFFICIENT_ENTROPY
 *   - PSA_ERROR_INSUFFICIENT_MEMORY
 *   - PSA_ERROR_INSUFFICIENT_STORAGE
 *   - PSA_ERROR_COMMUNICATION_FAILURE
 *   - PSA_ERROR_CORRUPTION_DETECTED
 *   - PSA_ERROR_STORAGE_FAILURE
 *   - PSA_ERROR_DATA_CORRUPT
 *   - PSA_ERROR_DATA_INVALID
*/
psa_status_t psa_generate_key(const psa_key_attributes_t *attributes,
			      psa_key_id_t *key);

/**
 * psa_generate_key_custom() - Generate a key or key pair using custom
 *                             production parameters.
 * @attributes: [in] The attributes for the new key.
 * @custom: [in] Customized production parameters for the key generation.
 * @custom_data: [in] A buffer containing additional variable-sized production
 *               parameters.
 * @custom_data_length: [in] Length of @custom_data in bytes.
 * @key: [out] On success, an identifier for the newly created key.
 *       PSA_KEY_ID_NULL on failure.
 *
 * .. warning::
 *     Not supported
 *
 * Use this function to provide explicit production parameters when generating
 * a key. See the description of psa_generate_key() for the operation of this
 * function with the default production parameters.
 *
 * The key is generated randomly. Its location, policy, type and size are taken
 * from @attributes.
 *
 * The @attributes parameter must set the new key:\
 *
 *    - Permitted algorithm
 *    - Usage
 *    - Lifetime (if a persistent key is desired)
 *    - Key identifier (if a persistent key is desired)
 *    - Key type
 *    - Key size
 *
 * .. note::
 *     The attributes is an input parameter: it is not updated with the final
 *     key attributes. The final attributes of the new key can be queried by
 *     calling psa_get_key_attributes() with the key’s identifier.
 *
 * If custom parameters are not used, this function is psa_generate_key()
 * equivalent.
 *
 * Return:
 *  - PSA_SUCCESS:
 *      Success. If the key is persistent, the key material and the key’s
 *      metadata have been saved to persistent storage.
 *  - PSA_ERROR_BAD_STATE:
 *      The library has not been previously initialized by psa_crypto_init().
 *  - PSA_ERROR_NOT_PERMITTED:
 *      Creating a key with the specified attributes is not permitted.
 *  - PSA_ERROR_ALREADY_EXISTS:
 *      This is an attempt to create a persistent key, and there is already a
 *      persistent key with the given identifier.
 *  - PSA_ERROR_INVALID_ARGUMENT:
 *      - The key type is invalid, or is an asymmetric public-key type.
 *      - The key size is not valid for the key type.
 *      - The key lifetime is invalid.
 *      - The key identifier is not valid for the key lifetime.
 *      - The key usage flags include invalid values.
 *      - The key’s permitted-usage algorithm is invalid.
 *      - The key attributes, as a whole, are invalid.
 *      - The production parameters are invalid.
 *  - PSA_ERROR_NOT_SUPPORTED:
 *      The key attributes, as a whole are not supported.
 *  - PSA_ERROR_INSUFFICIENT_ENTROPY
 *  - PSA_ERROR_INSUFFICIENT_MEMORY
 *  - PSA_ERROR_INSUFFICIENT_STORAGE
 *  - PSA_ERROR_COMMUNICATION_FAILURE
 *  - PSA_ERROR_CORRUPTION_DETECTED
 *  - PSA_ERROR_STORAGE_FAILURE
 *  - PSA_ERROR_DATA_CORRUPT
 *  - PSA_ERROR_DATA_INVALID
 */
psa_status_t psa_generate_key_custom(const psa_key_attributes_t *attributes,
				     const psa_custom_key_parameters_t *custom,
				     const uint8_t *custom_data,
				     size_t custom_data_length,
				     psa_key_id_t *key);

/**
 * psa_copy_key() - Make a copy of a key.
 * @source_key: [in] The key to copy. It must allow the usage PSA_KEY_USAGE_COPY.
 *              If a private or secret key is being copied outside of a secure
 *              element it must also allow PSA_KEY_USAGE_EXPORT.
 * @attributes: [in] The attributes for the new key.
 * @target_key: [out] On success, an identifier for the newly created key.
 *              PSA_KEY_ID_NULL on failure.
 *
 * .. warning::
 *     Not supported
 *
 *
 * Copy key material from one location to another. Its location is taken from
 * attributes, its policy is the intersection of the policy in @attributes and
 * the source key policy, and its type and size are taken from the source key.
 *
 * This function is primarily useful to copy a key from one location to another,
 * as it populates a key using the material from another key which can have a
 * different lifetime.
 *
 * The policy on the source key must have the usage flag PSA_KEY_USAGE_COPY set.
 * This flag is sufficient to permit the copy if the key has the lifetime
 * PSA_KEY_LIFETIME_VOLATILE or PSA_KEY_LIFETIME_PERSISTENT. Some secure
 * elements do not provide a way to copy a key without making it extractable
 * from the secure element. If a key is located in such a secure element, then
 * the key must have both usage flags PSA_KEY_USAGE_COPY and
 * PSA_KEY_USAGE_EXPORT in order to make a copy of the key outside the secure
 * element.
 *
 * The resulting key can only be used in a way that conforms to both the policy
 * of the original key and the policy specified in the attributes parameter:\
 *
 *   - The usage flags on the resulting key are the bitwise-and of the usage
 *     flags on the source policy and the usage flags in attributes.
 *   - If both permit the same algorithm or wildcard-based algorithm, the
 *     resulting key has the same permitted algorithm.
 *   - If either of the policies permits an algorithm and the other policy
 *     permits a wildcard-based permitted algorithm that includes this
 *     algorithm, the resulting key uses this permitted algorithm.
 *   - If the policies do not permit any algorithm in common, this function
 *     fails with the status PSA_ERROR_INVALID_ARGUMENT.
 *
 * As a result, the new key cannot be used for operations that were not
 * permitted on the source key.
 *
 * The @attributes parameter must set the new key:\
 *
 *    - Permitted algorithm
 *    - Usage: Flags are combined with the source key usage flags.
 *    - Lifetime (if a persistent key is desired)
 *    - Key identifier (if a persistent key is desired)
 *    - key type and key size: (optional) These are taken from the source key,
 *      if set they must be identical as the source key.
 *
 * .. note::
 *     The attributes is an input parameter: it is not updated with the final
 *     key attributes. The final attributes of the new key can be queried by
 *     calling psa_get_key_attributes() with the key’s identifier.
 *
 * Return:
 *  - PSA_SUCCESS:
 *      Success. If the new key is persistent, the key material and the key’s
 *      metadata have been saved to persistent storage.
 *  - PSA_ERROR_BAD_STATE:
 *     The library has not been previously initialized by psa_crypto_init().
 *  - PSA_ERROR_INVALID_HANDLE:
 *      @source_key is invalid.
 *  - PSA_ERROR_NOT_PERMITTED:
 *      - @source_key does not have the PSA_KEY_USAGE_COPY usage flag.
 *      - @source_key does not have the PSA_KEY_USAGE_EXPORT usage flag, and
 *        the location of @target_key is outside the security boundary of the
 *        @source_key storage location.
 *      - Creating a key with the specified attributes is not permitted.
 *  - PSA_ERROR_ALREADY_EXISTS:
 *      This is an attempt to create a persistent key, and there is already a
 *      persistent key with the given identifier.
 *  - PSA_ERROR_INVALID_ARGUMENT:
 *      - @attributes specifies a key type or key size which does not match the
 *        attributes of source key.
 *      - The lifetime or identifier in @attributes are invalid.
 *      - The key policies from @source_key and those specified in attributes
 *        are incompatible.
 *  - PSA_ERROR_NOT_SUPPORTED:
 *      - The @source_key storage location does not support copying to the
 *        target key’s storage location.
 *      - The key attributes, as a whole, are not supported in the target key’s
 *        storage location.
 *  - PSA_ERROR_INSUFFICIENT_MEMORY
 *  - PSA_ERROR_INSUFFICIENT_STORAGE
 *  - PSA_ERROR_COMMUNICATION_FAILURE
 *  - PSA_ERROR_CORRUPTION_DETECTED
 *  - PSA_ERROR_STORAGE_FAILURE
 *  - PSA_ERROR_DATA_CORRUPT
 *  - PSA_ERROR_DATA_INVALID
*/
psa_status_t psa_copy_key(psa_key_id_t source_key,
			  const psa_key_attributes_t *attributes,
			  psa_key_id_t *target_key);

/**
 * psa_import_key() - Import a key in binary format.
 * @attributes: [in] The attributes for the new key.
 * @data: [in] Buffer containing the key data. The content of this buffer is
 *             interpreted according to the type declared in attributes.
 * @data_length: [in] Size of the @data buffer in bytes.
 * @key: [out] On success, an identifier for the newly created key.
 *             PSA_KEY_ID_NULL on failure.
 *
 * .. warning::
 *    Import of private plaintext key may be not supported depending on the
 *    secure subsystem in use, in this case the key must be wrapped.
 *
 * The key data determines the key size. The attributes can optionally specify
 * a key size; in this case it must match the size determined from the key data.
 * A key size of 0 in attributes indicates that the key size is solely
 * determined by the key data.
 *
 * .. note:
 *    The PSA Crypto API does not support asymmetric private key objects
 *    outside of a key pair. To import a private key, the attributes must
 *    specify the corresponding key pair type. Depending on the key type,
 *    either the import format contains the public key data or the
 *    public key is reconstructed from the private key as needed.
 *
 * The following new key @attributes are required:\
 *
 *   - The key type determines how the data buffer is interpreted.
 *   - The key permitted algorithm.
 *   - The key usage flags.
 *
 * The following new key @attributes must be set in case of a persistent key:\
 *
 *   - The key lifetime.
 *   - The key identifier.
 *
 * The following new key @attributes are optional:\
 *
 *   - The key size, if not zero, must match the size of the key data.
 *
 * Return:
 *  - PSA_SUCCESS:
 *      Success. If the key is persistent, the key material and the key’s
 *      metadata have been saved to persistent storage.
 *  - PSA_ERROR_ALREADY_EXISTS:
 *      This is an attempt to create a persistent key, and there is already a
 *      persistent key with the given identifier.
 *  - PSA_ERROR_NOT_PERMITTED:
 *      Creating a key with the specified attributes is not permitted.
 *  - PSA_ERROR_NOT_SUPPORTED:
 *      The key type or key size is not supported.
 *  - PSA_ERROR_INVALID_ARGUMENT:
 *      - The key type is invalid.
 *      - The key size is nonzero, and is incompatible with the key data in data.
 *      - The key lifetime is invalid.
 *      - The key identifier is not valid for the key lifetime.
 *      - The key usage flags include invalid values.
 *      - The key’s permitted-usage algorithm is invalid.
 *      - The key attributes, as a whole, are invalid.
 *      - The key data is not correctly formatted for the key type.
 *  - PSA_ERROR_INSUFFICIENT_MEMORY
 *  - PSA_ERROR_INSUFFICIENT_STORAGE
 *  - PSA_ERROR_COMMUNICATION_FAILURE
 *  - PSA_ERROR_STORAGE_FAILURE
 *  - PSA_ERROR_DATA_CORRUPT
 *  - PSA_ERROR_DATA_INVALID
 *  - PSA_ERROR_HARDWARE_FAILURE
 *  - PSA_ERROR_CORRUPTION_DETECTED
 *  - PSA_ERROR_BAD_STATE:
 *      The library has not been previously initialized by psa_crypto_init().
 */
psa_status_t psa_import_key(const psa_key_attributes_t *attributes,
			    const uint8_t *data, size_t data_length,
			    psa_key_id_t *key);

/**
 * psa_destroy_key() - Destroy a key.
 * @key: [in] Identifier of the key to erase. If this is PSA_KEY_ID_NULL, do
 *            nothing and return PSA_SUCCESS.
 *
 * This function destroys a key from both volatile memory and, if applicable,
 * non-volatile storage.
 *
 * Destroying the key makes the key identifier invalid, and the key identifier
 * must not be used again by the application.
 *
 * If a key is currently in use in a multi-part operation, then destroying the
 * key will cause the multi-part operation to fail.
 *
 * Return:
 *  - PSA_SUCCESS:
 *      @key was a valid key identifier and the key material that it referred
 *      to has been erased. Alternatively, key is PSA_KEY_ID_NULL.
 *  - PSA_ERROR_NOT_PERMITTED:
 *      The key cannot be erased because it is read-only, either due to a
 *      policy or due to physical restrictions.
 *  - PSA_ERROR_INVALID_HANDLE:
 *      @key is not a valid handle nor PSA_KEY_ID_NULL.
 *  - PSA_ERROR_COMMUNICATION_FAILURE:
 *      There was an failure in communication with the cryptoprocessor.
 *      The key material might still be present in the cryptoprocessor.
 *  - PSA_ERROR_STORAGE_FAILURE:
 *      The storage operation failed.
 *  - PSA_ERROR_DATA_CORRUPT:
 *      The storage is corrupted.
 *  - PSA_ERROR_DATA_INVALID
 *  - PSA_ERROR_CORRUPTION_DETECTED:
 *      An unexpected condition which is not a storage corruption or a
 *      communication failure occurred. The cryptoprocessor might have been
 *      compromised.
 *  - PSA_ERROR_BAD_STATE:
 *      The library has not been previously initialized by psa_crypto_init().
 */
psa_status_t psa_destroy_key(psa_key_id_t key);

/**
 * psa_purge_key() - Remove non-essential copies of key material from memory.
 * @key: [in] Identifier of the key to purge.
 *
 * .. warning::
 *     Not supported.
 *
 * For keys that have been created with the PSA_KEY_USAGE_CACHE usage flag,
 * an implementation is permitted to make additional copies of the key material
 * that are not in storage and not for the purpose of ongoing operations.
 *
 * This function will remove these extra copies of the key material from memory.
 *
 * This function is not required to remove key material from memory in any of
 * the following situations\:
 *
 *  - The key is currently in use in a cryptographic operation.
 *  - The key is volatile.
 *
 * Return:
 *  - PSA_SUCCESS:
 *      The key material will have been removed from memory if it is not
 *      currently required.
 *  - PSA_ERROR_INVALID_HANDLE
 *  - PSA_ERROR_COMMUNICATION_FAILURE
 *  - PSA_ERROR_STORAGE_FAILURE
 *  - PSA_ERROR_DATA_CORRUPT
 *  - PSA_ERROR_DATA_INVALID
 *  - PSA_ERROR_CORRUPTION_DETECTED
 *  - PSA_ERROR_BAD_STATE:
 *      The library has not been previously initialized by psa_crypto_init().
 */
psa_status_t psa_purge_key(psa_key_id_t key);

/**
 * psa_export_key() - Export a key in binary format.
 * @key: [in] Identifier of the key to export. It must allow the usage
 *            PSA_KEY_USAGE_EXPORT, unless it is a public key.
 * @data: [out] Buffer where the key data is to be written.
 * @data_size: [in] Size of the @data buffer in bytes.
 * @data_length: [out] On success, the number of bytes that make up the key data.
 *
 * .. warning::
 *    Private or secure key are not exportable in plain text, only asymmetric
 *    public key can be exported.
 *
 * In the current implementation only the asymmetric public keys is exported
 * in a standard binary format.
 *
 * Parameter @data_size must be appropriate for the key\:
 *
 *  - The required output size is PSA_EXPORT_KEY_OUTPUT_SIZE() where
 *    type is the key type and bits is the key size in bits.
 *  - :c:macro:`PSA_EXPORT_ASYMMETRIC_KEY_MAX_SIZE` evaluates to the maximum
 *    output size of any supported public key or key pair.
 *  - :c:macro:`PSA_EXPORT_KEY_PAIR_MAX_SIZE` evaluates to the maximum output
 *    size of any supported key pair.
 *  - :c:macro:`PSA_EXPORT_PUBLIC_KEY_MAX_SIZE` evaluates to the maximum output
 *    size of any supported public key.
 *  - This API defines no maximum size for symmetric keys. Arbitrarily large
 *    data items can be stored in the key store, for example certificates that
 *    correspond to a stored private key or input material for key derivation.
 *
 * Return:
 *  - PSA_SUCCESS:
 *      Success. The first @data_length bytes of data contain the exported key.
 *  - PSA_ERROR_INVALID_HANDLE:
 *      The @key handle is invalid.
 *  - PSA_ERROR_NOT_PERMITTED:
 *      The key does not have the PSA_KEY_USAGE_EXPORT flag.
 *  - PSA_ERROR_NOT_SUPPORTED:
 *      - The key’s storage location does not support export of the key.
 *      - This type of key can't be exported.
 *  - PSA_ERROR_BUFFER_TOO_SMALL:
 *      The size of the @data buffer is too small.
 *  - PSA_ERROR_STORAGE_FAILURE
 *  - PSA_ERROR_DATA_CORRUPT
 *  - PSA_ERROR_DATA_INVALID
 *  - PSA_ERROR_INSUFFICIENT_MEMORY
 *  - PSA_ERROR_BAD_STATE:
 *      The library has not been previously initialized by psa_crypto_init().
 */
psa_status_t psa_export_key(psa_key_id_t key, uint8_t *data, size_t data_size,
			    size_t *data_length);

/**
 * psa_export_public_key() - Export a public key or the public part of a key
 *                           pair in binary format.
 * @key: [in] Identifier of the key to export.
 * @data: [out] Buffer where the key data is to be written.
 * @data_size: [in] Size of the @data buffer in bytes.
 * @data_length: [out] On success, the number of bytes that make up the key data.
 *
 * Exporting a public key object or the public part of a key pair is always
 * permitted, regardless of the key’s usage flags.
 *
 * Parameter @data_size must be appropriate for the key\:
 *
 *  - The required output size is PSA_EXPORT_PUBLIC_KEY_OUTPUT_SIZE()
 *    where type is the key type and bits is the key size in bits.
 *  - :c:macro:`PSA_EXPORT_PUBLIC_KEY_MAX_SIZE` evaluates to the maximum output
 *    size of any supported public key or public part of a key pair.
 *  - :c:macro:`PSA_EXPORT_ASYMMETRIC_KEY_MAX_SIZE` evaluates to the maximum
 *    output size of any supported public key or key pair
 *
 * Return:
 *  - PSA_SUCCESS
 *  - PSA_ERROR_INVALID_HANDLE
 *  - PSA_ERROR_INVALID_ARGUMENT:
 *      The key is neither a public key nor a key pair.
 *  - PSA_ERROR_NOT_SUPPORTED:
 *      - The key’s storage location does not support export of the key.
 *      - This type of key can't be exported.
 *  - PSA_ERROR_BUFFER_TOO_SMALL:
 *      The size of the @data buffer is too small.
 *  - PSA_ERROR_COMMUNICATION_FAILURE
 *  - PSA_ERROR_HARDWARE_FAILURE
 *  - PSA_ERROR_CORRUPTION_DETECTED
 *  - PSA_ERROR_STORAGE_FAILURE
 *  - PSA_ERROR_DATA_CORRUPT
 *  - PSA_ERROR_DATA_INVALID
 *  - PSA_ERROR_INSUFFICIENT_MEMORY
 *  - PSA_ERROR_BAD_STATE:
 *      The library has not been previously initialized by psa_crypto_init().
 */
psa_status_t psa_export_public_key(psa_key_id_t key, uint8_t *data,
				   size_t data_size, size_t *data_length);

/**
 * psa_key_derivation_operation_init() - Return an initial value for a key
 *                                       derivation operation object.
 *
 * Return:
 * Initialized value of a key derivation operation object.
 */
static psa_key_derivation_operation_t psa_key_derivation_operation_init(void);

/**
 * psa_key_derivation_setup() - Set up a key derivation operation.
 * @operation: [in] The key derivation operation object to set up. It must have
 *                  been initialized but not set up yet.
 * @alg: [in] The algorithm to compute.
 *
 * A key derivation algorithm takes some inputs and uses them to generate a byte
 * stream in a deterministic way. This byte stream can be used to produce keys
 * and other cryptographic material.
 *
 * The @alg must be an algorithm where\:
 *
 *   - PSA_ALG_IS_KEY_DERIVATION() is true, for a key derivation algorithm.
 *   - PSA_ALG_IS_KEY_AGREEMENT() is true and PSA_ALG_IS_RAW_KEY_AGREEMENT() is
 *     false, for a key agreement and key derivation combined algorithm.
 *
 * A key-agreement and key-derivation algorithm uses a key-agreement protocol
 * to provide a shared secret which is used for the key derivation. See
 * psa_key_derivation_key_agreement().
 *
 * After a successful call to psa_key_derivation_setup(), the operation is
 * active, and the application must eventually terminate the operation with a
 * call to psa_key_derivation_abort().
 *
 * If psa_key_derivation_setup() returns an error, the operation object is
 * unchanged. If a subsequent function call with an active operation returns
 * an error, the operation enters an error state.
 *
 * To abandon an active operation, or reset an operation in an error state,
 * call psa_key_derivation_abort().
 *
 * Return:
 *  -  PSA_SUCCESS:
 *       Success.
 *  -  PSA_ERROR_INVALID_ARGUMENT:
 *       @alg is neither a key-derivation algorithm, nor a key-agreement and
 *       key-derivation algorithm.
 *  -  PSA_ERROR_NOT_SUPPORTED:
 *       @alg is not supported.
 *  -  PSA_ERROR_INSUFFICIENT_MEMORY
 *  -  PSA_ERROR_COMMUNICATION_FAILURE
 *  -  PSA_ERROR_HARDWARE_FAILURE
 *  -  PSA_ERROR_CORRUPTION_DETECTED
 *  -  PSA_ERROR_STORAGE_FAILURE
 *  -  PSA_ERROR_DATA_CORRUPT
 *  -  PSA_ERROR_DATA_INVALID
 *  -  PSA_ERROR_BAD_STATE:
 *       - The operation state is not valid: it must be inactive.
 *       - The library has not been previously initialized by psa_crypto_init().
 */
psa_status_t psa_key_derivation_setup(psa_key_derivation_operation_t *operation,
				      psa_algorithm_t alg);

/**
 * psa_key_derivation_get_capacity() - Retrieve the current capacity of a key
 *                                     derivation operation.
 * @operation: [in] The operation to query.
 * @capacity: [out] On success, the capacity of the operation.
 *
 * .. warning::
 *     Not supported.
 *
 * The capacity of a key derivation is the maximum number of bytes that it can
 * return. Reading **N** bytes of output from a key derivation operation reduces
 * its capacity by at least **N**. The capacity can be reduced by more than
 * **N** in the following situations\:
 *
 *  - Calling psa_key_derivation_output_key() or psa_key_derivation_key_custom()
 *    can reduce the capacity by more than the key size, depending on the type
 *    of key being generated. See psa_key_derivation_output_key() for details
 *    of the key derivation process.
 *  - When the &typedef psa_key_derivation_operation_t object is operating as
 *    a deterministic random bit generator (DBRG), which reduces capacity in
 *    whole blocks, even when less than a block is read.
 *
 * Return:
 *  -  PSA_SUCCESS
 *  -  PSA_ERROR_COMMUNICATION_FAILURE
 *  -  PSA_ERROR_HARDWARE_FAILURE
 *  -  PSA_ERROR_CORRUPTION_DETECTED
 *  -  PSA_ERROR_BAD_STATE:
 *       - The operation state is not valid: it must be active.
 *       - The library has not been previously initialized by psa_crypto_init().
 */
psa_status_t
psa_key_derivation_get_capacity(const psa_key_derivation_operation_t *operation,
				size_t *capacity);

/**
 * psa_key_derivation_set_capacity() - Set the maximum capacity of a key
 *                                     derivation operation.
 * @operation: [in] The key derivation operation object to modify.
 * @capacity: [in] The new capacity of the operation. It must be less or equal
 *                 to the operation’s current capacity.
 *
 * .. warning::
 *     Not supported.
 *
 * The capacity of a key derivation operation is the maximum number of bytes
 * that the key derivation operation can return from this point onwards.
 *
 * Return:
 *  - PSA_SUCCESS
 *  - PSA_ERROR_INVALID_ARGUMENT:
 *      @capacity is larger than the operation’s current capacity. In this
 *      case, the operation object remains valid and its capacity remains
 *      unchanged.
 *  - PSA_ERROR_COMMUNICATION_FAILURE
 *  - PSA_ERROR_HARDWARE_FAILURE
 *  - PSA_ERROR_CORRUPTION_DETECTED
 *  - PSA_ERROR_BAD_STATE:
 *      - The operation state is not valid: it must be active.
 *      - The library has not been previously initialized by psa_crypto_init().
 */
psa_status_t
psa_key_derivation_set_capacity(psa_key_derivation_operation_t *operation,
				size_t capacity);

/**
 * psa_key_derivation_input_bytes() - Provide an input for key derivation or
 *                                    key agreement.
 * @operation: [in] The key derivation operation object to use. It must have
 *                  been set up with psa_key_derivation_setup() and must not
 *                  have produced any output yet.
 * @step: [in] Which step the input data is for.
 * @data: [in] Input data to use.
 * @data_length: [in] Size of the @data buffer in bytes.
 *
 * Which inputs are required and in what order depends on the algorithm.
 * Refer to the documentation of each key derivation or key agreement algorithm
 * for information.
 *
 * This function passes direct inputs, which is usually correct for non-secret
 * inputs. To pass a secret input, which is normally in a key object, call
 * psa_key_derivation_input_key() instead of this function. Refer to the
 * documentation of individual step types (PSA_KEY_DERIVATION_INPUT_xxx
 * values of &typedef psa_key_derivation_step_t) for more information.
 *
 * If this function returns an error status, the operation enters an error
 * state and must be aborted by calling psa_key_derivation_abort().
 *
 * Return:
 *  - PSA_SUCCESS:
 *      Success.
 *  - PSA_ERROR_INVALID_ARGUMENT:
 *      - @step is not compatible with the operation’s algorithm.
 *      - @step does not permit direct inputs.
 *      - @data_length is too small or too large for step in this particular
 *        algorithm.
 *  - PSA_ERROR_NOT_SUPPORTED:
 *      - @step is not supported with the operation’s algorithm.
 *      - @data_length is is not supported for step in this particular algorithm.
 *  - PSA_ERROR_INSUFFICIENT_MEMORY
 *  - PSA_ERROR_COMMUNICATION_FAILURE
 *  - PSA_ERROR_CORRUPTION_DETECTED
 *  - PSA_ERROR_STORAGE_FAILURE
 *  - PSA_ERROR_DATA_CORRUPT
 *  - PSA_ERROR_DATA_INVALID
 *  - PSA_ERROR_BAD_STATE:
 *      - The operation state is not valid for this input step. This can happen
 *        if the application provides a step out of order or repeats a step that
 *        may not be repeated.
 *      - The library has not been previously initialized by psa_crypto_init().
 */
psa_status_t
psa_key_derivation_input_bytes(psa_key_derivation_operation_t *operation,
			       psa_key_derivation_step_t step,
			       const uint8_t *data, size_t data_length);

/**
 * psa_key_derivation_input_integer() - Provide a numeric input for key
 *                                      derivation or key agreement.
 * @operation: [in] The key derivation operation object to use. It must have
 *                  been set up with psa_key_derivation_setup() and must not
 *                  have produced any output yet.
 * @step: [in] Which step the input data is for.
 * @value: [in] The value of the numeric input.
 *
 * .. warning::
 *     Not supported.
 *
 * Which inputs are required and in what order depends on the algorithm.
 * However, when an algorithm requires a particular order, numeric inputs
 * usually come first as they tend to be configuration parameters.
 * Refer to the documentation of each key derivation or key agreement algorithm
 * for information.
 *
 * This function is used for inputs which are fixed-size non-negative integers.
 *
 * If this function returns an error status, the operation enters an error state
 * and must be aborted by calling psa_key_derivation_abort().
 *
 * Return:
 *  - PSA_SUCCESS:
 *      Success.
 *  - PSA_ERROR_BAD_STATE:
 *      - The operation state is not valid for this input @step. This can
 *        happen if the application provides a step out of order or repeats a
 *        step that may not be repeated.
 *      - The library has not been previously initialized by psa_crypto_init().
 *  - PSA_ERROR_INVALID_ARGUMENT:
 *      - @step is not compatible with the operation’s algorithm.
 *      - @step does not allow numerical inputs.
 *      - @value is not valid for @step in the operation’s algorithm.
 *  - PSA_ERROR_NOT_SUPPORTED:
 *      - @step is not supported with the operation’s algorithm.
 *      - @value is not supported for @step in the operation’s algorithm.
 *  - PSA_ERROR_INSUFFICIENT_MEMORY
 *  - PSA_ERROR_COMMUNICATION_FAILURE
 *  - PSA_ERROR_CORRUPTION_DETECTED
 *  - PSA_ERROR_STORAGE_FAILURE
 *  - PSA_ERROR_DATA_CORRUPT
 *  - PSA_ERROR_DATA_INVALID
 */
psa_status_t
psa_key_derivation_input_integer(psa_key_derivation_operation_t *operation,
				 psa_key_derivation_step_t step,
				 uint64_t value);

/**
 * psa_key_derivation_input_key() - Provide an input for key derivation in the
 *                                  form of a key.
 * @operation: [in] The key derivation operation object to use. It must have
 *                  been set up with psa_key_derivation_setup() and must not
 *                  have produced any output yet.
 * @step: [in] Which step the input data is for.
 * @key: [in] Identifier of the key. It must have an appropriate type for step
 *            and must allow the usage PSA_KEY_USAGE_DERIVE or
 *            PSA_KEY_USAGE_VERIFY_DERIVATION.
 *
 * Which inputs are required and in what order depends on the algorithm. Refer
 * to the documentation of each key derivation or key agreement algorithm for
 * information.
 *
 * This function obtains input from a key object, which is usually correct for
 * secret inputs or for non-secret personalization strings kept in the key
 * store. To pass a non-secret parameter which is not in the key store, call
 * psa_key_derivation_input_bytes() instead of this function. Refer to
 * the documentation of individual step types (PSA_KEY_DERIVATION_INPUT_xxx
 * values of &typedef psa_key_derivation_step_t) for more information.
 *
 * If this function returns an error status, the operation enters an error state
 * and must be aborted by calling psa_key_derivation_abort().
 *
 * Return:
 *  - PSA_SUCCESS:
 *      Success.
 *  - PSA_ERROR_INVALID_HANDLE:
 *      @key is not a valid key identifier.
 *  - PSA_ERROR_NOT_PERMITTED:
 *      - The key has neither the PSA_KEY_USAGE_DERIVE nor the
 *        PSA_KEY_USAGE_VERIFY_DERIVATION usage flag.
 *      - The key does not permit the operation’s algorithm.
 *  - PSA_ERROR_INVALID_ARGUMENT:
 *      - @step is not compatible with the operation’s algorithm.
 *      - @step does not allow key inputs of the given type or does not allow
 *        key inputs at all.
 *  - PSA_ERROR_NOT_SUPPORTED:
 *      - @step is not supported with the operation’s algorithm.
 *      - Key inputs of the given type are not supported for @step in the
 *        operation’s algorithm.
 *  - PSA_ERROR_INSUFFICIENT_MEMORY
 *  - PSA_ERROR_COMMUNICATION_FAILURE
 *  - PSA_ERROR_HARDWARE_FAILURE
 *  - PSA_ERROR_CORRUPTION_DETECTED
 *  - PSA_ERROR_STORAGE_FAILURE
 *  - PSA_ERROR_DATA_CORRUPT
 *  - PSA_ERROR_DATA_INVALID
 *  - PSA_ERROR_BAD_STATE:
 *      - The operation state is not valid for this input step. This can happen
 *        if the application provides a step out of order or repeats a step that
 *        may not be repeated.
 *      - The library has not been previously initialized by psa_crypto_init().
 */
psa_status_t
psa_key_derivation_input_key(psa_key_derivation_operation_t *operation,
			     psa_key_derivation_step_t step, psa_key_id_t key);

/**
 * psa_key_derivation_output_bytes() - Read some data from a key derivation
 *                                     operation.
 * @operation: [in] The key derivation operation object to read from.
 * @output: [out] Buffer where the output will be written.
 * @output_length: [in] Number of bytes to @output.
 *
 * This function calculates output bytes from a key derivation algorithm and
 * returns those bytes. If the key derivation’s output is viewed as a stream
 * of bytes, this function consumes the requested number of bytes from the
 * stream and returns them to the caller. The operation’s capacity decreases
 * by the number of bytes read.
 *
 * If this function returns an error status other than
 * PSA_ERROR_INSUFFICIENT_DATA, the operation enters an error state and must be
 * aborted by calling psa_key_derivation_abort().
 *
 * Return:
 *  - PSA_SUCCESS:
 *      Success.
 *  - PSA_ERROR_NOT_PERMITTED:
 *      One of the inputs was a key whose policy did not permit
 *      PSA_KEY_USAGE_DERIVE.
 *  - PSA_ERROR_INSUFFICIENT_DATA:
 *      The operation’s capacity was less than @output_length bytes. In this
 *      case:\
 *
 *         - No output is written to the @output buffer.
 *         - The operation’s capacity is set to 0.
 *  - PSA_ERROR_INSUFFICIENT_MEMORY
 *  - PSA_ERROR_COMMUNICATION_FAILURE
 *  - PSA_ERROR_CORRUPTION_DETECTED
 *  - PSA_ERROR_STORAGE_FAILURE
 *  - PSA_ERROR_DATA_CORRUPT
 *  - PSA_ERROR_DATA_INVALID
 *  - PSA_ERROR_BAD_STATE:
 *      - The operation state is not valid: it must be active and completed all
 *        required input steps.
 *      - The library has not been previously initialized by psa_crypto_init().
 */
psa_status_t
psa_key_derivation_output_bytes(psa_key_derivation_operation_t *operation,
				uint8_t *output, size_t output_length);

/**
 * psa_key_derivation_output_key() - Derive a key from an ongoing key derivation
 *                                   operation.
 * @attributes: [in] The attributes for the new key.
 * @operation: [in] The key derivation operation object to read from.
 * @key: [out] On success, an identifier for the newly created key.
 *             PSA_KEY_ID_NULL on failure.
 *
 * This function calculates output bytes from a key derivation algorithm and
 * uses those bytes to generate a key deterministically. The key’s location,
 * policy, type and size are taken from @attributes.
 *
 * The following new key @attributes are required\:
 *
 *  - The key type. It cannot be an asymmetric public key.
 *  - The key size. It must be a valid size for the key type.
 *  - The key permitted algorithm policy. If the key type to be created is
 *    PSA_KEY_TYPE_PASSWORD_HASH, then the permitted algorithm policy must be
 *    either the same as the current operation’s algorithm, or PSA_ALG_NONE.
 *  - The key usage flags.
 *
 * The following new key attributes must be set in case of a persistent key\:
 *
 *  - The key lifetime.
 *  - The key identifier.
 *
 * If the key derivation’s output is viewed as a stream of bytes, this function
 * consumes the required number of bytes from the stream. The operation’s
 * capacity decreases by the number of bytes used to derive the key.
 *
 * If this function returns an error status other than
 * PSA_ERROR_INSUFFICIENT_DATA, the operation enters an error state and must be
 * aborted by calling psa_key_derivation_abort().
 *
 * How much output is produced and consumed from the operation, and how the key
 * is derived, depends on the key type.
 *
 * For algorithms that take a PSA_KEY_DERIVATION_INPUT_SECRET or
 * PSA_KEY_DERIVATION_INPUT_PASSWORD input step, the input to that step must be
 * provided with psa_key_derivation_input_key().
 *
 * .. note::
 *    This function is equivalent to calling
 *    psa_key_derivation_output_key_custom() with the production parameters
 *    PSA_CUSTOM_KEY_PARAMETERS_INIT and *custom_data_length == 0*
 *    (custom_data is ignored).
 *
 * Return:
 *  - PSA_SUCCESS:
 *      Success. If the key is persistent, the key material and the key’s
 *      metadata have been saved to persistent storage.
 *  - PSA_ERROR_ALREADY_EXISTS:
 *      This is an attempt to create a persistent key, and there is already a
 *      persistent key with the given identifier.
 *  - PSA_ERROR_INSUFFICIENT_DATA:
 *      The operation’s capacity was less than @output_length bytes. In this
 *      case:\
 *
 *         - No output is written to the @output buffer.
 *         - The operation’s capacity is set to 0.
 *  - PSA_ERROR_NOT_SUPPORTED:
 *      The key attributes, as a whole, are not supported.
 *  - PSA_ERROR_INVALID_ARGUMENT:
 *      - The key type is invalid, or is an asymmetric public-key type.
 *      - The key type is PSA_KEY_TYPE_PASSWORD_HASH, and the permitted
 *        algorithm policy is not the same as the current operation’s algorithm.
 *      - The key size is not valid for the key type.
 *      - The key lifetime is invalid.
 *      - The key identifier is not valid for the key lifetime.
 *      - The key usage flags include invalid values.
 *      - The key’s permitted-usage algorithm is invalid.
 *      - The key attributes, as a whole, are invalid.
 *  - PSA_ERROR_NOT_PERMITTED:
 *      - A PSA_KEY_DERIVATION_INPUT_SECRET or
 *        PSA_KEY_DERIVATION_INPUT_PASSWORD input was neither provided through
 *        a key nor the result of a key agreement.
 *      - One of the inputs was a key whose policy did not permit
 *        PSA_KEY_USAGE_DERIVE.
 *      - Creating a key with the specified attributes is not permitted.
 *  - PSA_ERROR_INSUFFICIENT_MEMORY
 *  - PSA_ERROR_INSUFFICIENT_STORAGE
 *  - PSA_ERROR_COMMUNICATION_FAILURE
 *  - PSA_ERROR_CORRUPTION_DETECTED
 *  - PSA_ERROR_STORAGE_FAILURE
 *  - PSA_ERROR_DATA_CORRUPT
 *  - PSA_ERROR_DATA_INVALID
 *  - PSA_ERROR_BAD_STATE:
 *      - The operation state is not valid: it must be active and completed all
 *        required input steps.
 *      - The library has not been previously initialized by psa_crypto_init().
 */
psa_status_t
psa_key_derivation_output_key(const psa_key_attributes_t *attributes,
			      psa_key_derivation_operation_t *operation,
			      psa_key_id_t *key);

/**
 * psa_key_derivation_output_key_custom() - Derive a key from an ongoing
 *                                          key derivation operation with
 *                                          custom production parameters.
 * @attributes: [in] The attributes for the new key.
 * @operation: [in] The key derivation operation object to read from.
 * @custom: [in] Customized production parameters for the key derivation.
 * @custom_data: [in] A buffer containing additional variable-sized production
 *                    parameters.
 * @custom_data_length: [in] Length of @custom_data in bytes.
 * @key: [out] On success, an identifier for the newly created key.
 *             PSA_KEY_ID_NULL on failure.
 *
 * .. warning::
 *     Not supported
 *
 * This function calculates output bytes from a key derivation algorithm and
 * uses those bytes to generate a key deterministically. The key’s location,
 * policy, type and size are taken from @attributes.
 *
 * The following new key @attributes are required\:
 *
 *  - The key type. It cannot be an asymmetric public key.
 *  - The key size. It must be a valid size for the key type.
 *  - The key permitted algorithm policy. If the key type to be created is
 *    PSA_KEY_TYPE_PASSWORD_HASH, then the permitted algorithm policy must be
 *    either the same as the current operation’s algorithm, or PSA_ALG_NONE.
 *  - The key usage flags.
 *
 * The following new key attributes must be set in case of a persistent key\:
 *
 *  - The key lifetime.
 *  - The key identifier.
 *
 * This function operates in a similar way to psa_key_derivation_output_key(),
 * but enables explicit production parameters to be provided when deriving a key.
 * For example, the production parameters can be used to select an alternative
 * key derivation process, or configure additional key parameters.
 * See psa_key_derivation_output_key() for the operation of this function with
 * the default production parameters.
 *
 * See &typedef psa_custom_key_parameters_t for a list of non-default production
 * parameters. See the key type definitions in Key types for details of the
 * custom production parameters used for key derivation.
 *
 * .. note::
 *    When the custom parameter is PSA_CUSTOM_KEY_PARAMETERS_INIT with
 *    *custom_data_length == 0*, this function is equivalent to the
 *    psa_key_derivation_output_key() (custom_data is ignored).
 *
 * Return:
 *  - PSA_SUCCESS:
 *      Success. If the key is persistent, the key material and the key’s
 *      metadata have been saved to persistent storage.
 *  - PSA_ERROR_ALREADY_EXISTS:
 *      This is an attempt to create a persistent key, and there is already a
 *      persistent key with the given identifier.
 *  - PSA_ERROR_INSUFFICIENT_DATA:
 *      The operation’s capacity was less than @output_length bytes. In this
 *      case:\
 *
 *         - No output is written to the @output buffer.
 *         - The operation’s capacity is set to 0.
 *  - PSA_ERROR_NOT_SUPPORTED:
 *      - The key attributes, as a whole, are not supported.
 *      - The production parameters are not supported.
 *  - PSA_ERROR_INVALID_ARGUMENT:
 *      - The key type is invalid, or is an asymmetric public-key type.
 *      - The key type is PSA_KEY_TYPE_PASSWORD_HASH, and the permitted
 *        algorithm policy is not the same as the current operation’s algorithm.
 *      - The key size is not valid for the key type.
 *      - The key lifetime is invalid.
 *      - The key identifier is not valid for the key lifetime.
 *      - The key usage flags include invalid values.
 *      - The key’s permitted-usage algorithm is invalid.
 *      - The key attributes, as a whole, are invalid.
 *      - The production parameters are invalid.
 *  - PSA_ERROR_NOT_PERMITTED:
 *      - A PSA_KEY_DERIVATION_INPUT_SECRET or
 *        PSA_KEY_DERIVATION_INPUT_PASSWORD input was neither provided through
 *        a key nor the result of a key agreement.
 *      - One of the inputs was a key whose policy did not permit
 *        PSA_KEY_USAGE_DERIVE.
 *      - Creating a key with the specified attributes is not permitted.
 *  - PSA_ERROR_INSUFFICIENT_MEMORY
 *  - PSA_ERROR_INSUFFICIENT_STORAGE
 *  - PSA_ERROR_COMMUNICATION_FAILURE
 *  - PSA_ERROR_CORRUPTION_DETECTED
 *  - PSA_ERROR_STORAGE_FAILURE
 *  - PSA_ERROR_DATA_CORRUPT
 *  - PSA_ERROR_DATA_INVALID
 *  - PSA_ERROR_BAD_STATE:
 *      - The operation state is not valid: it must be active and completed all
 *        required input steps.
 *      - The library has not been previously initialized by psa_crypto_init().
 */
psa_status_t psa_key_derivation_output_key_custom(
	const psa_key_attributes_t *attributes,
	psa_key_derivation_operation_t *operation,
	const psa_custom_key_parameters_t *custom, const uint8_t *custom_data,
	size_t custom_data_length, psa_key_id_t *key);

/**
 * psa_key_derivation_verify_bytes - Compare output data from a key derivation
 *                                   operation to an expected value.
 * @operation: [in] The key derivation operation object to read from.
 * @expected_output: [in] Buffer containing the expected derivation output.
 * @output_length: [in] Length ot the expected output. This is also the number
 *                      of bytes that will be read.
 *
 * .. warning::
 *     Not supported.
 *
 * This function calculates output bytes from a key derivation algorithm and
 * compares those bytes to an expected value. If the key derivation’s output is
 * viewed as a stream of bytes, this function destructively reads
 * @output_length bytes from the stream before comparing them with
 * @expected_output. The operation’s capacity decreases by the number of bytes
 * read.
 *
 * This is functionally equivalent to the following code\:
 *
 *   .. code-block:: c
 *
 *      uint8_t tmp[output_length];
 *
 *      psa_key_derivation_output_bytes(operation, tmp, output_length);
 *
 *      if (memcmp(expected_output, tmp, output_length) != 0)
 *          return PSA_ERROR_INVALID_SIGNATURE;
 *
 * However, calling psa_key_derivation_verify_bytes() works even if the key’s
 * policy does not allow output of the bytes.
 *
 * If this function returns an error status other than
 * PSA_ERROR_INSUFFICIENT_DATA, the operation enters an error state and must be
 * aborted by calling psa_key_derivation_abort().
 *
 * Return:
 *  - PSA_SUCCESS:
 *      Success. The output of the key derivation operation matches
 *      @expected_output.
 *  - PSA_ERROR_BAD_STATE:
 *      - The operation state is not valid: it must be active, with all required
 *        input steps complete.
 *      - The library has not been previously initialized by psa_crypto_init().
 *  - PSA_ERROR_INVALID_SIGNATURE:
 *      The output of the key derivation operation does not match the value
 *      in @expected_output.
 *  - PSA_ERROR_INSUFFICIENT_DATA:
 *      The operation’s capacity was less than @output_length bytes. In this
 *      case, the operation’s capacity is set to zero.
 *  - PSA_ERROR_INSUFFICIENT_MEMORY
 *  - PSA_ERROR_COMMUNICATION_FAILURE
 *  - PSA_ERROR_CORRUPTION_DETECTED
 *  - PSA_ERROR_STORAGE_FAILURE
 *  - PSA_ERROR_DATA_CORRUPT
 *  - PSA_ERROR_DATA_INVALID
 */
psa_status_t
psa_key_derivation_verify_bytes(psa_key_derivation_operation_t *operation,
				const uint8_t *expected_output,
				size_t output_length);

/**
 * psa_key_derivation_verify_key() - Compare output data from a key derivation
 *                                   operation to an expected value stored in a
 *                                   key.
 * @operation: [in] The key derivation operation object to read from.
 * @expected: [in] key of type PSA_KEY_TYPE_PASSWORD_HASH containing the
 *                 expected output. The key must allow the usage
 *                 PSA_KEY_USAGE_VERIFY_DERIVATION, and the permitted algorithm
 *                 must match the operation’s algorithm. The value of this key
 *                 is typically computed by a previous call to
 *                 psa_key_derivation_output_key().
 *
 * .. warning::
 *     Not supported.
 *
 * This function calculates output bytes from a key derivation algorithm and
 * compares those bytes to an expected value, provided as key of type
 * PSA_KEY_TYPE_PASSWORD_HASH. If the key derivation’s output is viewed as a
 * stream of bytes, this function destructively reads the number of bytes
 * corresponding to the length of the expected key from the stream before
 * comparing them with the key value. The operation’s capacity decreases by the
 * number of bytes read.
 *
 * .. note::
 *    This is functionally equivalent to exporting the expected key and calling
 *    psa_key_derivation_verify_bytes() on the result, except that it works when
 *    the key cannot be exported.
 *
 * If this function returns an error status other than
 * PSA_ERROR_INSUFFICIENT_DATA, the operation enters an error state and must be
 * aborted by calling psa_key_derivation_abort().
 *
 * Return:
 *  - PSA_SUCCESS:
 *      Success. The output of the key derivation operation matches the expected
 *      key value.
 *  - PSA_ERROR_BAD_STATE:
 *      - The operation state is not valid: it must be active, with all required
 *        input steps complete.
 *      - The library has not been previously initialized by psa_crypto_init().
 *  - PSA_ERROR_INVALID_HANDLE:
 *      @expected is not a valid key identifier.
 *  - PSA_ERROR_NOT_PERMITTED:
 *      The key does not have the PSA_KEY_USAGE_VERIFY_DERIVATION flag, or it
 *      does not permit the requested algorithm.
 *  - PSA_ERROR_INVALID_SIGNATURE:
 *      The output of the key derivation operation does not match the value of
 *      the expected key.
 *  - PSA_ERROR_INSUFFICIENT_DATA:
 *      The operation’s capacity was less than the length of the @expected key.
 *      In this case, the operation’s capacity is set to zero.
 *  - PSA_ERROR_INVALID_ARGUMENT:
 *      The key type is not PSA_KEY_TYPE_PASSWORD_HASH.
 *  - PSA_ERROR_INSUFFICIENT_MEMORY
 *  - PSA_ERROR_COMMUNICATION_FAILURE
 *  - PSA_ERROR_CORRUPTION_DETECTED
 *  - PSA_ERROR_STORAGE_FAILURE
 *  - PSA_ERROR_DATA_CORRUPT
 *  - PSA_ERROR_DATA_INVALID
 */
psa_status_t
psa_key_derivation_verify_key(psa_key_derivation_operation_t *operation,
			      psa_key_id_t expected);

/**
 * psa_key_derivation_abort() - Abort a key derivation operation.
 * @operation: [in] The operation to abort.
 *
 * Aborting an operation frees all associated resources except for the operation
 * object itself. Once aborted, the operation object can be reused for another
 * operation by calling psa_key_derivation_setup() again.
 *
 * This function can be called at any time after the operation object has been
 * initialized as described in &typedef psa_key_derivation_operation_t.
 *
 * In particular, it is valid to call psa_key_derivation_abort() twice, or to
 * call psa_key_derivation_abort() on an operation that has not been set up.
 *
 * Return:
 *  - PSA_SUCCESS
 *  - PSA_ERROR_COMMUNICATION_FAILURE
 *  - PSA_ERROR_HARDWARE_FAILURE
 *  - PSA_ERROR_CORRUPTION_DETECTED
 *  - PSA_ERROR_BAD_STATE:
 *      The library has not been previously initialized by psa_crypto_init().
 */
psa_status_t
psa_key_derivation_abort(psa_key_derivation_operation_t *operation);

/**
 * psa_key_agreement() - Perform a key agreement and return the shared secret
 *                       as a derivation key.
 * @private_key: [in] Identifier of the private key to use. It must permit the
 *                    usage PSA_KEY_USAGE_DERIVE.
 * @peer_key: [in] Public key of the peer.
 * @peer_key_length: [in] Size of @peer_key in bytes.
 * @alg: [in] The standalone key agreement algorithm to compute: a value of
 *            &typedef psa_algorithm_t such that
 *            :c:macro:`PSA_ALG_IS_STANDALONE_KEY_AGREEMENT` is true.
 * @attributes: [in] The attributes for the new key.
 * @key: [out] On success, an identifier for the newly created key.
 *             PSA_KEY_ID_NULL on failure.
 *
 * .. warning::
 *     Not supported.
 *
 * A key agreement algorithm takes two inputs: a private key @private_key, and
 * a public key @peer_key. The result of this function is a shared secret,
 * returned as a derivation key.
 *
 * The @peer_key data is parsed with the type
 * :c:macro:`PSA_KEY_TYPE_PUBLIC_KEY_OF_KEY_PAIR` where type is the type of
 * @private_key, and with the same bit-size as private_key. The peer key must
 * be in the format that psa_import_key() accepts for this public key type.
 *
 * This key can be input to a key derivation operation using
 * psa_key_derivation_input_key().
 *
 * .. warning::
 *    The shared secret resulting from a key agreement algorithm such as
 *    finite-field Diffie-Hellman or elliptic curve Diffie-Hellman has biases.
 *    This makes it unsuitable for use as key material, for example, as an AES
 *    key. Instead, it is recommended that a key derivation algorithm is applied
 *    to the result, to derive unbiased cryptographic keys.
 *
 * The following new key @attributes are required\:
 *
 *  - The key type must be one of PSA_KEY_TYPE_DERIVE, PSA_KEY_TYPE_RAW_DATA,
 *    PSA_KEY_TYPE_HMAC, or PSA_KEY_TYPE_PASSWORD.
 *  - The key permitted algorithm policy.
 *  - The key usage flags.
 *
 * The following new key attributes must be set in case of a persistent key\:
 *
 *  - The key lifetime.
 *  - The key identifier.
 *
 * The following new key @attributes is optional\:
 *
 *  - The key size if nonzero, it must be equal to the output size of the key
 *    agreement, in bits.
 *
 *    The output size, in bits, of the key agreement is
 *    8 * PSA_RAW_KEY_AGREEMENT_OUTPUT_SIZE(type, bits), where type and bits are
 *    the type and bit-size of @private_key.
 *
 * Return:
 *  - PSA_SUCCESS:
 *      Success. The new key contains the share secret. If the key is
 *      persistent, the key material and the key’s metadata have been saved to
 *      persistent storage.
 *  - PSA_ERROR_BAD_STATE:
 *      - The library has not been previously initialized by psa_crypto_init().
 *  - PSA_ERROR_INVALID_HANDLE:
 *      @private_key is not a valid key identifier.
 *  - PSA_ERROR_NOT_PERMITTED:
 *      - @private_key does not have the PSA_KEY_USAGE_DERIVE flag, or it does
 *        not permit the requested algorithm.
 *      - Creating a key with the specified attributes is not permitted.
 *  - PSA_ERROR_ALREADY_EXISTS:
 *      This is an attempt to create a persistent key, and there is already a
 *      persistent key with the given identifier.
 *  - PSA_ERROR_INVALID_ARGUMENT:
 *      - @alg is not a key agreement algorithm.
 *      - @private_key is not compatible with @alg.
 *      - @peer_key is not a valid public key corresponding to @private_key.
 *      - The output key attributes in @attributes are not valid\:
 *
 *         - The key type is not valid for key agreement output.
 *         - The key size is nonzero, and is not the size of the shared secret.
 *         - The key lifetime is invalid.
 *         - The key identifier is not valid for the key lifetime.
 *         - The key usage flags include invalid values.
 *         - The key’s permitted-usage algorithm is invalid.
 *         - The key attributes, as a whole, are invalid.
 *  - PSA_ERROR_NOT_SUPPORTED:
 *      - @alg is not supported.
 *      - @private_key is not supported for use with @alg.
 *      - The output key attributes, as a whole, are not supported.
 *  - PSA_ERROR_INSUFFICIENT_MEMORY
 *  - PSA_ERROR_INSUFFICIENT_STORAGE
 *  - PSA_ERROR_COMMUNICATION_FAILURE
 *  - PSA_ERROR_CORRUPTION_DETECTED
 *  - PSA_ERROR_STORAGE_FAILURE
 *  - PSA_ERROR_DATA_CORRUPT
 *  - PSA_ERROR_DATA_INVALID
 */
psa_status_t psa_key_agreement(psa_key_id_t private_key,
			       const uint8_t *peer_key, size_t peer_key_length,
			       psa_algorithm_t alg,
			       const psa_key_attributes_t *attributes,
			       psa_key_id_t *key);

/**
 * psa_raw_key_agreement() - Perform a key agreement and return the raw shared
 *                           secret.
 * @alg: [in] The key agreement algorithm to compute (PSA_ALG_XXX value such
 *            that :c:macro:`PSA_ALG_IS_RAW_KEY_AGREEMENT` is true).
 * @private_key: [in] Identifier of the private key to use. It must allow the
 *                    usage PSA_KEY_USAGE_DERIVE.
 * @peer_key: [in] Public key of the peer.
 * @peer_key_length: [in] Size of @peer_key in bytes.
 * @output: [out] Buffer where the raw shared secret is to be written.
 * @output_size: [in] Size of the @output buffer in bytes.
 * @output_length: [out] On success, the number of bytes that make up the
 *                       returned output.
 *
 * .. warning::
 *     Not supported.
 *
 * A key agreement algorithm takes two inputs: a private key @private_key, and
 * a public key @peer_key. The result of this function is a shared secret,
 * returned as a derivation key.
 *
 * The @peer_key data is parsed with the type
 * :c:macro:`PSA_KEY_TYPE_PUBLIC_KEY_OF_KEY_PAIR` where type is the type of
 * @private_key, and with the same bit-size as private_key. The peer key must
 * be in the format that psa_import_key() accepts for this public key type.
 *
 * .. warning::
 *     The raw result of a key agreement algorithm such as finite-field
 *     Diffie-Hellman or elliptic curve Diffie-Hellman has biases, and is not
 *     suitable for use as key material. Instead it is recommended that the
 *     result is used as input to a key derivation algorithm.
 *
 *     To chain a key agreement with a key derivation, use
 *     psa_key_derivation_key_agreement() and other functions from the key
 *     derivation interface.
 *
 * The @output_size parameter must be appropriate for the keys\:
 *
 *  - The required output size is PSA_RAW_KEY_AGREEMENT_OUTPUT_SIZE(type, bits)
 *    where type is the type of @private_key and bits is the bit-size of either
 *    @private_key or the @peer_key.
 *  - PSA_RAW_KEY_AGREEMENT_OUTPUT_MAX_SIZE evaluates to the maximum output size
 *    of any supported raw key agreement algorithm.
 *
 * Return:
 *  - PSA_SUCCESS:
 *      Success.
 *  - PSA_ERROR_INVALID_HANDLE:
 *      @private_key is not a valid key identifier.
 *  - PSA_ERROR_NOT_PERMITTED:
 *      @private_key does not have the PSA_KEY_USAGE_DERIVE flag, or it does
 *      not permit the requested algorithm.
 *  - PSA_ERROR_INVALID_ARGUMENT:
 *      - @alg is not a key agreement algorithm.
 *      - @private_key is not compatible with @alg.
 *      - @peer_key is not valid public key corresponding to @private_key.
 *  - PSA_ERROR_BUFFER_TOO_SMALL:
 *      The size of the @output buffer is too small.
 *      PSA_RAW_KEY_AGREEMENT_OUTPUT_SIZE() or
 *      PSA_RAW_KEY_AGREEMENT_OUTPUT_MAX_SIZE can be used to determine the
 *      required buffer size.
 *  - PSA_ERROR_NOT_SUPPORTED:
 *      - @alg is not a supported key agreement algorithm.
 *      - @private_key is not supported for use with @alg.
 *  - PSA_ERROR_INSUFFICIENT_MEMORY
 *  - PSA_ERROR_COMMUNICATION_FAILURE
 *  - PSA_ERROR_CORRUPTION_DETECTED
 *  - PSA_ERROR_STORAGE_FAILURE
 *  - PSA_ERROR_DATA_CORRUPT
 *  - PSA_ERROR_DATA_INVALID
 *  - PSA_ERROR_BAD_STATE:
 *      - The library has not been previously initialized by psa_crypto_init().
 */
psa_status_t psa_raw_key_agreement(psa_algorithm_t alg,
				   psa_key_id_t private_key,
				   const uint8_t *peer_key,
				   size_t peer_key_length, uint8_t *output,
				   size_t output_size, size_t *output_length);

/**
 * psa_key_derivation_key_agreement() - Perform a key agreement and use the
 *                                      shared secret as input to a key derivation.
 * @operation: [in] The key derivation operation object to use. It must have
 *                  been set up with psa_key_derivation_setup() with a key
 *                  agreement and derivation algorithm (PSA_ALG_XXX value such
 *                  that :c:macro:`PSA_ALG_IS_KEY_AGREEMENT` is true and
 *                  :c:macro:`PSA_ALG_IS_RAW_KEY_AGREEMENT` is false). The
 *                  operation must be ready for an input of the type given by
 *                  step.
 * @step: [in] Which step the input data is for.
 * @private_key: [in] Identifier of the private key to use. It must allow the
 *                    usage PSA_KEY_USAGE_DERIVE.
 * @peer_key: [in] Public key of the peer.
 * @peer_key_length: [in] Size of @peer_key in bytes.
 *
 * A key agreement algorithm takes two inputs: a private key @private_key a
 * public key @peer_key. The result of this function is passed as input to a
 * key derivation. The output of this key derivation can be extracted by reading
 * from the resulting operation to produce keys and other cryptographic
 * material.
 *
 * The @peer_key data is parsed with the type
 * :c:macro:`PSA_KEY_TYPE_PUBLIC_KEY_OF_KEY_PAIR` where type is the type of
 * @private_key, and with the same bit-size as private_key. The peer key must
 * be in the format that psa_import_key() accepts for this public key type.
 *
 * If this function returns an error status, the operation enters an error
 * state and must be aborted by calling psa_key_derivation_abort().
 *
 * Return:
 *  - PSA_SUCCESS:
 *      Success.
 *  - PSA_ERROR_INVALID_HANDLE:
 *      @private_key is not a valid key identifier.
 *  - PSA_ERROR_NOT_PERMITTED:
 *      @private_key does not have the PSA_KEY_USAGE_DERIVE flag, or it does
 *      not permit the requested algorithm.
 *  - PSA_ERROR_INVALID_ARGUMENT:
 *      - The operation’s algorithm is not a key-agreement algorithm.
 *      - @step does not permit an input resulting from a key agreement.
 *      - @private_key is not compatible with the operation’s algorithm.
 *      - @peer_key is not a valid public key corresponding to @private_key.
 *  - PSA_ERROR_NOT_SUPPORTED:
 *      @private_key is not supported for use with the operation’s algorithm.
 *  - PSA_ERROR_INSUFFICIENT_MEMORY
 *  - PSA_ERROR_COMMUNICATION_FAILURE
 *  - PSA_ERROR_CORRUPTION_DETECTED
 *  - PSA_ERROR_STORAGE_FAILURE
 *  - PSA_ERROR_DATA_CORRUPT
 *  - PSA_ERROR_DATA_INVALID
 *  - PSA_ERROR_BAD_STATE:
 *      - The operation state is not valid for this key agreement step.
 *      - The library has not been previously initialized by psa_crypto_init().
 */
psa_status_t
/* Without this comment clang-format does not meet the checkpatch requirement. */
psa_key_derivation_key_agreement(psa_key_derivation_operation_t *operation,
				 psa_key_derivation_step_t step,
				 psa_key_id_t private_key,
				 const uint8_t *peer_key,
				 size_t peer_key_length);

/**
 * psa_encapsulate() - Use a public key to generate a new shared secret key and
 *                     associated ciphertext.
 * @key: [in] Identifier of the key to use for the encapsulation. It must be a
 *            public key or an asymmetric key pair. It must permit the usage
 *            PSA_KEY_USAGE_ENCRYPT.
 * @alg: [in] The key-encapsulation algorithm such that
 *            :c:macro:`PSA_ALG_IS_KEY_ENCAPSULATION` is true.
 * @attributes: [in] The attributes for the output key.
 * @output_key: [out] On success, an identifier for the newly created shared
 *                    secret key. PSA_KEY_ID_NULL on failure.
 * @ciphertext: [out] Buffer where the ciphertext output is to be written.
 * @ciphertext_size: [in] Size of the @ciphertext buffer in bytes.
 * @ciphertext_length: [out] On success, the number of bytes that make up the
 *                           ciphertext value.
 *
 * .. warning::
 *    Not supported.
 *
 * The following new key @attributes are required\:
 *
 *  - The key type. All key-encapsulation algorithms can output a key of type
 *    PSA_KEY_TYPE_DERIVE or PSA_KEY_TYPE_HMAC. Key encapsulation algorithms
 *    that produce a uniformly pseudorandom shared secret, can also output
 *    block-cipher key types, for example PSA_KEY_TYPE_AES.
 *  - The key permitted algorithm policy.
 *  - The key usage flags.
 *
 * The following new key attributes must be set in case of a persistent key\:
 *
 *  - The key lifetime.
 *  - The key identifier.
 *
 * The following new key @attributes is optional\:
 *
 *  - The key size, if is nonzero, it must be equal to the size, in bits, of
 *    the shared secret.
 *
 * The @output_key location, policy, and type are taken from @attributes.
 *
 * The size of the returned key is always the bit-size of the shared secret,
 * rounded up to a whole number of bytes. The size of the shared secret is
 * dependent on the key encapsulation algorithm and the type and size of @key.
 *
 * It is recommended that the shared secret key is used as an input to a key
 * derivation operation to produce additional cryptographic keys. For some
 * key encapsulation algorithms, the shared secret key is also suitable for use
 * as a key in cryptographic operations such as encryption.
 *
 * The output @ciphertext is to be sent to the other participant, who uses the
 * decapsulation key to extract another copy of the shared secret key.
 *
 * Return:
 *  - PSA_SUCCESS:
 *      Success. The bytes of @ciphertext contain the data to be sent to the
 *      other participant, and @output_key contains the identifier for the
 *      shared secret key.
 *  - PSA_ERROR_INVALID_HANDLE:
 *      @key is not a valid key identifier.
 *  - PSA_ERROR_NOT_PERMITTED:
 *      - The key does not have the PSA_KEY_USAGE_ENCRYPT flag, or it does not
 *        permit the requested algorithm.
 *      - Creating a key with the specified attributes is not permitted.
 *  - PSA_ERROR_INVALID_ARGUMENT:
 *      - @alg is not a key encapsulation algorithm.
 *      - @key is not a public key or an asymmetric key pair, that is compatible
 *        with @alg.
 *      - The output key attributes in @attributes are not valid\:
 *
 *         - The key type is not valid for the shared secret.
 *         - The key size is nonzero, and is not the size of the shared secret.
 *         - The key lifetime is invalid.
 *         - The key identifier is not valid for the key lifetime.
 *         - The key usage flags include invalid values.
 *         - The key’s permitted-usage algorithm is invalid.
 *         - The key attributes, as a whole, are invalid.
 *  - PSA_ERROR_NOT_SUPPORTED:
 *      - @alg is not supported.
 *      - @key is not supported for use with @alg.
 *      - The output key attributes, as a whole, are not supported.
 *  - PSA_ERROR_INSUFFICIENT_MEMORY
 *  - PSA_ERROR_COMMUNICATION_FAILURE
 *  - PSA_ERROR_CORRUPTION_DETECTED
 *  - PSA_ERROR_STORAGE_FAILURE
 *  - PSA_ERROR_DATA_CORRUPT
 *  - PSA_ERROR_DATA_INVALID
 *  - PSA_ERROR_BAD_STATE:
 *      The library has not been previously initialized by psa_crypto_init().
 */
psa_status_t psa_encapsulate(psa_key_id_t key, psa_algorithm_t alg,
			     const psa_key_attributes_t *attributes,
			     psa_key_id_t *output_key, uint8_t *ciphertext,
			     size_t ciphertext_size, size_t *ciphertext_length);

/**
 * psa_decapsulate() - Use a private key to decapsulate a shared secret key
 *                     from a ciphertext.
 * @key: [in] Identifier of the key to use for the decapsulation. It must be an
 *            asymmetric key pair. It must permit the usage
 *            PSA_KEY_USAGE_DECRYPT.
 * @alg: [in] The key-encapsulation algorithm such that
 *            :c:macro:`PSA_ALG_IS_KEY_ENCAPSULATION` is true.
 * @ciphertext: [in] The ciphertext received from the other participant.
 * @ciphertext_length: [in] Size of the @ciphertext buffer in bytes.
 * @attributes: [in] The attributes for the output key.
 * @output_key: [out] On success, an identifier for the newly created shared
 *                    secret key. PSA_KEY_ID_NULL on failure.
 *
 * .. warning::
 *    Not supported.
 *
 * The following new key @attributes are required\:
 *
 *  - The key type. All key-encapsulation algorithms can output a key of type
 *    PSA_KEY_TYPE_DERIVE or PSA_KEY_TYPE_HMAC. Key encapsulation algorithms
 *    that produce a uniformly pseudorandom shared secret, can also output
 *    block-cipher key types, for example PSA_KEY_TYPE_AES.
 *  - The key permitted algorithm policy.
 *  - The key usage flags.
 *
 * The following new key attributes must be set in case of a persistent key\:
 *
 *  - The key lifetime.
 *  - The key identifier.
 *
 * The following new key @attributes is optional\:
 *
 *  - The key size, if is nonzero, it must be equal to the size, in bits, of
 *    the shared secret.
 *
 * The @output_key location, policy, and type are taken from @attributes.
 *
 * The size of the returned key is always the bit-size of the shared secret,
 * rounded up to a whole number of bytes. The size of the shared secret is
 * dependent on the key-encapsulation algorithm and the type and size of key.
 *
 * It is recommended that the shared secret key is used as an input to a key
 * derivation operation to produce additional cryptographic keys. For some
 * key encapsulation algorithms, the shared secret key is also suitable for use
 * as a key in cryptographic operations such as encryption.
 *
 * If the key encapsulation protocol is executed correctly then, with
 * overwhelming probability, the two copies of the shared secret are identical.
 * However, the protocol does not protect one participant against the other
 * participant executing it incorrectly, or against a third party modifying
 * data in transit.
 *
 * .. warning::
 *    A PSA_SUCCESS result from psa_decapsulate() does not guarantee that the
 *    output key is identical to the key produced by the call to
 *    psa_encapsulate(). For example, PSA_SUCCESS can be returned with a
 *    mismatched shared secret key value in the following situations\:
 *
 *      - The key encapsulation algorithm does not authenticate the ciphertext.
 *        Manipulated or corrupted ciphertext will not be detected during
 *        decapsulation.
 *      - The key encapsulation algorithm reports authentication failure
 *        implicitly, by returning a pseudorandom key value. This is done to
 *        prevent disclosing information to an attacker that has manipulated the
 *        ciphertext.
 *      - The key encapsulation algorithm is probabilistic, and will extremely
 *        rarely result in non-identical key values.
 *
 *    It is strongly recommended that the application uses the output key in a
 *    way that will confirm that the shared secret keys are identical.
 *
 * Return:
 *  - PSA_SUCCESS:
 *      Success. @output_key contains the identifier for the shared secret key.
 *  - PSA_ERROR_INVALID_HANDLE:
 *      @key is not a valid key identifier.
 *  - PSA_ERROR_NOT_PERMITTED:
 *      - The key does not have the PSA_KEY_USAGE_DECRYPT flag, or it does not
 *        permit the requested algorithm.
 *      - Creating a key with the specified attributes is not permitted.
 *  - PSA_ERROR_INVALID_ARGUMENT:
 *      - @alg is not a key encapsulation algorithm.
 *      - @key is not an asymmetric key pair, that is compatible with @alg.
 *      - The output key attributes in @attributes are not valid\:
 *
 *         - The key type is not valid for the shared secret.
 *         - The key size is nonzero, and is not the size of the shared secret.
 *         - The key lifetime is invalid.
 *         - The key identifier is not valid for the key lifetime.
 *         - The key usage flags include invalid values.
 *         - The key’s permitted-usage algorithm is invalid.
 *         - The key attributes, as a whole, are invalid.
 *      - @ciphertext is obviously invalid for the selected algorithm and key.
 *  - PSA_ERROR_NOT_SUPPORTED:
 *      - @alg is not supported.
 *      - @key is not supported for use with @alg.
 *      - The output key attributes, as a whole, are not supported.
 *  - PSA_ERROR_INSUFFICIENT_MEMORY
 *  - PSA_ERROR_COMMUNICATION_FAILURE
 *  - PSA_ERROR_CORRUPTION_DETECTED
 *  - PSA_ERROR_STORAGE_FAILURE
 *  - PSA_ERROR_DATA_CORRUPT
 *  - PSA_ERROR_DATA_INVALID
 *  - PSA_ERROR_BAD_STATE:
 *      The library has not been previously initialized by psa_crypto_init().
 */
psa_status_t psa_decapsulate(psa_key_id_t key, psa_algorithm_t alg,
			     const uint8_t *ciphertext,
			     size_t ciphertext_length,
			     const psa_key_attributes_t *attributes,
			     psa_key_id_t *output_key);

#endif /* __PSA_KEYMGR_H__ */