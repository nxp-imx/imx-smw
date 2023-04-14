/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2022-2023 NXP
 */

#ifndef __PSA_CRYPTO_H__
#define __PSA_CRYPTO_H__

#include <stdint.h>
#include <stddef.h>

#include "psa/error.h"
#include "psa/crypto_types.h"
#include "psa/crypto_values.h"

/**
 * DOC:
 * This file contains the delarations of the crypto functions supported by the PSA Cryptography API.
 */

/**
 * DOC: Reference
 * Documentation:
 *	PSA Cryptography API v1.1.0
 * Link:
 *	https://developer.arm.com/documentation/ihi0086/b
 */

/**
 * typedef psa_aead_operation_t - The type of the state object for multi-part AEAD operations.
 *
 * Before calling any function on an AEAD operation object, the application must initialize it by
 * any of the following means\:
 *
 * - Set the object to all-bits-zero, for example\:
 *
 *   .. code-block:: c
 *
 *      psa_aead_operation_t operation;
 *      memset(&operation, 0, sizeof(operation));
 *
 * - Initialize the object to logical zero values by declaring the object as static or global
 *   without an explicit initializer, for example\:
 *
 *   .. code-block:: c
 *
 *      static psa_aead_operation_t operation;
 *
 * - Initialize the object to the initializer PSA_AEAD_OPERATION_INIT, for example\:
 *
 *   .. code-block:: c
 *
 *      psa_aead_operation_t operation = PSA_AEAD_OPERATION_INIT;
 *
 * - Assign the result of the function psa_aead_operation_init() to the object, for example\:
 *
 *   .. code-block:: c
 *
 *      psa_aead_operation_t operation;
 *
 * This is an implementation-defined type. Application should not make any assumptions about the
 * content of this object.
 */
typedef struct psa_aead_operation_s psa_aead_operation_t;

/**
 * typedef psa_cipher_operation_t - The type of the state object for multi-part cipher operations.
 *
 * Before calling any function on a cipher operation object, the application must initialize it by
 * any of the following means\:
 *
 * - Set the object to all-bits-zero, for example\:
 *
 *   .. code-block:: c
 *
 *      psa_cipher_operation_t operation;
 *      memset(&operation, 0, sizeof(operation));
 *
 * - Initialize the object to logical zero values by declaring the object as static or global
 *   without an explicit initializer, for example\:
 *
 *   .. code-block:: c
 *
 *      static psa_cipher_operation_t operation;
 *
 * - Initialize the object to the initializer PSA_CIPHER_OPERATION_INIT, for example\:
 *
 *   .. code-block:: c
 *
 *      psa_cipher_operation_t operation = PSA_CIPHER_OPERATION_INIT;
 *
 * - Assign the result of the function psa_cipher_operation_init() to the object, for example\:
 *
 *   .. code-block:: c
 *
 *      psa_cipher_operation_t operation;
 *      operation = psa_cipher_operation_init();
 *
 * This is an implementation-defined type. Application should not make any assumptions about the
 * content of this object.
 */
typedef struct psa_cipher_operation_s psa_cipher_operation_t;

/**
 * typedef psa_hash_operation_t - The type of the state object for multi-part hash operations.
 *
 * Before calling any function on a hash operation object, the application must initialize it by
 * any of the following means\:
 *
 * - Set the object to all-bits-zero, for example\:
 *
 *   .. code-block:: c
 *
 *      psa_hash_operation_t operation;
 *      memset(&operation, 0, sizeof(operation));
 *
 * - Initialize the object to logical zero values by declaring the object as static or global
 *   without an explicit initializer, for example\:
 *
 *   .. code-block:: c
 *
 *      static psa_hash_operation_t operation;
 *
 * - Initialize the object to the initializer PSA_HASH_OPERATION_INIT, for example\:
 *
 *   .. code-block:: c
 *
 *      psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;
 *
 * - Assign the result of the function psa_hash_operation_init() to the object, for example\:
 *
 *   .. code-block:: c
 *
 *      psa_hash_operation_t operation;
 *      operation = psa_hash_operation_init();
 *
 * This is an implementation-defined type. Application should not make any assumptions about the
 * content of this object.
 */
typedef struct psa_hash_operation_s psa_hash_operation_t;

/**
 * typedef psa_key_attributes_t - The type of an object containing key attributes.
 *
 * This is the object that represents the metadata of a key object. Metadata that can be stored in
 * attributes includes\:
 *
 * - The location of the key in storage, indicated by its key identifier and its lifetime.
 *
 * - The key’s policy, comprising usage flags and a specification of the permitted algorithm(s).
 *
 * - Information about the key itself: the key type and its size.
 *
 * - Implementation specific attributes.
 *
 * The actual key material is not considered an attribute of a key. Key attributes do not contain
 * information that is generally considered highly confidential.
 *
 * This is an implementation-defined type. Application should not make any assumptions about the
 * content of this object.
 *
 * Each attribute of this object is set with a function psa_set_key_xxx() and retrieved with a
 * function psa_get_key_xxx().
 *
 * An attribute object can contain references to auxiliary resources, for example pointers to
 * allocated memory or indirect references to pre-calculated values. In order to free such
 * resources, the application must call psa_reset_key_attributes(). As an exception, calling
 * psa_reset_key_attributes() on an attribute object is optional if the object has only been
 * modified by the following functions since it was initialized or last reset with
 * psa_reset_key_attributes()\:
 *
 * - psa_set_key_id()
 * - psa_set_key_lifetime()
 * - psa_set_key_type()
 * - psa_set_key_bits()
 * - psa_set_key_usage_flags()
 * - psa_set_key_algorithm()
 *
 * Before calling any function on a key attribute object, the application must initialize it by any
 * of the following means\:
 *
 * - Set the object to all-bits-zero, for example\:
 *
 *   .. code-block:: c
 *
 *      psa_key_attributes_t attributes;
 *      memset(&attributes, 0, sizeof(attributes));
 *
 * - Initialize the object to logical zero values by declaring the object as static or global
 *   without an explicit initializer, for example\:
 *
 *   .. code-block:: c
 *
 *      static psa_key_attributes_t attributes;
 *
 * - Initialize the object to the initializer PSA_KEY_ATTRIBUTES_INIT, for example\:
 *
 *   .. code-block:: c
 *
 *      psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
 *
 * - Assign the result of the function psa_key_attributes_init() to the object, for example\:
 *
 *   .. code-block:: c
 *
 *      psa_key_attributes_t attributes;
 *      attributes = psa_key_attributes_init();
 *
 * A freshly initialized attribute object contains the following values\:
 *
 *   .. tabularcolumns:: |\Y{0.2}|\Y{0.8}|
 *
 *   +----------------+----------------------------------------------------------------------------+
 *   | **Attribute**  | **Value**                                                                  |
 *   +================+============================================================================+
 *   | lifetime       | PSA_KEY_LIFETIME_VOLATILE.                                                 |
 *   +----------------+----------------------------------------------------------------------------+
 *   | key identifier | PSA_KEY_ID_NULL - which is not a valid key identifier.                     |
 *   +----------------+----------------------------------------------------------------------------+
 *   | type           | PSA_KEY_TYPE_NONE - meaning that the type is unspecified.                  |
 *   +----------------+----------------------------------------------------------------------------+
 *   | key size       | 0 - meaning that the size is unspecified.                                  |
 *   +----------------+----------------------------------------------------------------------------+
 *   | usage flags    | 0 - which allows no usage except exporting a public key.                   |
 *   +----------------+----------------------------------------------------------------------------+
 *   | algorithm      | PSA_ALG_NONE - which does not allow cryptographic usage, but allows        |
 *   |                | exporting.                                                                 |
 *   +----------------+----------------------------------------------------------------------------+
 *
 * **Usage**:
 *
 * A typical sequence to create a key is as follows\:
 *
 * #. Create and initialize an attribute object.
 *
 * #. If the key is persistent, call psa_set_key_id(). Also call psa_set_key_lifetime() to place
 *    the key in a non-default location.
 *
 * #. Set the key policy with psa_set_key_usage_flags() and psa_set_key_algorithm().
 *
 * #. Set the key type with psa_set_key_type(). Skip this step if copying an existing key with
 *    psa_copy_key().
 *
 * #. When generating a random key with psa_generate_key() or deriving a key with
 *    psa_key_derivation_output_key(), set the desired key size with psa_set_key_bits().
 *
 * #. Call a key creation function: psa_import_key(), psa_generate_key(),
 *    psa_key_derivation_output_key() or psa_copy_key(). This function reads the attribute object,
 *    creates a key with these attributes, and outputs an identifier for the newly created key.
 *
 * #. Optionally call psa_reset_key_attributes(), now that the attribute object is no longer
 *    needed. Currently this call is not required as the attributes defined in this specification do
 *    not require additional resources beyond the object itself.
 *
 * A typical sequence to query a key’s attributes is as follows\:
 *
 * #. Call psa_get_key_attributes().
 *
 * #. Call psa_get_key_xxx() functions to retrieve the required attribute(s).
 *
 * #. Call psa_reset_key_attributes() to free any resources that can be used by the attribute
 *    object.
 *
 * Once a key has been created, it is impossible to change its attributes.
 */
typedef struct psa_key_attributes_s psa_key_attributes_t;

/**
 * typedef psa_key_derivation_operation_t - The type of the state object for key derivation
 * operations.
 *
 * Before calling any function on a key derivation operation object, the application must
 * initialize it by any of the following means\:
 *
 * - Set the object to all-bits-zero, for example\:
 *
 *   .. code-block:: c
 *
 *      psa_key_derivation_operation_t operation;
 *      memset(&operation, 0, sizeof(operation));
 *
 * - Initialize the object to logical zero values by declaring the object as static or global
 *   without an explicit initializer, for example\:
 *
 *   .. code-block:: c
 *
 *      static psa_key_derivation_operation_t operation;
 *
 * - Initialize the object to the initializer PSA_KEY_DERIVATION_OPERATION_INIT, for example\:
 *
 *   .. code-block:: c
 *
 *      psa_key_derivation_operation_t operation = PSA_KEY_DERIVATION_OPERATION_INIT;
 *
 * - Assign the result of the function psa_key_derivation_operation_init() to the object, for
 *   example\:
 *
 *   .. code-block:: c
 *
 *      psa_key_derivation_operation_t operation;
 *      operation = psa_key_derivation_operation_init();
 *
 * This is an implementation-defined type. Application should not make any assumptions about the
 * content of this object.
 */
typedef struct psa_key_derivation_operation_s psa_key_derivation_operation_t;

/**
 * typedef psa_mac_operation_t - The type of the state object for multi-part MAC operations.
 *
 * Before calling any function on a MAC operation object, the application must initialize it by any
 * of the following means\:
 *
 * - Set the object to all-bits-zero, for example\:
 *
 *   .. code-block:: c
 *
 *      psa_mac_operation_t operation;
 *      memset(&operation, 0, sizeof(operation));
 *
 * - Initialize the object to logical zero values by declaring the object as static or global
 *   without an explicit initializer, for example\:
 *
 *   .. code-block:: c
 *
 *      static psa_mac_operation_t operation;
 *
 * - Initialize the object to the initializer PSA_MAC_OPERATION_INIT, for example\:
 *
 *   .. code-block:: c
 *
 *      psa_mac_operation_t operation = PSA_MAC_OPERATION_INIT;
 *
 * - Assign the result of the function psa_mac_operation_init() to the object, for example\:
 *
 *   .. code-block:: c
 *
 *      psa_mac_operation_t operation;
 *      operation = psa_mac_operation_init();
 *
 * This is an implementation-defined type. Application should not make any assumptions about the
 * content of this object.
 */
typedef struct psa_mac_operation_s psa_mac_operation_t;

/**
 * DOC: PSA_CRYPTO_API_VERSION_MAJOR
 * The major version of this implementation of the PSA Crypto API.
 */
#define PSA_CRYPTO_API_VERSION_MAJOR 1

/**
 * DOC: PSA_CRYPTO_API_VERSION_MINOR
 * The minor version of this implementation of the PSA Crypto API.
 */
#define PSA_CRYPTO_API_VERSION_MINOR 1

/**
 * DOC: PSA_KEY_DERIVATION_UNLIMITED_CAPACITY
 * Use the maximum possible capacity for a key derivation operation.
 *
 * Use this value as the capacity argument when setting up a key derivation to specify that the
 * operation will use the maximum possible capacity. The value of the maximum possible capacity
 * depends on the key derivation algorithm.
 */
#define PSA_KEY_DERIVATION_UNLIMITED_CAPACITY /* implementation-defined value */

/**
 * psa_aead_abort() - Abort an AEAD operation.
 * @operation: Initialized AEAD operation.
 *
 * **Warning: Not supported**
 *
 * Aborting an operation frees all associated resources except for the operation object itself. Once
 * aborted, the operation object can be reused for another operation by calling
 * psa_aead_encrypt_setup() or psa_aead_decrypt_setup() again.
 *
 * This function can be called any time after the operation object has been initialized as described
 * in &typedef psa_aead_operation_t.
 *
 * In particular, calling psa_aead_abort() after the operation has been terminated by a call to
 * psa_aead_abort(), psa_aead_finish() or psa_aead_verify() is safe and has no effect.
 *
 * Return:
 * * PSA_SUCCESS
 * * PSA_ERROR_COMMUNICATION_FAILURE
 * * PSA_ERROR_HARDWARE_FAILURE
 * * PSA_ERROR_CORRUPTION_DETECTED
 * * PSA_ERROR_BAD_STATE:
 *	The library has not been previously initialized by psa_crypto_init(). It is
 *	implementation-dependent whether a failure to initialize results in this error code.
 */
psa_status_t psa_aead_abort(psa_aead_operation_t *operation);

/**
 * psa_aead_decrypt() - Process an authenticated decryption operation.
 * @key: Identifier of the key to use for the operation. It must allow the usage
 *       PSA_KEY_USAGE_DECRYPT.
 * @alg: The AEAD algorithm to compute (PSA_ALG_XXX value such that PSA_ALG_IS_AEAD(alg) is true).
 * @nonce: Nonce or IV to use.
 * @nonce_length: Size of the @nonce buffer in bytes. This must be appropriate for the selected
 *                algorithm. The default nonce size is PSA_AEAD_NONCE_LENGTH(key_type, alg) where
 *                key_type is the type of @key.
 * @additional_data: Additional data that has been authenticated but not encrypted.
 * @additional_data_length: Size of @additional_data in bytes.
 * @ciphertext: Data that has been authenticated and encrypted. For algorithms where the encrypted
 *              data and the authentication tag are defined as separate inputs, the buffer must
 *              contain the encrypted data followed by the authentication tag.
 * @ciphertext_length: Size of ciphertext in bytes.
 * @plaintext: Output buffer for the decrypted data.
 * @plaintext_size: Size of the @plaintext buffer in bytes.
 * @plaintext_length: On success, the size of the output in the plaintext buffer.
 *
 * **Warning: Not supported**
 *
 * Parameter @plaintext_size must be appropriate for the selected algorithm and key\:
 *
 * - A sufficient output size is PSA_AEAD_DECRYPT_OUTPUT_SIZE(key_type, alg, ciphertext_length)
 *   where key_type is the type of @key.
 * - PSA_AEAD_DECRYPT_OUTPUT_MAX_SIZE(ciphertext_length) evaluates to the maximum plaintext size of
 *   any supported AEAD decryption.
 *
 * Return:
 * * PSA_SUCCESS:
 *	Success.
 * * PSA_ERROR_INVALID_HANDLE
 * * PSA_ERROR_INVALID_SIGNATURE:
 *	The ciphertext is not authentic.
 * * PSA_ERROR_NOT_PERMITTED:
 *	The key does not have the PSA_KEY_USAGE_DECRYPT flag, or it does not permit the requested
 *	algorithm.
 * * PSA_ERROR_INVALID_ARGUMENT:
 *	@key is not compatible with @alg.
 * * PSA_ERROR_NOT_SUPPORTED:
 *	@alg is not supported or is not an AEAD algorithm.
 * * PSA_ERROR_INSUFFICIENT_MEMORY
 * * PSA_ERROR_BUFFER_TOO_SMALL:
 *	@plaintext_size is too small. PSA_AEAD_DECRYPT_OUTPUT_SIZE() or
 *	PSA_AEAD_DECRYPT_OUTPUT_MAX_SIZE() can be used to determine the required buffer size.
 * * PSA_ERROR_COMMUNICATION_FAILURE
 * * PSA_ERROR_HARDWARE_FAILURE
 * * PSA_ERROR_CORRUPTION_DETECTED
 * * PSA_ERROR_STORAGE_FAILURE
 * * PSA_ERROR_DATA_CORRUPT
 * * PSA_ERROR_DATA_INVALID
 * * PSA_ERROR_BAD_STATE:
 *	The library has not been previously initialized by psa_crypto_init(). It is
 *	implementation-dependent whether a failure to initialize results in this error code.
 */
psa_status_t psa_aead_decrypt(psa_key_id_t key, psa_algorithm_t alg,
			      const uint8_t *nonce, size_t nonce_length,
			      const uint8_t *additional_data,
			      size_t additional_data_length,
			      const uint8_t *ciphertext,
			      size_t ciphertext_length, uint8_t *plaintext,
			      size_t plaintext_size, size_t *plaintext_length);

/**
 * psa_aead_decrypt_setup() - Set the key for a multi-part authenticated decryption operation.
 * @operation: The operation object to set up. It must have been initialized as per the
 *             documentation for &typedef psa_aead_operation_t and not yet in use.
 * @key: Identifier of the key to use for the operation. It must remain valid until the operation
 *       terminates. It must allow the usage PSA_KEY_USAGE_DECRYPT.
 * @alg: The AEAD algorithm to compute (PSA_ALG_XXX value such that PSA_ALG_IS_AEAD(alg) is true).
 *
 * **Warning: Not supported**
 *
 * The sequence of operations to decrypt a message with authentication is as follows\:
 *
 * #. Allocate an operation object which will be passed to all the functions listed here.
 *
 * #. Initialize the operation object with one of the methods described in the documentation for
 *    &typedef psa_aead_operation_t, e.g. PSA_AEAD_OPERATION_INIT.
 *
 * #. Call psa_aead_decrypt_setup() to specify the algorithm and key.
 *
 * #. If needed, call psa_aead_set_lengths() to specify the length of the inputs to the subsequent
 *    calls to psa_aead_update_ad() and psa_aead_update(). See the documentation of
 *    psa_aead_set_lengths() for details.
 *
 * #. Call psa_aead_set_nonce() with the nonce for the decryption.
 *
 * #. Call psa_aead_update_ad() zero, one or more times, passing a fragment of the non-encrypted
 *    additional authenticated data each time.
 *
 * #. Call psa_aead_update() zero, one or more times, passing a fragment of the ciphertext to
 *    decrypt each time.
 *
 * #. Call psa_aead_verify().
 *
 * If an error occurs at any step after a call to psa_aead_decrypt_setup(), the operation will need
 * to be reset by a call to psa_aead_abort(). The application can call psa_aead_abort() at any time
 * after the operation has been initialized.
 *
 * After a successful call to psa_aead_decrypt_setup(), the application must eventually terminate
 * the operation. The following events terminate an operation\:
 *
 * - A successful call to psa_aead_verify().
 *
 * - A call to psa_aead_abort().
 *
 * Return:
 * * PSA_SUCCESS:
 *	Success.
 * * PSA_ERROR_BAD_STATE:
 *	The operation state is not valid: it must be inactive.
 * * PSA_ERROR_INVALID_HANDLE
 * * PSA_ERROR_NOT_PERMITTED:
 *	The key does not have the PSA_KEY_USAGE_DECRYPT flag, or it does not permit the requested
 *	algorithm.
 * * PSA_ERROR_INVALID_ARGUMENT:
 *	@key is not compatible with @alg.
 * * PSA_ERROR_NOT_SUPPORTED:
 *	@alg is not supported or is not an AEAD algorithm.
 * * PSA_ERROR_INSUFFICIENT_MEMORY
 * * PSA_ERROR_COMMUNICATION_FAILURE
 * * PSA_ERROR_HARDWARE_FAILURE
 * * PSA_ERROR_CORRUPTION_DETECTED
 * * PSA_ERROR_STORAGE_FAILURE
 * * PSA_ERROR_DATA_CORRUPT
 * * PSA_ERROR_DATA_INVALID
 * * PSA_ERROR_BAD_STATE:
 *	The library has not been previously initialized by psa_crypto_init(). It is
 *	implementation-dependent whether a failure to initialize results in this error code.
 */
psa_status_t psa_aead_decrypt_setup(psa_aead_operation_t *operation,
				    psa_key_id_t key, psa_algorithm_t alg);

/**
 * psa_aead_encrypt() - Process an authenticated encryption operation.
 * @key: Identifier of the key to use for the operation. It must allow the usage
 *       PSA_KEY_USAGE_ENCRYPT.
 * @alg: The AEAD algorithm to compute (PSA_ALG_XXX value such that PSA_ALG_IS_AEAD(alg) is true).
 * @nonce: Nonce or IV to use.
 * @nonce_length: Size of the @nonce buffer in bytes. This must be appropriate for the selected
 *                algorithm. The default nonce size is PSA_AEAD_NONCE_LENGTH(key_type, alg) where
 *                key_type is the type of @key.
 * @additional_data: Additional data that will be authenticated but not encrypted.
 * @additional_data_length: Size of @additional_data in bytes.
 * @plaintext: Data that will be authenticated and encrypted.
 * @plaintext_length: Size of plaintext in bytes.
 * @ciphertext: Output buffer for the authenticated and encrypted data. The additional data is not
 *              part of this output. For algorithms where the encrypted data and the authentication
 *              tag are defined as separate outputs, the authentication tag is appended to the
 *              encrypted data.
 * @ciphertext_size: Size of the @ciphertext buffer in bytes.
 * @ciphertext_length: On success, the size of the output in the ciphertext buffer.
 *
 * **Warning: Not supported**
 *
 * Parameter @ciphertext_size must be appropriate for the selected algorithm and key\:
 *
 * - A sufficient output size is PSA_AEAD_ENCRYPT_OUTPUT_SIZE(key_type, alg, plaintext_length)
 *   where key_type is the type of @key.
 *
 * - PSA_AEAD_ENCRYPT_OUTPUT_MAX_SIZE(plaintext_length) evaluates to the maximum ciphertext size of
 *   any supported AEAD encryption.
 *
 * Return:
 * * PSA_SUCCESS:
 *	Success.
 * * PSA_ERROR_INVALID_HANDLE
 * * PSA_ERROR_NOT_PERMITTED:
 *	The key does not have the PSA_KEY_USAGE_ENCRYPT flag, or it does not permit the requested
 *	algorithm.
 * * PSA_ERROR_INVALID_ARGUMENT:
 *	@key is not compatible with @alg.
 * * PSA_ERROR_NOT_SUPPORTED:
 *	@alg is not supported or is not an AEAD algorithm.
 * * PSA_ERROR_INSUFFICIENT_MEMORY
 * * PSA_ERROR_BUFFER_TOO_SMALL:
 *	@ciphertext_size is too small. PSA_AEAD_ENCRYPT_OUTPUT_SIZE() or
 *	PSA_AEAD_ENCRYPT_OUTPUT_MAX_SIZE() can be used to determine the required buffer size.
 * * PSA_ERROR_COMMUNICATION_FAILURE
 * * PSA_ERROR_HARDWARE_FAILURE
 * * PSA_ERROR_CORRUPTION_DETECTED
 * * PSA_ERROR_STORAGE_FAILURE
 * * PSA_ERROR_DATA_CORRUPT
 * * PSA_ERROR_DATA_INVALID
 * * PSA_ERROR_BAD_STATE:
 *	The library has not been previously initialized by psa_crypto_init(). It is
 *	implementation-dependent whether a failure to initialize results in this error code.
 */
psa_status_t psa_aead_encrypt(psa_key_id_t key, psa_algorithm_t alg,
			      const uint8_t *nonce, size_t nonce_length,
			      const uint8_t *additional_data,
			      size_t additional_data_length,
			      const uint8_t *plaintext, size_t plaintext_length,
			      uint8_t *ciphertext, size_t ciphertext_size,
			      size_t *ciphertext_length);

/**
 * psa_aead_encrypt_setup() - Set the key for a multi-part authenticated encryption operation.
 * @operation: The operation object to set up. It must have been initialized as per the
 *             documentation for &typedef psa_aead_operation_t and not yet in use.
 * @key: Identifier of the key to use for the operation. It must remain valid until the operation
 *       terminates. It must allow the usage PSA_KEY_USAGE_ENCRYPT.
 * @alg: The AEAD algorithm to compute (PSA_ALG_XXX value such that PSA_ALG_IS_AEAD(alg) is true).
 *
 * **Warning: Not supported**
 *
 * The sequence of operations to encrypt a message with authentication is as follows\:
 *
 * - Allocate an operation object which will be passed to all the functions listed here.
 *
 * - Initialize the operation object with one of the methods described in the documentation for
 *   &typedef psa_aead_operation_t, e.g. PSA_AEAD_OPERATION_INIT.
 *
 * - Call psa_aead_encrypt_setup() to specify the algorithm and key.
 *
 * - If needed, call psa_aead_set_lengths() to specify the length of the inputs to the subsequent
 *   calls to psa_aead_update_ad() and psa_aead_update(). See the documentation of
 *   psa_aead_set_lengths() for details.
 *
 * - Call either psa_aead_generate_nonce() or psa_aead_set_nonce() to generate or set the nonce. It
 *   is recommended to use psa_aead_generate_nonce() unless the protocol being implemented requires
 *   a specific nonce value.
 *
 * - Call psa_aead_update_ad() zero, one or more times, passing a fragment of the non-encrypted
 *   additional authenticated data each time.
 *
 * - Call psa_aead_update() zero, one or more times, passing a fragment of the message to encrypt
 *   each time.
 *
 * - Call psa_aead_finish().
 *
 * If an error occurs at any step after a call to psa_aead_encrypt_setup(), the operation will need
 * to be reset by a call to psa_aead_abort(). The application can call psa_aead_abort() at any time
 * after the operation has been initialized.
 *
 * After a successful call to psa_aead_encrypt_setup(), the application must eventually terminate
 * the operation. The following events terminate an operation\:
 *
 * - A successful call to psa_aead_finish().
 *
 * - A call to psa_aead_abort().
 *
 * Return:
 * * PSA_SUCCESS:
 *	Success.
 * * PSA_ERROR_BAD_STATE:
 *	The operation state is not valid: it must be inactive.
 * * PSA_ERROR_INVALID_HANDLE
 * * PSA_ERROR_NOT_PERMITTED:
 *	The key does not have the PSA_KEY_USAGE_ENCRYPT flag, or it does not permit the requested
 *	algorithm.
 * * PSA_ERROR_INVALID_ARGUMENT:
 *	@key is not compatible with @alg.
 * * PSA_ERROR_NOT_SUPPORTED:
 *	@alg is not supported or is not an AEAD algorithm.
 * * PSA_ERROR_INSUFFICIENT_MEMORY
 * * PSA_ERROR_COMMUNICATION_FAILURE
 * * PSA_ERROR_HARDWARE_FAILURE
 * * PSA_ERROR_CORRUPTION_DETECTED
 * * PSA_ERROR_STORAGE_FAILURE
 * * PSA_ERROR_DATA_CORRUPT
 * * PSA_ERROR_DATA_INVALID
 * * PSA_ERROR_BAD_STATE:
 *	The library has not been previously initialized by psa_crypto_init(). It is
 *	implementation-dependent whether a failure to initialize results in this error code.
 */
psa_status_t psa_aead_encrypt_setup(psa_aead_operation_t *operation,
				    psa_key_id_t key, psa_algorithm_t alg);

/**
 * psa_aead_finish() - Finish encrypting a message in an AEAD operation.
 * @operation: Active AEAD operation.
 * @ciphertext: Buffer where the last part of the ciphertext is to be written.
 * @ciphertext_size: Size of the @ciphertext buffer in bytes.
 * @ciphertext_length: On success, the number of bytes of returned ciphertext.
 * @tag: Buffer where the authentication tag is to be written.
 * @tag_size: Size of the @tag buffer in bytes.
 * @tag_length: On success, the number of bytes that make up the returned tag.
 *
 * **Warning: Not supported**
 *
 * The operation must have been set up with psa_aead_encrypt_setup().
 *
 * This function finishes the authentication of the additional data formed by concatenating the
 * inputs passed to preceding calls to psa_aead_update_ad() with the plaintext formed by
 * concatenating the inputs passed to preceding calls to psa_aead_update().
 *
 * This function has two output buffers\:
 *
 * - @ciphertext contains trailing ciphertext that was buffered from preceding calls to
 *   psa_aead_update().
 *
 * - @tag contains the authentication tag.
 *
 * When this function returns successfully, the operation becomes inactive. If this function returns
 * an error status, the operation enters an error state and must be aborted by calling
 * psa_aead_abort().
 *
 * Parameter @ciphertext_size must be appropriate for the selected algorithm and key\:
 *
 * - A sufficient output size is PSA_AEAD_FINISH_OUTPUT_SIZE(key_type, alg) where key_type is the
 *   type of key and alg is the algorithm that were used to set up the operation.
 *
 * - PSA_AEAD_FINISH_OUTPUT_MAX_SIZE evaluates to the maximum output size of any supported AEAD
 *   algorithm.
 *
 * Parameter @tag_size must be appropriate for the selected algorithm and key\:
 *
 * - The exact tag size is PSA_AEAD_TAG_LENGTH(key_type, key_bits, alg) where key_type and key_bits
 *   are the type and bit-size of the key, and alg is the algorithm that were used in the call to
 *   psa_aead_encrypt_setup().
 *
 * - PSA_AEAD_TAG_MAX_SIZE evaluates to the maximum tag size of any supported AEAD algorithm.
 *
 * Return:
 * * PSA_SUCCESS:
 *	Success.
 * * PSA_ERROR_BAD_STATE
 *	The operation state is not valid: it must be an active encryption operation with a nonce
 *	set.
 * * PSA_ERROR_BUFFER_TOO_SMALL
 *	The size of the @ciphertext or @tag buffer is too small. PSA_AEAD_FINISH_OUTPUT_SIZE() or
 *	PSA_AEAD_FINISH_OUTPUT_MAX_SIZE can be used to determine the required ciphertext buffer
 *	size. PSA_AEAD_TAG_LENGTH() or PSA_AEAD_TAG_MAX_SIZE can be used to determine the required
 *	@tag buffer size.
 * * PSA_ERROR_INVALID_ARGUMENT
 *	The total length of input to psa_aead_update_ad() so far is less than the additional data
 *	length that was previously specified with psa_aead_set_lengths().
 * * PSA_ERROR_INVALID_ARGUMENT
 *	The total length of input to psa_aead_update() so far is less than the plaintext length that
 *	was previously specified with psa_aead_set_lengths().
 * * PSA_ERROR_INSUFFICIENT_MEMORY
 * * PSA_ERROR_COMMUNICATION_FAILURE
 * * PSA_ERROR_HARDWARE_FAILURE
 * * PSA_ERROR_CORRUPTION_DETECTED
 * * PSA_ERROR_STORAGE_FAILURE
 * * PSA_ERROR_DATA_CORRUPT
 * * PSA_ERROR_DATA_INVALID
 * * PSA_ERROR_BAD_STATE
 *	The library has not been previously initialized by psa_crypto_init(). It is
 *	implementation-dependent whether a failure to initialize results in this error code.
 */
psa_status_t psa_aead_finish(psa_aead_operation_t *operation,
			     uint8_t *ciphertext, size_t ciphertext_size,
			     size_t *ciphertext_length, uint8_t *tag,
			     size_t tag_size, size_t *tag_length);

/**
 * psa_aead_generate_nonce() - Generate a random nonce for an authenticated encryption operation.
 * @operation: Active AEAD operation.
 * @nonce: Buffer where the generated nonce is to be written.
 * @nonce_size: Size of the @nonce buffer in bytes. This must be at least
 *              PSA_AEAD_NONCE_LENGTH(key_type, alg) where key_type and alg are type of key and the
 *              algorithm respectively that were used to set up the AEAD operation.
 * @nonce_length: On success, the number of bytes of the generated nonce.
 *
 * **Warning: Not supported**
 *
 * This function generates a random nonce for the authenticated encryption operation with an
 * appropriate size for the chosen algorithm, key type and key size.
 *
 * The application must call psa_aead_encrypt_setup() before calling this function. If applicable
 * for the algorithm, the application must call psa_aead_set_lengths() before calling this function.
 *
 * If this function returns an error status, the operation enters an error state and must be aborted
 * by calling psa_aead_abort().
 *
 * Return:
 * * PSA_SUCCESS:
 *	Success.
 * * PSA_ERROR_BAD_STATE:
 *	The operation state is not valid: it must be an active AEAD encryption operation, with no
 *	nonce set.
 * * PSA_ERROR_BAD_STATE:
 *	The operation state is not valid: this is an algorithm which requires psa_aead_set_lengths()
 *	to be called before setting the nonce.
 * * PSA_ERROR_BUFFER_TOO_SMALL:
 *	The size of the @nonce buffer is too small. PSA_AEAD_NONCE_LENGTH() or
 *	PSA_AEAD_NONCE_MAX_SIZE can be used to determine the required buffer size.
 * * PSA_ERROR_INSUFFICIENT_MEMORY
 * * PSA_ERROR_COMMUNICATION_FAILURE
 * * PSA_ERROR_HARDWARE_FAILURE
 * * PSA_ERROR_CORRUPTION_DETECTED
 * * PSA_ERROR_STORAGE_FAILURE
 * * PSA_ERROR_DATA_CORRUPT
 * * PSA_ERROR_DATA_INVALID
 * * PSA_ERROR_BAD_STATE:
 *	The library has not been previously initialized by psa_crypto_init(). It is
 *	implementation-dependent whether a failure to initialize results in this error code.
 */
psa_status_t psa_aead_generate_nonce(psa_aead_operation_t *operation,
				     uint8_t *nonce, size_t nonce_size,
				     size_t *nonce_length);

/**
 * psa_aead_operation_init() - Return an initial value for an AEAD operation object.
 *
 * **Warning: Not supported**
 *
 * Return:
 * &typedef psa_aead_operation_t
 */
static psa_aead_operation_t psa_aead_operation_init(void);

/**
 * psa_aead_set_lengths() - Declare the lengths of the message and additional data for AEAD.
 * @operation: Active AEAD operation.
 * @ad_length: Size of the non-encrypted additional authenticated data in bytes.
 * @plaintext_length: Size of the plaintext to encrypt in bytes.
 *
 * **Warning: Not supported**
 *
 * The application must call this function before calling psa_aead_set_nonce() or
 * psa_aead_generate_nonce(), if the algorithm for the operation requires it. If the algorithm does
 * not require it, calling this function is optional, but if this function is called then the
 * implementation must enforce the lengths.
 *
 * - For PSA_ALG_CCM, calling this function is required.
 *
 * - For the other AEAD algorithms defined in this specification, calling this function is not
 *   required.
 *
 * - For vendor-defined algorithm, refer to the vendor documentation.
 *
 * If this function returns an error status, the operation enters an error state and must be aborted
 * by calling psa_aead_abort().
 *
 * Return:
 * * PSA_SUCCESS:
 *	Success.
 * * PSA_ERROR_BAD_STATE:
 *	The operation state is not valid: it must be active, and psa_aead_set_nonce() and
 *	psa_aead_generate_nonce() must not have been called yet.
 * * PSA_ERROR_INVALID_ARGUMENT:
 *	At least one of the lengths is not acceptable for the chosen algorithm.
 * * PSA_ERROR_INSUFFICIENT_MEMORY
 * * PSA_ERROR_COMMUNICATION_FAILURE
 * * PSA_ERROR_HARDWARE_FAILURE
 * * PSA_ERROR_CORRUPTION_DETECTED
 * * PSA_ERROR_BAD_STATE:
 *	The library has not been previously initialized by psa_crypto_init(). It is
 *	implementation-dependent whether a failure to initialize results in this error code.
 */
psa_status_t psa_aead_set_lengths(psa_aead_operation_t *operation,
				  size_t ad_length, size_t plaintext_length);

/**
 * psa_aead_set_nonce() - Set the nonce for an authenticated encryption or decryption operation.
 * @operation: Active AEAD operation.
 * @nonce: Buffer containing the nonce to use.
 * @nonce_length: Size of the nonce in bytes. This must be a valid nonce size for the chosen
 *                algorithm. The default nonce size is PSA_AEAD_NONCE_LENGTH(key_type, alg) where
 *                key_type and alg are type of key and the algorithm respectively that were used to
 *                set up the AEAD operation.
 *
 * This function sets the nonce for the authenticated encryption or decryption operation.
 *
 * **Warning: Not supported**
 *
 * The application must call psa_aead_encrypt_setup() or psa_aead_decrypt_setup() before calling
 * this function. If applicable for the algorithm, the application must call psa_aead_set_lengths()
 * before calling this function.
 *
 * If this function returns an error status, the operation enters an error state and must be aborted
 * by calling psa_aead_abort().
 *
 * **Note**:
 *	When encrypting, psa_aead_generate_nonce() is recommended instead of using this function,
 *	unless implementing a protocol that requires a non-random IV.
 *
 * Return:
 * * PSA_SUCCESS:
 *	Success.
 * * PSA_ERROR_BAD_STATE:
 *	The operation state is not valid: it must be active, with no nonce set.
 * * PSA_ERROR_BAD_STATE:
 *	The operation state is not valid: this is an algorithm which requires psa_aead_set_lengths()
 *	to be called before setting the nonce.
 * * PSA_ERROR_INVALID_ARGUMENT:
 *	The size of nonce is not acceptable for the chosen algorithm.
 * * PSA_ERROR_INSUFFICIENT_MEMORY
 * * PSA_ERROR_COMMUNICATION_FAILURE
 * * PSA_ERROR_HARDWARE_FAILURE
 * * PSA_ERROR_CORRUPTION_DETECTED
 * * PSA_ERROR_STORAGE_FAILURE
 * * PSA_ERROR_DATA_CORRUPT
 * * PSA_ERROR_DATA_INVALID
 * * PSA_ERROR_BAD_STATE:
 *	The library has not been previously initialized by psa_crypto_init(). It is
 *	implementation-dependent whether a failure to initialize results in this error code.
 */
psa_status_t psa_aead_set_nonce(psa_aead_operation_t *operation,
				const uint8_t *nonce, size_t nonce_length);

/**
 * psa_aead_update() - Encrypt or decrypt a message fragment in an active AEAD operation.
 * @operation: Active AEAD operation.
 * @input: Buffer containing the message fragment to encrypt or decrypt.
 * @input_length: Size of the @input buffer in bytes.
 * @output: Buffer where the output is to be written.
 * @output_size: Size of the @output buffer in bytes.
 * @output_length: On success, the number of bytes that make up the returned output.
 *
 * **Warning: Not supported**
 *
 * The following must occur before calling this function\:
 *
 * - Call either psa_aead_encrypt_setup() or psa_aead_decrypt_setup(). The choice of setup function
 *   determines whether this function encrypts or decrypts its input.
 *
 * - Set the nonce with psa_aead_generate_nonce() or psa_aead_set_nonce().
 *
 * - Call psa_aead_update_ad() to pass all the additional data.
 *
 * If this function returns an error status, the operation enters an error state and must be aborted
 * by calling psa_aead_abort().
 *
 * This function does not require the input to be aligned to any particular block boundary. If the
 * implementation can only process a whole block at a time, it must consume all the input provided,
 * but it might delay the end of the corresponding output until a subsequent call to
 * psa_aead_update(), psa_aead_finish() or psa_aead_verify() provides sufficient input. The amount
 * of data that can be delayed in this way is bounded by PSA_AEAD_UPDATE_OUTPUT_SIZE().
 *
 * Parameter @output_size must be appropriate for the selected algorithm and key\:
 *
 * - A sufficient output size is PSA_AEAD_UPDATE_OUTPUT_SIZE(key_type, alg, input_length) where
 *   key_type is the type of @key and alg is the algorithm that were used to set up the operation.
 *
 * - PSA_AEAD_UPDATE_OUTPUT_MAX_SIZE(input_length) evaluates to the maximum output size of any
 *   supported AEAD algorithm.
 *
 * Return:
 * * PSA_SUCCESS:
 *	Success.
 *
 *	**Warning**:
 *		When decrypting, do not use the output until psa_aead_verify() succeeds.
 *
 *		See the detailed warning.
 * * PSA_ERROR_BAD_STATE:
 *	The operation state is not valid: it must be active, have a nonce set, and have lengths set
 *	if required by the algorithm.
 * * PSA_ERROR_BUFFER_TOO_SMALL:
 *	The size of the @output buffer is too small. PSA_AEAD_UPDATE_OUTPUT_SIZE() or
 *	PSA_AEAD_UPDATE_OUTPUT_MAX_SIZE() can be used to determine the required buffer size.
 * * PSA_ERROR_INVALID_ARGUMENT:
 *	The total length of @input to psa_aead_update_ad() so far is less than the additional data
 *	length that was previously specified with psa_aead_set_lengths().
 * * PSA_ERROR_INVALID_ARGUMENT:
 *	The total input length overflows the plaintext length that was previously specified with
 *	psa_aead_set_lengths().
 * * PSA_ERROR_INSUFFICIENT_MEMORY
 * * PSA_ERROR_COMMUNICATION_FAILURE
 * * PSA_ERROR_HARDWARE_FAILURE
 * * PSA_ERROR_CORRUPTION_DETECTED
 * * PSA_ERROR_STORAGE_FAILURE
 * * PSA_ERROR_DATA_CORRUPT
 * * PSA_ERROR_DATA_INVALID
 * * PSA_ERROR_BAD_STATE:
 *	The library has not been previously initialized by psa_crypto_init(). It is
 *	implementation-dependent whether a failure to initialize results in this error code.
 */
psa_status_t psa_aead_update(psa_aead_operation_t *operation,
			     const uint8_t *input, size_t input_length,
			     uint8_t *output, size_t output_size,
			     size_t *output_length);

/**
 * psa_aead_update_ad() - Pass additional data to an active AEAD operation.
 * @operation: Active AEAD operation.
 * @input: Buffer containing the fragment of additional data.
 * @input_length:S ize of the @input buffer in bytes.
 *
 * **Warning: Not supported**
 *
 * Additional data is authenticated, but not encrypted.
 *
 * This function can be called multiple times to pass successive fragments of the additional data.
 * This function must not be called after passing data to encrypt or decrypt with psa_aead_update().
 *
 * The following must occur before calling this function:
 *
 * - Call either psa_aead_encrypt_setup() or psa_aead_decrypt_setup().
 *
 * - Set the nonce with psa_aead_generate_nonce() or psa_aead_set_nonce().
 *
 * If this function returns an error status, the operation enters an error state and must be aborted
 * by calling psa_aead_abort().
 *
 * Return:
 * * PSA_SUCCESS:
 *	Success.
 *
 *	**Warning**:
 *		When decrypting, do not trust the input until psa_aead_verify() succeeds.
 *
 *		See the detailed warning.
 * * PSA_ERROR_BAD_STATE:
 *	The operation state is not valid: it must be active, have a nonce set, have lengths set if
 *	required by the algorithm, and psa_aead_update() must not have been called yet.
 * * PSA_ERROR_INVALID_ARGUMENT:
 *	The total input length overflows the additional data length that was previously specified
 *	with psa_aead_set_lengths().
 * * PSA_ERROR_INSUFFICIENT_MEMORY
 * * PSA_ERROR_COMMUNICATION_FAILURE
 * * PSA_ERROR_HARDWARE_FAILURE
 * * PSA_ERROR_CORRUPTION_DETECTED
 * * PSA_ERROR_STORAGE_FAILURE
 * * PSA_ERROR_DATA_CORRUPT
 * * PSA_ERROR_DATA_INVALID
 * * PSA_ERROR_BAD_STATE:
 *	The library has not been previously initialized by psa_crypto_init(). It is
 *	implementation-dependent whether a failure to initialize results in this error code.
 */
psa_status_t psa_aead_update_ad(psa_aead_operation_t *operation,
				const uint8_t *input, size_t input_length);

/**
 * psa_aead_verify() - Finish authenticating and decrypting a message in an AEAD operation.
 * @operation: Active AEAD operation.
 * @plaintext: Buffer where the last part of the plaintext is to be written. This is the remaining
 *             data from previous calls to psa_aead_update() that could not be processed until the
 *             end of the input.
 * @plaintext_size: Size of the @plaintext buffer in bytes.
 * @plaintext_length: On success, the number of bytes of returned plaintext.
 * @tag: Buffer containing the authentication tag.
 * @tag_length: Size of the @tag buffer in bytes.
 *
 * **Warning: Not supported**
 *
 * The operation must have been set up with psa_aead_decrypt_setup().
 *
 * This function finishes the authenticated decryption of the message components\:
 *
 * - The additional data consisting of the concatenation of the inputs passed to preceding calls to
 *   psa_aead_update_ad().
 *
 * - The ciphertext consisting of the concatenation of the inputs passed to preceding calls to
 *   psa_aead_update().
 *
 * - The tag passed to this function call.
 *
 * If the authentication tag is correct, this function outputs any remaining plaintext and reports
 * success. If the authentication tag is not correct, this function returns
 * PSA_ERROR_INVALID_SIGNATURE.
 *
 * When this function returns successfully, the operation becomes inactive. If this function returns
 * an error status, the operation enters an error state and must be aborted by calling
 * psa_aead_abort().
 *
 * **Note**:
 *	Implementations must make the best effort to ensure that the comparison between the actual
 *	tag and the expected tag is performed in constant time.
 *
 * Parameter @plaintext_size must be appropriate for the selected algorithm and key\:
 *
 * - A sufficient output size is PSA_AEAD_VERIFY_OUTPUT_SIZE(key_type, alg) where key_type is the
 *   type of key and alg is the algorithm that were used to set up the operation.
 *
 * - PSA_AEAD_VERIFY_OUTPUT_MAX_SIZE evaluates to the maximum output size of any supported AEAD
 *   algorithm.
 *
 * Return:
 * * PSA_SUCCESS:
 *	Success.
 * * PSA_ERROR_INVALID_SIGNATURE:
 *	The calculations were successful, but the authentication tag is not correct.
 * * PSA_ERROR_BAD_STATE:
 *	The operation state is not valid: it must be an active decryption operation with a nonce
 *	set.
 * * PSA_ERROR_BUFFER_TOO_SMALL:
 *	The size of the @plaintext buffer is too small. PSA_AEAD_VERIFY_OUTPUT_SIZE() or
 *	PSA_AEAD_VERIFY_OUTPUT_MAX_SIZE can be used to determine the required buffer size.
 * * PSA_ERROR_INVALID_ARGUMENT:
 *	The total length of input to psa_aead_update_ad() so far is less than the additional data
 *	length that was previously specified with psa_aead_set_lengths().
 * * PSA_ERROR_INVALID_ARGUMENT:
 *	The total length of input to psa_aead_update() so far is less than the plaintext length that
 *	was previously specified with psa_aead_set_lengths().
 * * PSA_ERROR_INSUFFICIENT_MEMORY
 * * PSA_ERROR_COMMUNICATION_FAILURE
 * * PSA_ERROR_HARDWARE_FAILURE
 * * PSA_ERROR_CORRUPTION_DETECTED
 * * PSA_ERROR_STORAGE_FAILURE
 * * PSA_ERROR_DATA_CORRUPT
 * * PSA_ERROR_DATA_INVALID
 * * PSA_ERROR_BAD_STATE:
 *	The library has not been previously initialized by psa_crypto_init(). It is
 *	implementation-dependent whether a failure to initialize results in this error code.
 */
psa_status_t psa_aead_verify(psa_aead_operation_t *operation,
			     uint8_t *plaintext, size_t plaintext_size,
			     size_t *plaintext_length, const uint8_t *tag,
			     size_t tag_length);

/**
 * psa_asymmetric_decrypt() - Decrypt a short message with a private key.
 *
 * @key: Identifier of the key to use for the operation. It must be an asymmetric key pair. It must
 *       allow the usage PSA_KEY_USAGE_DECRYPT.
 * @alg: An asymmetric encryption algorithm that is compatible with the type of key.
 * @input: The message to decrypt.
 * @input_length: Size of the @input buffer in bytes.
 * @salt: A salt or label, if supported by the encryption algorithm. If the algorithm does not
 *        support a salt, pass NULL. If the algorithm supports an optional salt, pass NULL to
 *        indicate that there is no salt.
 * @salt_length: Size of the @salt buffer in bytes. If @salt is NULL, pass 0.
 * @output: Buffer where the decrypted message is to be written.
 * @output_size: Size of the @output buffer in bytes.
 * @output_length: On success, the number of bytes that make up the returned output.
 *
 * **Warning: Not supported**
 *
 * For PSA_ALG_RSA_PKCS1V15_CRYPT, no salt is supported.
 *
 * Parameter @output_size must be appropriate for the selected algorithm and key\:
 *
 * - The required output size is PSA_ASYMMETRIC_DECRYPT_OUTPUT_SIZE(key_type, key_bits, alg) where
 *   key_type and key_bits are the type and bit-size respectively of @key.
 *
 * - PSA_ASYMMETRIC_DECRYPT_OUTPUT_MAX_SIZE evaluates to the maximum output size of any supported
 *   asymmetric decryption.
 *
 * Return:
 * * PSA_SUCCESS
 * * PSA_ERROR_INVALID_HANDLE
 * * PSA_ERROR_NOT_PERMITTED:
 *	The key does not have the PSA_KEY_USAGE_DECRYPT flag, or it does not permit the requested
 *	algorithm.
 * * PSA_ERROR_BUFFER_TOO_SMALL:
 *	The size of the @output buffer is too small. PSA_ASYMMETRIC_DECRYPT_OUTPUT_SIZE() or
 *	PSA_ASYMMETRIC_DECRYPT_OUTPUT_MAX_SIZE can be used to determine the required buffer size.
 * * PSA_ERROR_NOT_SUPPORTED
 * * PSA_ERROR_INVALID_ARGUMENT
 * * PSA_ERROR_INSUFFICIENT_MEMORY
 * * PSA_ERROR_COMMUNICATION_FAILURE
 * * PSA_ERROR_HARDWARE_FAILURE
 * * PSA_ERROR_CORRUPTION_DETECTED
 * * PSA_ERROR_STORAGE_FAILURE
 * * PSA_ERROR_DATA_CORRUPT
 * * PSA_ERROR_DATA_INVALID
 * * PSA_ERROR_INSUFFICIENT_ENTROPY
 * * PSA_ERROR_INVALID_PADDING
 * * PSA_ERROR_BAD_STATE:
 *	The library has not been previously initialized by psa_crypto_init(). It is
 *	implementation-dependent whether a failure to initialize results in this error code.
 */
psa_status_t psa_asymmetric_decrypt(psa_key_id_t key, psa_algorithm_t alg,
				    const uint8_t *input, size_t input_length,
				    const uint8_t *salt, size_t salt_length,
				    uint8_t *output, size_t output_size,
				    size_t *output_length);

/**
 * psa_asymmetric_encrypt() - Encrypt a short message with a public key.
 * @key: Identifer of the key to use for the operation. It must be a public key or an asymmetric key
 *       pair. It must allow the usage PSA_KEY_USAGE_ENCRYPT.
 * @alg: An asymmetric encryption algorithm that is compatible with the type of key.
 * @input: The message to encrypt.
 * @input_length: Size of the @input buffer in bytes.
 * @salt: A salt or label, if supported by the encryption algorithm. If the algorithm does not
 *        support a salt, pass NULL. If the algorithm supports an optional salt, pass NULL to
 *        indicate that there is no salt.
 * @salt_length: Size of the @salt buffer in bytes. If salt is NULL, pass 0.
 * @output: Buffer where the encrypted message is to be written.
 * @output_size: Size of the @output buffer in bytes.
 * @output_length: On success, the number of bytes that make up the returned output.
 *
 * **Warning: Not supported**
 *
 * For PSA_ALG_RSA_PKCS1V15_CRYPT, no salt is supported.
 *
 * Parameter @output_size must be appropriate for the selected algorithm and key\:
 *
 * - The required output size is PSA_ASYMMETRIC_ENCRYPT_OUTPUT_SIZE(key_type, key_bits, alg) where
 *   key_type and key_bits are the type and bit-size respectively of @key.
 *
 * - PSA_ASYMMETRIC_ENCRYPT_OUTPUT_MAX_SIZE evaluates to the maximum output size of any supported
 *   asymmetric encryption.
 *
 * Return:
 * * PSA_SUCCESS
 * * PSA_ERROR_INVALID_HANDLE
 * * PSA_ERROR_NOT_PERMITTED:
 *	The key does not have the PSA_KEY_USAGE_ENCRYPT flag, or it does not permit the requested
 *	algorithm.
 * * PSA_ERROR_BUFFER_TOO_SMALL:
 *	The size of the @output buffer is too small. PSA_ASYMMETRIC_ENCRYPT_OUTPUT_SIZE() or
 *	PSA_ASYMMETRIC_ENCRYPT_OUTPUT_MAX_SIZE can be used to determine the required buffer size.
 * * PSA_ERROR_NOT_SUPPORTED
 * * PSA_ERROR_INVALID_ARGUMENT
 * * PSA_ERROR_INSUFFICIENT_MEMORY
 * * PSA_ERROR_COMMUNICATION_FAILURE
 * * PSA_ERROR_HARDWARE_FAILURE
 * * PSA_ERROR_CORRUPTION_DETECTED
 * * PSA_ERROR_STORAGE_FAILURE
 * * PSA_ERROR_DATA_CORRUPT
 * * PSA_ERROR_DATA_INVALID
 * * PSA_ERROR_INSUFFICIENT_ENTROPY
 * * PSA_ERROR_BAD_STATE:
 *	The library has not been previously initialized by psa_crypto_init(). It is
 *	implementation-dependent whether a failure to initialize results in this error code.
 */
psa_status_t psa_asymmetric_encrypt(psa_key_id_t key, psa_algorithm_t alg,
				    const uint8_t *input, size_t input_length,
				    const uint8_t *salt, size_t salt_length,
				    uint8_t *output, size_t output_size,
				    size_t *output_length);

/**
 * psa_cipher_abort() - Abort a cipher operation.
 * @operation: Initialized cipher operation.
 *
 * **Warning: Not supported**
 *
 * Aborting an operation frees all associated resources except for the operation object itself. Once
 * aborted, the operation object can be reused for another operation by calling
 * psa_cipher_encrypt_setup() or psa_cipher_decrypt_setup() again.
 *
 * This function can be called any time after the operation object has been initialized as described
 * in &typedef psa_cipher_operation_t.
 *
 * In particular, calling psa_cipher_abort() after the operation has been terminated by a call to
 * psa_cipher_abort() or psa_cipher_finish() is safe and has no effect.
 *
 * Return:
 * * PSA_SUCCESS
 * * PSA_ERROR_COMMUNICATION_FAILURE
 * * PSA_ERROR_HARDWARE_FAILURE
 * * PSA_ERROR_CORRUPTION_DETECTED
 * * PSA_ERROR_BAD_STATE:
 *	The library has not been previously initialized by psa_crypto_init(). It is
 *	implementation-dependent whether a failure to initialize results in this error code.
 */
psa_status_t psa_cipher_abort(psa_cipher_operation_t *operation);

/**
 * psa_cipher_decrypt() - Decrypt a message using a symmetric cipher.
 * @key: Identifier of the key to use for the operation. It must remain valid until the operation
 *       terminates. It must allow the usage PSA_KEY_USAGE_DECRYPT.
 * @alg: The cipher algorithm to compute (PSA_ALG_XXX value such that PSA_ALG_IS_CIPHER(alg) is
 *       true).
 * @input: Buffer containing the message to decrypt. This consists of the IV followed by the
 *         ciphertext proper.
 * @input_length: Size of the @input buffer in bytes.
 * @output: Buffer where the plaintext is to be written.
 * @output_size: Size of the @output buffer in bytes.
 * @output_length: On success, the number of bytes that make up the output.
 *
 * This function decrypts a message encrypted with a symmetric cipher.
 *
 * The input to this function must contain the IV followed by the ciphertext, as output by
 * psa_cipher_encrypt(). The IV must be PSA_CIPHER_IV_LENGTH(key_type, alg) bytes in length, where
 * key_type is the type of @key.
 *
 * Use the multi-part operation interface with a &typedef psa_cipher_operation_t object to decrypt
 * data which is not in the expected input format.
 *
 * Parameter @output_size must be appropriate for the selected algorithm and key\:
 *
 * - A sufficient output size is PSA_CIPHER_DECRYPT_OUTPUT_SIZE(key_type, alg, input_length) where
 *   key_type is the type of @key.
 *
 * - PSA_CIPHER_DECRYPT_OUTPUT_MAX_SIZE(input_length) evaluates to the maximum output size of any
 *   supported cipher decryption.
 *
 * Return:
 * * PSA_SUCCESS:
 *	Success.
 * * PSA_ERROR_INVALID_HANDLE
 * * PSA_ERROR_NOT_PERMITTED:
 *	The key does not have the PSA_KEY_USAGE_DECRYPT flag, or it does not permit the requested
 *	algorithm.
 * * PSA_ERROR_INVALID_ARGUMENT:
 *	@key is not compatible with @alg.
 * * PSA_ERROR_INVALID_ARGUMENT:
 *	The input_length is not valid for the algorithm and key type. For example, the algorithm is
 *	a based on block cipher and requires a whole number of blocks, but the total input size is
 *	not a multiple of the block size.
 * * PSA_ERROR_NOT_SUPPORTED:
 *	@alg is not supported or is not a cipher algorithm.
 * * PSA_ERROR_BUFFER_TOO_SMALL:
 *	@output_size is too small. PSA_CIPHER_DECRYPT_OUTPUT_SIZE() or
 *	PSA_CIPHER_DECRYPT_OUTPUT_MAX_SIZE() can be used to determine the required buffer size.
 * * PSA_ERROR_INSUFFICIENT_MEMORY
 * * PSA_ERROR_COMMUNICATION_FAILURE
 * * PSA_ERROR_HARDWARE_FAILURE
 * * PSA_ERROR_STORAGE_FAILURE
 * * PSA_ERROR_DATA_CORRUPT
 * * PSA_ERROR_DATA_INVALID
 * * PSA_ERROR_CORRUPTION_DETECTED
 * * PSA_ERROR_BAD_STATE:
 *	The library has not been previously initialized by psa_crypto_init(). It is
 *	implementation-dependent whether a failure to initialize results in this error code.
 */
psa_status_t psa_cipher_decrypt(psa_key_id_t key, psa_algorithm_t alg,
				const uint8_t *input, size_t input_length,
				uint8_t *output, size_t output_size,
				size_t *output_length);

/**
 * psa_cipher_decrypt_setup() - Set the key for a multi-part symmetric decryption operation.
 * @operation: The operation object to set up. It must have been initialized as per the
 *             documentation for &typedef psa_cipher_operation_t and not yet in use.
 * @key: Identifier of the key to use for the operation. It must remain valid until the operation
 *       terminates. It must allow the usage PSA_KEY_USAGE_DECRYPT.
 * @alg: The cipher algorithm to compute (PSA_ALG_XXX value such that PSA_ALG_IS_CIPHER(alg) is
 *       true).
 *
 * **Warning: Not supported**
 *
 * The sequence of operations to decrypt a message with a symmetric cipher is as follows\:
 *
 * - Allocate an operation object which will be passed to all the functions listed here.
 *
 * - Initialize the operation object with one of the methods described in the documentation for
 *   &typedef psa_cipher_operation_t, e.g. PSA_CIPHER_OPERATION_INIT.
 *
 * - Call psa_cipher_decrypt_setup() to specify the algorithm and key.
 *
 * - Call psa_cipher_set_iv() with the initialization vector (IV) for the decryption, if the
 *   algorithm requires one. This must match the IV used for the encryption.
 *
 * - Call psa_cipher_update() zero, one or more times, passing a fragment of the message each time.
 *
 * - Call psa_cipher_finish().
 *
 * If an error occurs at any step after a call to psa_cipher_decrypt_setup(), the operation will
 * need to be reset by a call to psa_cipher_abort(). The application can call psa_cipher_abort()
 * at any time after the operation has been initialized.
 *
 * After a successful call to psa_cipher_decrypt_setup(), the application must eventually terminate
 * the operation. The following events terminate an operation\:
 *
 * - A successful call to psa_cipher_finish().
 *
 * - A call to psa_cipher_abort().
 *
 * Return:
 * * PSA_SUCCESS:
 *	Success.
 * * PSA_ERROR_INVALID_HANDLE
 * * PSA_ERROR_NOT_PERMITTED:
 *	The key does not have the PSA_KEY_USAGE_DECRYPT flag, or it does not permit the requested
 *	algorithm.
 * * PSA_ERROR_INVALID_ARGUMENT:
 *	@key is not compatible with @alg.
 * * PSA_ERROR_NOT_SUPPORTED:
 *	@alg is not supported or is not a cipher algorithm.
 * * PSA_ERROR_INSUFFICIENT_MEMORY
 * * PSA_ERROR_COMMUNICATION_FAILURE
 * * PSA_ERROR_HARDWARE_FAILURE
 * * PSA_ERROR_CORRUPTION_DETECTED
 * * PSA_ERROR_STORAGE_FAILURE
 * * PSA_ERROR_DATA_CORRUPT
 * * PSA_ERROR_DATA_INVALID
 * * PSA_ERROR_BAD_STATE:
 *	The operation state is not valid: it must be inactive.
 * * PSA_ERROR_BAD_STATE:
 *	The library has not been previously initialized by psa_crypto_init(). It is
 *	implementation-dependent whether a failure to initialize results in this error code.
 */
psa_status_t psa_cipher_decrypt_setup(psa_cipher_operation_t *operation,
				      psa_key_id_t key, psa_algorithm_t alg);

/**
 * psa_cipher_encrypt() - Encrypt a message using a symmetric cipher.
 * @key: Identifier of the key to use for the operation. It must allow the usage
 *       PSA_KEY_USAGE_ENCRYPT.
 * @alg: The cipher algorithm to compute (PSA_ALG_XXX value such that PSA_ALG_IS_CIPHER(alg) is
 *       true).
 * @input: Buffer containing the message to encrypt.
 * @input_length: Size of the @input buffer in bytes.
 * @output: Buffer where the output is to be written. The output contains the IV followed by the
 *          ciphertext proper.
 * @output_size: Size of the @output buffer in bytes.
 * @output_length: On success, the number of bytes that make up the output.
 *
 * This function encrypts a message with a random initialization vector (IV). The length of the IV
 * is PSA_CIPHER_IV_LENGTH(key_type, alg) where key_type is the type of @key. The output of
 * psa_cipher_encrypt() is the IV followed by the ciphertext.
 *
 * Use the multi-part operation interface with a &typedef psa_cipher_operation_t object to provide
 * other forms of IV or to manage the IV and ciphertext independently.
 *
 * Parameter @output_size must be appropriate for the selected algorithm and key\:
 *
 * - A sufficient output size is PSA_CIPHER_ENCRYPT_OUTPUT_SIZE(key_type, alg, input_length) where
 *   key_type is the type of @key.
 *
 * - PSA_CIPHER_ENCRYPT_OUTPUT_MAX_SIZE(input_length) evaluates to the maximum output size of any
 *   supported cipher encryption.
 *
 * Return:
 * * PSA_SUCCESS:
 *	Success.
 * * PSA_ERROR_INVALID_HANDLE
 * * PSA_ERROR_NOT_PERMITTED:
 *	The key does not have the PSA_KEY_USAGE_ENCRYPT flag, or it does not permit the requested
 *	algorithm.
 * * PSA_ERROR_INVALID_ARGUMENT:
 *	@key is not compatible with @alg.
 * * PSA_ERROR_INVALID_ARGUMENT:
 *	The input_length is not valid for the algorithm and key type. For example, the algorithm is
 *	a based on block cipher and requires a whole number of blocks, but the total input size is
 *	not a multiple of the block size.
 * * PSA_ERROR_NOT_SUPPORTED:
 *	@alg is not supported or is not a cipher algorithm.
 * * PSA_ERROR_BUFFER_TOO_SMALL:
 *	@output_size is too small. PSA_CIPHER_ENCRYPT_OUTPUT_SIZE() or
 *	PSA_CIPHER_ENCRYPT_OUTPUT_MAX_SIZE() can be used to determine the required buffer size.
 * * PSA_ERROR_INSUFFICIENT_MEMORY
 * * PSA_ERROR_COMMUNICATION_FAILURE
 * * PSA_ERROR_HARDWARE_FAILURE
 * * PSA_ERROR_CORRUPTION_DETECTED
 * * PSA_ERROR_STORAGE_FAILURE
 * * PSA_ERROR_DATA_CORRUPT
 * * PSA_ERROR_DATA_INVALID
 * * PSA_ERROR_BAD_STATE:
 *	The library has not been previously initialized by psa_crypto_init(). It is
 *	implementation-dependent whether a failure to initialize results in this error code.
 */
psa_status_t psa_cipher_encrypt(psa_key_id_t key, psa_algorithm_t alg,
				const uint8_t *input, size_t input_length,
				uint8_t *output, size_t output_size,
				size_t *output_length);

/**
 * psa_cipher_encrypt_setup() - Set the key for a multi-part symmetric encryption operation.
 * @operation: The operation object to set up. It must have been initialized as per the
 *             documentation for &typedef psa_cipher_operation_t and not yet in use.
 * @key: Identifier of the key to use for the operation. It must remain valid until the operation
 *       terminates. It must allow the usage PSA_KEY_USAGE_ENCRYPT.
 * @alg: The cipher algorithm to compute (PSA_ALG_XXX value such that PSA_ALG_IS_CIPHER(alg) is
 *       true).
 *
 * **Warning: Not supported**
 *
 * The sequence of operations to encrypt a message with a symmetric cipher is as follows\:
 *
 * - Allocate an operation object which will be passed to all the functions listed here.
 *
 * - Initialize the operation object with one of the methods described in the documentation for
 *   &typedef psa_cipher_operation_t, e.g. PSA_CIPHER_OPERATION_INIT.
 *
 * - Call psa_cipher_encrypt_setup() to specify the algorithm and key.
 *
 * - Call either psa_cipher_generate_iv() or psa_cipher_set_iv() to generate or set the
 *   initialization vector (IV), if the algorithm requires one. It is recommended to use
 *   psa_cipher_generate_iv() unless the protocol being implemented requires a specific IV value.
 *
 * - Call psa_cipher_update() zero, one or more times, passing a fragment of the message each time.
 *
 * - Call psa_cipher_finish().
 *
 * If an error occurs at any step after a call to psa_cipher_encrypt_setup(), the operation will
 * need to be reset by a call to psa_cipher_abort(). The application can call psa_cipher_abort() at
 * any time after the operation has been initialized.
 *
 * After a successful call to psa_cipher_encrypt_setup(), the application must eventually terminate
 * the operation. The following events terminate an operation:
 *
 * - A successful call to psa_cipher_finish().
 *
 * - A call to psa_cipher_abort().
 *
 * Return:
 * * PSA_SUCCESS:
 *	Success.
 * * PSA_ERROR_INVALID_HANDLE
 * * PSA_ERROR_NOT_PERMITTED:
 *	The key does not have the PSA_KEY_USAGE_ENCRYPT flag, or it does not permit the requested
 *	algorithm.
 * * PSA_ERROR_INVALID_ARGUMENT:
 *	@key is not compatible with @alg.
 * * PSA_ERROR_NOT_SUPPORTED:
 *	@alg is not supported or is not a cipher algorithm.
 * * PSA_ERROR_INSUFFICIENT_MEMORY
 * * PSA_ERROR_COMMUNICATION_FAILURE
 * * PSA_ERROR_HARDWARE_FAILURE
 * * PSA_ERROR_CORRUPTION_DETECTED
 * * PSA_ERROR_STORAGE_FAILURE
 * * PSA_ERROR_DATA_CORRUPT
 * * PSA_ERROR_DATA_INVALID
 * * PSA_ERROR_BAD_STATE:
 *	The operation state is not valid: it must be inactive.
 * * PSA_ERROR_BAD_STATE:
 *	The library has not been previously initialized by psa_crypto_init(). It is
 *	implementation-dependent whether a failure to initialize results in this error code.
 */
psa_status_t psa_cipher_encrypt_setup(psa_cipher_operation_t *operation,
				      psa_key_id_t key, psa_algorithm_t alg);

/**
 * psa_cipher_finish() - Finish encrypting or decrypting a message in a cipher operation.
 * @operation: Active cipher operation.
 * @output: Buffer where the output is to be written.
 * @output_size: Size of the @output buffer in bytes.
 * @output_length: On success, the number of bytes that make up the returned output.
 *
 * **Warning: Not supported**
 *
 * The application must call psa_cipher_encrypt_setup() or psa_cipher_decrypt_setup() before calling
 * this function. The choice of setup function determines whether this function encrypts or decrypts
 * its input.
 *
 * This function finishes the encryption or decryption of the message formed by concatenating the
 * inputs passed to preceding calls to psa_cipher_update().
 *
 * When this function returns successfully, the operation becomes inactive. If this function returns
 * an error status, the operation enters an error state and must be aborted by calling
 * psa_cipher_abort().
 *
 * Parameter @output_size must be appropriate for the selected algorithm and key\:
 *
 * - A sufficient output size is PSA_CIPHER_FINISH_OUTPUT_SIZE(key_type, alg) where key_type is the
 *   type of key and alg is the algorithm that were used to set up the operation.
 *
 * - PSA_CIPHER_FINISH_OUTPUT_MAX_SIZE evaluates to the maximum output size of any supported cipher
 *   algorithm.
 *
 * Return:
 * * PSA_SUCCESS:
 *	Success.
 * * PSA_ERROR_INVALID_ARGUMENT:
 *	The total input size passed to this operation is not valid for this particular algorithm.
 *	For example, the algorithm is a based on block cipher and requires a whole number of blocks,
 *	but the total input size is not a multiple of the block size.
 * * PSA_ERROR_INVALID_PADDING:
 *	This is a decryption operation for an algorithm that includes padding, and the ciphertext
 *	does not contain valid padding.
 * * PSA_ERROR_BAD_STATE:
 *	The operation state is not valid: it must be active, with an IV set if required for the
 *	algorithm.
 * * PSA_ERROR_BUFFER_TOO_SMALL:
 *	The size of the @output buffer is too small. PSA_CIPHER_FINISH_OUTPUT_SIZE() or
 *	PSA_CIPHER_FINISH_OUTPUT_MAX_SIZE can be used to determine the required buffer size.
 * * PSA_ERROR_INSUFFICIENT_MEMORY
 * * PSA_ERROR_COMMUNICATION_FAILURE
 * * PSA_ERROR_HARDWARE_FAILURE
 * * PSA_ERROR_CORRUPTION_DETECTED
 * * PSA_ERROR_STORAGE_FAILURE
 * * PSA_ERROR_DATA_CORRUPT
 * * PSA_ERROR_DATA_INVALID
 * * PSA_ERROR_BAD_STATE:
 *	The library has not been previously initialized by psa_crypto_init(). It is
 *	implementation-dependent whether a failure to initialize results in this error code.
 */
psa_status_t psa_cipher_finish(psa_cipher_operation_t *operation,
			       uint8_t *output, size_t output_size,
			       size_t *output_length);

/**
 * psa_cipher_generate_iv() - Generate an initialization vector (IV) for a symmetric encryption
 * operation.
 * @operation: Active cipher operation.
 * @iv: Buffer where the generated IV is to be written.
 * @iv_size: Size of the @iv buffer in bytes. This must be at least
 *           PSA_CIPHER_IV_LENGTH(key_type, alg) where key_type and alg are type of key and the
 *           algorithm respectively that were used to set up the cipher operation.
 * @iv_length: On success, the number of bytes of the generated IV.
 *
 * **Warning: Not supported**
 *
 * This function generates a random IV, nonce or initial counter value for the encryption operation
 * as appropriate for the chosen algorithm, key type and key size.
 *
 * The generated IV is always the default length for the key and algorithm\:
 * PSA_CIPHER_IV_LENGTH(key_type, alg), where key_type is the type of @key and alg is the algorithm
 * that were used to set up the operation. To generate different lengths of IV,
 * use psa_generate_random() and psa_cipher_set_iv().
 *
 * If the cipher algorithm does not use an IV, calling this function returns a PSA_ERROR_BAD_STATE
 * error. For these algorithms, PSA_CIPHER_IV_LENGTH(key_type, alg) will be zero.
 *
 * The application must call psa_cipher_encrypt_setup() before calling this function.
 *
 * If this function returns an error status, the operation enters an error state and must be aborted
 * by calling psa_cipher_abort().
 *
 * Return:
 * * PSA_SUCCESS:
 *	Success.
 * * PSA_ERROR_BAD_STATE:
 *	Either\:
 *
 *	- The cipher algorithm does not use an IV.
 *
 *	- The operation state is not valid: it must be active, with no IV set.
 * * PSA_ERROR_BUFFER_TOO_SMALL:
 *	The size of the @iv buffer is too small. PSA_CIPHER_IV_LENGTH() or PSA_CIPHER_IV_MAX_SIZE
 *	can be used to determine the required buffer size.
 * * PSA_ERROR_INSUFFICIENT_MEMORY
 * * PSA_ERROR_COMMUNICATION_FAILURE
 * * PSA_ERROR_HARDWARE_FAILURE
 * * PSA_ERROR_CORRUPTION_DETECTED
 * * PSA_ERROR_STORAGE_FAILURE
 * * PSA_ERROR_DATA_CORRUPT
 * * PSA_ERROR_DATA_INVALID
 * * PSA_ERROR_BAD_STATE:
 *	The library has not been previously initialized by psa_crypto_init(). It is
 *	implementation-dependent whether a failure to initialize results in this error code.
 */
psa_status_t psa_cipher_generate_iv(psa_cipher_operation_t *operation,
				    uint8_t *iv, size_t iv_size,
				    size_t *iv_length);

/**
 * psa_cipher_operation_init() - Return an initial value for a cipher operation object.
 *
 * Return:
 * &typedef psa_cipher_operation_t
 */
static psa_cipher_operation_t psa_cipher_operation_init(void);

/**
 * psa_cipher_set_iv() - Set the initialization vector (IV) for a symmetric encryption or decryption
 * operation.
 * @operation: Active cipher operation.
 * @iv: Buffer containing the IV to use.
 * @iv_length: Size of the IV in bytes.
 *
 * **Warning: Not supported**
 *
 * This function sets the IV, nonce or initial counter value for the encryption or decryption
 * operation.
 *
 * If the cipher algorithm does not use an IV, calling this function returns a PSA_ERROR_BAD_STATE
 * error. For these algorithms, PSA_CIPHER_IV_LENGTH(key_type, alg) will be zero.
 *
 * The application must call psa_cipher_encrypt_setup() or psa_cipher_decrypt_setup() before calling
 * this function.
 *
 * If this function returns an error status, the operation enters an error state and must be aborted
 * by calling psa_cipher_abort().
 *
 * **Note**:
 *	When encrypting, psa_cipher_generate_iv() is recommended instead of using this function,
 *	unless implementing a protocol that requires a non-random IV.
 *
 * Return:
 * * PSA_SUCCESS:
 *	Success.
 * * PSA_ERROR_BAD_STATE:
 *	Either\:
 *
 *	- The cipher algorithm does not use an IV.
 *
 *	- The operation state is not valid: it must be an active cipher encrypt operation, with no
 *	  IV set.
 * * PSA_ERROR_INVALID_ARGUMENT:
 *	The size of iv is not acceptable for the chosen algorithm, or the chosen algorithm does not
 *	use an IV.
 * * PSA_ERROR_INSUFFICIENT_MEMORY
 * * PSA_ERROR_COMMUNICATION_FAILURE
 * * PSA_ERROR_HARDWARE_FAILURE
 * * PSA_ERROR_CORRUPTION_DETECTED
 * * PSA_ERROR_STORAGE_FAILURE
 * * PSA_ERROR_DATA_CORRUPT
 * * PSA_ERROR_DATA_INVALID
 * * PSA_ERROR_BAD_STATE:
 *	The library has not been previously initialized by psa_crypto_init(). It is
 *	implementation-dependent whether a failure to initialize results in this error code.
 */
psa_status_t psa_cipher_set_iv(psa_cipher_operation_t *operation,
			       const uint8_t *iv, size_t iv_length);

/**
 * psa_cipher_update() - Encrypt or decrypt a message fragment in an active cipher operation.
 * @operation: Active cipher operation.
 * @input: Buffer containing the message fragment to encrypt or decrypt.
 * @input_length: Size of the @input buffer in bytes.
 * @output: Buffer where the output is to be written.
 * @output_size: Size of the @output buffer in bytes.
 * @output_length: On success, the number of bytes that make up the returned output.
 *
 * **Warning: Not supported**
 *
 * The following must occur before calling this function\:
 *
 * #. Call either psa_cipher_encrypt_setup() or psa_cipher_decrypt_setup(). The choice of setup
 *    function determines whether this function encrypts or decrypts its input.
 *
 * #. If the algorithm requires an IV, call psa_cipher_generate_iv() or psa_cipher_set_iv().
 *    psa_cipher_generate_iv() is recommended when encrypting.
 *
 * If this function returns an error status, the operation enters an error state and must be aborted
 * by calling psa_cipher_abort().
 *
 * Parameter @output_size must be appropriate for the selected algorithm and key\:
 *
 * - A sufficient output size is PSA_CIPHER_UPDATE_OUTPUT_SIZE(key_type, alg, input_length) where
 *   key_type is the type of @key and alg is the algorithm that were used to set up the operation.
 *
 * - PSA_CIPHER_UPDATE_OUTPUT_MAX_SIZE(input_length) evaluates to the maximum output size of any
 *   supported cipher algorithm.
 *
 * Return:
 * * PSA_SUCCESS:
 *	Success.
 * * PSA_ERROR_BAD_STATE:
 *	The operation state is not valid: it must be active, with an IV set if required for the
 *	algorithm.
 * * PSA_ERROR_BUFFER_TOO_SMALL:
 *	The size of the @output buffer is too small. PSA_CIPHER_UPDATE_OUTPUT_SIZE() or
 *	PSA_CIPHER_UPDATE_OUTPUT_MAX_SIZE() can be used to determine the required buffer size.
 * * PSA_ERROR_INSUFFICIENT_MEMORY
 * * PSA_ERROR_COMMUNICATION_FAILURE
 * * PSA_ERROR_HARDWARE_FAILURE
 * * PSA_ERROR_CORRUPTION_DETECTED
 * * PSA_ERROR_STORAGE_FAILURE
 * * PSA_ERROR_DATA_CORRUPT
 * * PSA_ERROR_DATA_INVALID
 * * PSA_ERROR_BAD_STATE:
 *	The library has not been previously initialized by psa_crypto_init(). It is
 *	implementation-dependent whether a failure to initialize results in this error code.
 */
psa_status_t psa_cipher_update(psa_cipher_operation_t *operation,
			       const uint8_t *input, size_t input_length,
			       uint8_t *output, size_t output_size,
			       size_t *output_length);

/**
 * psa_copy_key() - Make a copy of a key.
 * @source_key: The key to copy. It must allow the usage PSA_KEY_USAGE_COPY. If a private or secret
 *              key is being copied outside of a secure element it must also allow
 *              PSA_KEY_USAGE_EXPORT.
 * @attributes: The attributes for the new key.
 * @target_key: On success, an identifier for the newly created key. PSA_KEY_ID_NULL on failure.
 *
 * **Warning: Not supported**
 *
 * Copy key material from one location to another.
 *
 * This function is primarily useful to copy a key from one location to another, as it populates a
 * key using the material from another key which can have a different lifetime.
 *
 * This function can be used to share a key with a different party.
 *
 * The policy on the source key must have the usage flag PSA_KEY_USAGE_COPY set. This flag is
 * sufficient to permit the copy if the key has the lifetime PSA_KEY_LIFETIME_VOLATILE or
 * PSA_KEY_LIFETIME_PERSISTENT. Some secure elements do not provide a way to copy a key without
 * making it extractable from the secure element. If a key is located in such a secure element,then
 * the key must have both usage flags PSA_KEY_USAGE_COPY and PSA_KEY_USAGE_EXPORT in order to make a
 * copy of the key outside the secure element.
 *
 * The resulting key can only be used in a way that conforms to both the policy of the original key
 * and the policy specified in the attributes parameter\:
 *
 * - The usage flags on the resulting key are the bitwise-and of the usage flags on the source
 *   policy and the usage flags in attributes.
 *
 * - If both permit the same algorithm or wildcard-based algorithm, the resulting key has the same
 *   permitted algorithm.
 *
 * - If either of the policies permits an algorithm and the other policy allows a wildcard-based
 *   permitted algorithm that includes this algorithm, the resulting key uses this permitted
 *   algorithm.
 *
 * - If the policies do not permit any algorithm in common, this function fails with the status
 *   PSA_ERROR_INVALID_ARGUMENT.
 *
 * The effect of this function on implementation-defined attributes is implementation-defined.
 *
 * This function uses the attributes as follows\:
 *
 * - The key type and size can be 0. If either is nonzero, it must match the corresponding attribut
 *   of the source key.
 *
 * - The key location (the lifetime and, for persistent keys, the key identifier) is used directly.
 *
 * - The key policy (usage flags and permitted algorithm) are combined from the source key and
 *   attributes so that both sets of restrictions apply, as described in the documentation of this
 *   function.
 *
 *   **Note**:
 *	This is an input parameter: it is not updated with the final key attributes. The final
 *	attributes of the new key can be queried by calling psa_get_key_attributes() with the
 *	key’s identifier.
 *
 * Return:
 * * PSA_SUCCESS:
 *	Success. If the new key is persistent, the key material and the key’s metadata have been
 *	saved to persistent storage.
 * * PSA_ERROR_INVALID_HANDLE:
 *	@source_key is invalid.
 * * PSA_ERROR_ALREADY_EXISTS:
 *	This is an attempt to create a persistent key, and there is already a persistent key with
 *	the given identifier.
 * * PSA_ERROR_INVALID_ARGUMENT:
 *	The lifetime or identifier in @attributes are invalid.
 * * PSA_ERROR_INVALID_ARGUMENT:
 *	The key policies from @source_key and specified in @attributes are incompatible.
 * * PSA_ERROR_INVALID_ARGUMENT:
 *	@attributes specifies a key type or key size which does not match the attributes of source
 *	key.
 * * PSA_ERROR_NOT_PERMITTED:
 *	@source_key does not have the PSA_KEY_USAGE_COPY usage flag.
 * * PSA_ERROR_NOT_PERMITTED:
 *	@source_key does not have the PSA_KEY_USAGE_EXPORT usage flag and its lifetime does not
 *	allow copying it to the target’s lifetime.
 * * PSA_ERROR_INSUFFICIENT_MEMORY
 * * PSA_ERROR_INSUFFICIENT_STORAGE
 * * PSA_ERROR_COMMUNICATION_FAILURE
 * * PSA_ERROR_HARDWARE_FAILURE
 * * PSA_ERROR_STORAGE_FAILURE
 * * PSA_ERROR_DATA_CORRUPT
 * * PSA_ERROR_DATA_INVALID
 * * PSA_ERROR_CORRUPTION_DETECTED
 * * PSA_ERROR_BAD_STATE:
 *	The library has not been previously initialized by psa_crypto_init(). It is
 *	implementation-dependent whether a failure to initialize results in this error code.
 */
psa_status_t psa_copy_key(psa_key_id_t source_key,
			  const psa_key_attributes_t *attributes,
			  psa_key_id_t *target_key);

/**
 * psa_crypto_init() - Library initialization.
 *
 * Applications must call this function before calling any other function in this module.
 *
 * Applications are permitted to call this function more than once. Once a call succeeds, subsequent
 * calls are guaranteed to succeed.
 *
 * If the application calls other functions before calling psa_crypto_init(), the behavior is
 * undefined. In this situation\:
 *
 * - Implementations are encouraged to either perform the operation as if the library had been
 *   initialized or to return PSA_ERROR_BAD_STATE or some other applicable error.
 *
 * - Implementations must not return a success status if the lack of initialization might have
 *   security implications, for example due to improper seeding of the random number generator.
 *
 * Return:
 * * PSA_SUCCESS
 * * PSA_ERROR_INSUFFICIENT_MEMORY
 * * PSA_ERROR_COMMUNICATION_FAILURE
 * * PSA_ERROR_HARDWARE_FAILURE
 * * PSA_ERROR_CORRUPTION_DETECTED
 * * PSA_ERROR_INSUFFICIENT_ENTROPY
 */
psa_status_t psa_crypto_init(void);

/**
 * psa_destroy_key() - Destroy a key.
 * @key: Identifier of the key to erase. If this is PSA_KEY_ID_NULL, do nothing and return
 *       PSA_SUCCESS.
 *
 * This function destroys a key from both volatile memory and, if applicable, non-volatile storage.
 * Implementations must make a best effort to ensure that the key material cannot be recovered.
 *
 * This function also erases any metadata such as policies and frees resources associated with the
 * key.
 *
 * Destroying the key makes the key identifier invalid, and the key identifier must not be used
 * again by the application.
 *
 * If a key is currently in use in a multi-part operation, then destroying the key will cause the
 * multi-part operation to fail.
 *
 * Return:
 * * PSA_SUCCESS:
 *	@key was a valid key identifier and the key material that it referred to has been erased.
 *	Alternatively, key is PSA_KEY_ID_NULL.
 * * PSA_ERROR_NOT_PERMITTED:
 *	The key cannot be erased because it is read-only, either due to a policy or due to physical
 *	restrictions.
 * * PSA_ERROR_INVALID_HANDLE:
 *	@key is not a valid handle nor PSA_KEY_ID_NULL.
 * * PSA_ERROR_COMMUNICATION_FAILURE
 *	There was an failure in communication with the cryptoprocessor. The key material might still
 *	be present in the cryptoprocessor.
 * * PSA_ERROR_STORAGE_FAILURE:
 *	The storage operation failed. Implementations must make a best effort to erase key material
 *	even in this situation, however, it might be impossible to guarantee that the key material
 *	is not recoverable in such cases.
 * * PSA_ERROR_DATA_CORRUPT:
 *	The storage is corrupted. Implementations must make a best effort to erase key material even
 *	in this situation, however, it might be impossible to guarantee that the key material is not
 *	recoverable in such cases.
 * * PSA_ERROR_DATA_INVALID
 * * PSA_ERROR_CORRUPTION_DETECTED:
 *	An unexpected condition which is not a storage corruption or a communication failure
 *	occurred. The cryptoprocessor might have been compromised.
 * * PSA_ERROR_BAD_STATE:
 *	The library has not been previously initialized by psa_crypto_init(). It is
 *	implementation-dependent whether a failure to initialize results in this error code.
 */
psa_status_t psa_destroy_key(psa_key_id_t key);

/**
 * psa_export_key() - Export a key in binary format.
 * @key: Identifier of the key to export. It must allow the usage PSA_KEY_USAGE_EXPORT, unless it is
 *       a public key.
 * @data: Buffer where the key data is to be written.
 * @data_size: Size of the @data buffer in bytes.
 * @data_length: On success, the number of bytes that make up the key data.
 *
 * **Warning: Export of any private key is not supported for now.**
 *
 * The output of this function can be passed to psa_import_key() to create an equivalent object.
 *
 * If the implementation of psa_import_key() supports other formats beyond the format specified
 * here, the output from psa_export_key() must use the representation specified here, not the
 * original representation.
 *
 * For standard key types, the output format is as follows\:
 *
 * - For symmetric keys, excluding HMAC keys, the format is the raw bytes of the key.
 *
 * - For HMAC keys that are shorter than, or equal in size to, the underlying hash algorithm block
 *   size, the format is the raw bytes of the key.
 *
 *   For HMAC keys that are longer than the underlying hash algorithm block size, the format is an
 *   implementation defined choice between the following formats\:
 *
 *   #. The raw bytes of the key.
 *
 *   #. The raw bytes of the hash of the key, using the underlying hash algorithm.
 *
 *   See also PSA_KEY_TYPE_HMAC.
 *
 * - For DES, the key data consists of 8 bytes. The parity bits must be correct.
 *
 * - For Triple-DES, the format is the concatenation of the two or three DES keys.
 *
 * - For RSA key pairs, with key type PSA_KEY_TYPE_RSA_KEY_PAIR, the format is the non-encrypted DER
 *   encoding of the representation defined by in PKCS #1: RSA Cryptography Specifications Version
 *   2.2 [RFC8017] as RSAPrivateKey, version 0.
 *
 *     .. code-block:: none
 *
 *        RSAPrivateKey ::= SEQUENCE {
 *            version             INTEGER,  -- must be 0
 *            modulus             INTEGER,  -- n
 *            publicExponent      INTEGER,  -- e
 *            privateExponent     INTEGER,  -- d
 *            prime1              INTEGER,  -- p
 *            prime2              INTEGER,  -- q
 *            exponent1           INTEGER,  -- d mod (p-1)
 *            exponent2           INTEGER,  -- d mod (q-1)
 *            coefficient         INTEGER,  -- (inverse of q) mod p
 *        }
 *
 *     **Note**:
 *	Although it is possible to define an RSA key pair or private key using a subset of these
 *	elements, the output from psa_export_key() for an RSA key pair must include all of these
 *	elements.
 *
 * - For elliptic curve key pairs, with key types for which PSA_KEY_TYPE_IS_ECC_KEY_PAIR() is true,
 *   the format is a representation of the private value.
 *
 *   * For Weierstrass curve families PSA_ECC_FAMILY_SECT_XX, PSA_ECC_FAMILY_SECP_XX,
 *     PSA_ECC_FAMILY_FRP and PSA_ECC_FAMILY_BRAINPOOL_P_R1, the content of the privateKey field of
 *     the ECPrivateKey format defined by Elliptic Curve Private Key Structure [RFC5915].
 *
 *     This is a ceiling(m/8)-byte string in big-endian order where m is the key size in bits.
 *
 *   * For curve family PSA_ECC_FAMILY_MONTGOMERY, the scalar value of the ‘private key’ in
 *     little-endian order as defined by Elliptic Curves for Security [RFC7748] §6. The value must
 *     have the forced bits set to zero or one as specified by decodeScalar25519() and
 *     decodeScalar448() in [RFC7748] §5.
 *
 *     This is a ceiling(m/8)-byte string where m is the key size in bits. This is 32 bytes for
 *     Curve25519, and 56 bytes for Curve448.
 *
 * - For Diffie-Hellman key exchange key pairs, with key types for which
 *   PSA_KEY_TYPE_IS_DH_KEY_PAIR() is true, the format is the representation of the private key x as
 *   a big-endian byte string. The length of the byte string is the private key size in bytes, and
 *   leading zeroes are not stripped.
 *
 * - For public keys, with key types for which PSA_KEY_TYPE_IS_PUBLIC_KEY() is true, the format is
 *   the same as for psa_export_public_key().
 *
 * The policy on the key must have the usage flag PSA_KEY_USAGE_EXPORT set.
 *
 * Parameter @data_size must be appropriate for the key\:
 *
 * - The required output size is PSA_EXPORT_KEY_OUTPUT_SIZE(type, bits) where type is the key type
 *   and bits is the key size in bits.
 *
 * - PSA_EXPORT_KEY_PAIR_MAX_SIZE evaluates to the maximum output size of any supported key pair.
 *
 * - PSA_EXPORT_PUBLIC_KEY_MAX_SIZE evaluates to the maximum output size of any supported public
 *   key.
 *
 * - This API defines no maximum size for symmetric keys. Arbitrarily large data items can be stored
 *   in the key store, for example certificates that correspond to a stored private key or input
 *   material for key derivation.
 *
 * Return:
 * * PSA_SUCCESS
 * * PSA_ERROR_INVALID_HANDLE
 * * PSA_ERROR_NOT_PERMITTED:
 *	The key does not have the PSA_KEY_USAGE_EXPORT flag.
 * * PSA_ERROR_NOT_SUPPORTED
 * * PSA_ERROR_BUFFER_TOO_SMALL:
 *	The size of the @data buffer is too small. PSA_EXPORT_KEY_OUTPUT_SIZE() or
 *	PSA_EXPORT_KEY_PAIR_MAX_SIZE can be used to determine the required buffer size.
 * * PSA_ERROR_COMMUNICATION_FAILURE
 * * PSA_ERROR_HARDWARE_FAILURE
 * * PSA_ERROR_CORRUPTION_DETECTED
 * * PSA_ERROR_STORAGE_FAILURE
 * * PSA_ERROR_DATA_CORRUPT
 * * PSA_ERROR_DATA_INVALID
 * * PSA_ERROR_INSUFFICIENT_MEMORY
 * * PSA_ERROR_BAD_STATE:
 *	The library has not been previously initialized by psa_crypto_init(). It is
 *	implementation-dependent whether a failure to initialize results in this error code.
 */
psa_status_t psa_export_key(psa_key_id_t key, uint8_t *data, size_t data_size,
			    size_t *data_length);

/**
 * psa_export_public_key() - Export a public key or the public part of a key pair in binary format.
 * @key: Identifier of the key to export.
 * @data: Buffer where the key data is to be written.
 * @data_size: Size of the @data buffer in bytes.
 * @data_length: On success, the number of bytes that make up the key data.
 *
 * **Warning: Not supported**
 *
 * The output of this function can be passed to psa_import_key() to create an object that is
 * equivalent to the public key.
 *
 * If the implementation of psa_import_key() supports other formats beyond the format specified
 * here, the output from psa_export_public_key() must use the representation specified here, not the
 * original representation.
 *
 * For standard key types, the output format is as follows\:
 *
 * - For RSA public keys, with key type PSA_KEY_TYPE_RSA_PUBLIC_KEY, the DER encoding of the
 *   representation defined by Algorithms and Identifiers for the Internet X.509 Public Key
 *   Infrastructure Certificate and Certificate Revocation List (CRL) Profile [RFC3279] §2.3.1 as
 *   RSAPublicKey.
 *
 *   .. code-block:: none
 *
 *      RSAPublicKey ::= SEQUENCE {
 *         modulus            INTEGER,    -- n
 *         publicExponent     INTEGER  }  -- e
 *
 * - For elliptic curve key pairs, with key types for which PSA_KEY_TYPE_IS_ECC_PUBLIC_KEY() is
 *   true, the format depends on the key family:
 *
 *   * For Weierstrass curve families PSA_ECC_FAMILY_SECT_XX, PSA_ECC_FAMILY_SECP_XX,
 *     PSA_ECC_FAMILY_FRP and PSA_ECC_FAMILY_BRAINPOOL_P_R1, the uncompressed representation of an
 *     elliptic curve point as an octet string defined in SEC 1: Elliptic Curve Cryptography [SEC1]
 *     §2.3.3. If m is the bit size associated with the curve, i.e. the bit size of q for a curve
 *     over F_q. The representation consists of\:
 *
 *     - The byte 0x04;
 *
 *     - x_P as a ceiling(m/8)-byte string, big-endian;
 *
 *     - y_P as a ceiling(m/8)-byte string, big-endian.
 *
 *   * For curve family PSA_ECC_FAMILY_MONTGOMERY, the scalar value of the ‘public key’ in
 *     little-endian order as defined by Elliptic Curves for Security [RFC7748] §6. This is a
 *     ceiling(m/8)-byte string where m is the key size in bits.
 *
 *     - This is 32 bytes for Curve25519, computed as X25519(private_key, 9).
 *
 *     - This is 56 bytes for Curve448, computed as X448(private_key, 5).
 *
 * - For Diffie-Hellman key exchange public keys, with key types for which
 *   PSA_KEY_TYPE_IS_DH_PUBLIC_KEY is true, the format is the representation of the public key
 *   y = g^x mod p as a big-endian byte string. The length of the byte string is the length of the
 *   base prime p in bytes.
 *
 * Exporting a public key object or the public part of a key pair is always permitted, regardless of
 * the key’s usage flags.
 *
 * Parameter @data_size must be appropriate for the key\:
 *
 * - The required output size is PSA_EXPORT_PUBLIC_KEY_OUTPUT_SIZE(type, bits) where type is the key
 *   type and bits is the key size in bits.
 *
 * - PSA_EXPORT_PUBLIC_KEY_MAX_SIZE evaluates to the maximum output size of any supported public key
 *   or public part of a key pair.
 *
 * Return:
 * * PSA_SUCCESS
 * * PSA_ERROR_INVALID_HANDLE
 * * PSA_ERROR_INVALID_ARGUMENT:
 *	The key is neither a public key nor a key pair.
 * * PSA_ERROR_NOT_SUPPORTED
 * * PSA_ERROR_BUFFER_TOO_SMALL:
 *	The size of the @data buffer is too small. PSA_EXPORT_PUBLIC_KEY_OUTPUT_SIZE() or
 *	PSA_EXPORT_PUBLIC_KEY_MAX_SIZE can be used to determine the required buffer size.
 * * PSA_ERROR_COMMUNICATION_FAILURE
 * * PSA_ERROR_HARDWARE_FAILURE
 * * PSA_ERROR_CORRUPTION_DETECTED
 * * PSA_ERROR_STORAGE_FAILURE
 * * PSA_ERROR_DATA_CORRUPT
 * * PSA_ERROR_DATA_INVALID
 * * PSA_ERROR_INSUFFICIENT_MEMORY
 * * PSA_ERROR_BAD_STATE:
 *	The library has not been previously initialized by psa_crypto_init(). It is
 *	implementation-dependent whether a failure to initialize results in this error code.
 */
psa_status_t psa_export_public_key(psa_key_id_t key, uint8_t *data,
				   size_t data_size, size_t *data_length);

/**
 * psa_generate_key() - Generate a key or key pair.
 * @attributes: The attributes for the new key.
 * @key: On success, an identifier for the newly created key. PSA_KEY_ID_NULL on failure.
 *
 * The key is generated randomly. Its location, policy, type and size are taken from attributes.
 *
 * Implementations must reject an attempt to generate a key of size 0.
 *
 * The following type-specific considerations apply\:
 *
 * - For RSA keys (PSA_KEY_TYPE_RSA_KEY_PAIR), the public exponent is 65537. The modulus is a
 *   product of two probabilistic primes between 2^{n-1} and 2^n where n is the bit size specified
 *   in the attributes.
 *
 * This function uses the attributes as follows\:
 *
 * - The key type is required. It cannot be an asymmetric public key.
 *
 * - The key size is required. It must be a valid size for the key type.
 *
 * - The key permitted-algorithm policy is required for keys that will be used for a cryptographic
 *   operation, see Permitted algorithms.
 *
 * - The key usage flags define what operations are permitted with the key, see Key usage flags.
 *
 * - The key lifetime and identifier are required for a persistent key.
 *
 *   **Note**:
 *	This is an input parameter: it is not updated with the final key attributes. The final
 *	attributes of the new key can be queried by calling psa_get_key_attributes() with the
 *	key’s identifier.
 *
 * Return:
 * * PSA_SUCCESS:
 *	Success. If the key is persistent, the key material and the key’s metadata have been saved
 *	to persistent storage.
 * * PSA_ERROR_ALREADY_EXISTS:
 *	This is an attempt to create a persistent key, and there is already a persistent key with
 *	the given identifier.
 * * PSA_ERROR_NOT_SUPPORTED:
 *	The key type or key size is not supported, either by the implementation in general or in
 *	this particular persistent location.
 * * PSA_ERROR_INVALID_ARGUMENT:
 *	The key attributes, as a whole, are invalid.
 * * PSA_ERROR_INVALID_ARGUMENT:
 *	The key type is an asymmetric public key type.
 * * PSA_ERROR_INVALID_ARGUMENT:
 *	The key size is not a valid size for the key type.
 * * PSA_ERROR_INSUFFICIENT_MEMORY
 * * PSA_ERROR_INSUFFICIENT_ENTROPY
 * * PSA_ERROR_COMMUNICATION_FAILURE
 * * PSA_ERROR_HARDWARE_FAILURE
 * * PSA_ERROR_CORRUPTION_DETECTED
 * * PSA_ERROR_INSUFFICIENT_STORAGE
 * * PSA_ERROR_STORAGE_FAILURE
 * * PSA_ERROR_DATA_CORRUPT
 * * PSA_ERROR_DATA_INVALID
 * * PSA_ERROR_BAD_STATE:
 *	The library has not been previously initialized by psa_crypto_init(). It is
 *	implementation-dependent whether a failure to initialize results in this error code.
 */
psa_status_t psa_generate_key(const psa_key_attributes_t *attributes,
			      psa_key_id_t *key);

/**
 * psa_generate_random() - Generate random bytes.
 * @output: Output buffer for the generated data.
 * @output_size: Number of bytes to generate and output.
 *
 * **Warning**:
 *	This function can fail! Callers MUST check the return status and MUST NOT use the content of
 *	the @output buffer if the return status is not PSA_SUCCESS.
 *
 * **Note**:
 *	To generate a key, use psa_generate_key() instead.
 *
 * Return:
 * * PSA_SUCCESS
 * * PSA_ERROR_NOT_SUPPORTED
 * * PSA_ERROR_INSUFFICIENT_ENTROPY
 * * PSA_ERROR_INSUFFICIENT_MEMORY
 * * PSA_ERROR_COMMUNICATION_FAILURE
 * * PSA_ERROR_HARDWARE_FAILURE
 * * PSA_ERROR_CORRUPTION_DETECTED
 * * PSA_ERROR_BAD_STATE:
 *	The library has not been previously initialized by psa_crypto_init(). It is
 *	implementation-dependent whether a failure to initialize results in this error code.
 */
psa_status_t psa_generate_random(uint8_t *output, size_t output_size);

/**
 * psa_get_key_algorithm() - Retrieve the permitted algorithm policy from key attributes.
 * @attributes: The key attribute object to query.
 *
 * **Implementation note**:
 *	This is a simple accessor function that is not required to validate its inputs. The
 *	following approaches can be used to provide an efficient implementation\:
 *
 *	- This function can be declared as static or inline, instead of using the default external
 *	  linkage.
 *
 *	- This function can be provided as a function-like macro. In this form, the macro must
 *	  evaluate each of its arguments exactly once, as if it was a function call.
 *
 * Return:
 * &typedef psa_algorithm_t
 *
 * The algorithm stored in the attribute object.
 */
static psa_algorithm_t
psa_get_key_algorithm(const psa_key_attributes_t *attributes);

/**
 * psa_get_key_attributes() - Retrieve the attributes of a key.
 * @key: Identifier of the key to query.
 * @attributes: On entry, \*attributes must be in a valid state. On successful return, it contains
 *              the attributes of the key. On failure, it is equivalent to a freshly-initialized
 *              attribute object.
 *
 * This function first resets the attribute object as with psa_reset_key_attributes(). It then
 * copies the attributes of the given key into the given attribute object.
 *
 * **Note**:
 *	This function clears any previous content from the attribute object and therefore expects it
 *	to be in a valid state. In particular, if this function is called on a newly allocated
 *	attribute object, the attribute object must be initialized before calling this function.
 *
 * **Note**:
 *	This function might allocate memory or other resources. Once this function has been called
 *	on an attribute object, psa_reset_key_attributes() must be called to free these resources.
 *
 * Return:
 * * PSA_SUCCESS
 * * PSA_ERROR_INVALID_HANDLE
 * * PSA_ERROR_INSUFFICIENT_MEMORY
 * * PSA_ERROR_COMMUNICATION_FAILURE
 * * PSA_ERROR_CORRUPTION_DETECTED
 * * PSA_ERROR_STORAGE_FAILURE
 * * PSA_ERROR_DATA_CORRUPT
 * * PSA_ERROR_DATA_INVALID
 * * PSA_ERROR_BAD_STATE:
 *	The library has not been previously initialized by psa_crypto_init(). It is
 *	implementation-dependent whether a failure to initialize results in this error code.
 */
psa_status_t psa_get_key_attributes(psa_key_id_t key,
				    psa_key_attributes_t *attributes);

/**
 * psa_get_key_bits() - Retrieve the key size from key attributes.
 * @attributes: The key attribute object to query.
 *
 * **Implementation note**:
 *	This is a simple accessor function that is not required to validate its inputs. The
 *	following approaches can be used to provide an efficient implementation\:
 *
 *	- This function can be declared as static or inline, instead of using the default external
 *	  linkage.
 *
 *	- This function can be provided as a function-like macro. In this form, the macro must
 *	  evaluate each of its arguments exactly once, as if it was a function call.
 *
 * Return:
 * size_t
 *
 * The key size stored in the attribute object, in bits.
 */
static size_t psa_get_key_bits(const psa_key_attributes_t *attributes);

/**
 * psa_get_key_id() - Retrieve the key identifier from key attributes.
 * @attributes: The key attribute object to query.
 *
 * **Implementation note**:
 *	This is a simple accessor function that is not required to validate its inputs. The
 *	following approaches can be used to provide an efficient implementation\:
 *
 *	- This function can be declared as static or inline, instead of using the default external
 *	  linkage.
 *
 *	- This function can be provided as a function-like macro. In this form, the macro must
 *	  evaluate each of its arguments exactly once, as if it was a function call.
 *
 * Return:
 * &typedef psa_key_id_t
 *
 * The persistent identifier stored in the attribute object. This value is unspecified if the
 * attribute object declares the key as volatile.
 */
static psa_key_id_t psa_get_key_id(const psa_key_attributes_t *attributes);

/**
 * psa_get_key_lifetime() - Retrieve the lifetime from key attributes.
 * @attributes: The key attribute object to query.
 *
 * **Implementation note**:
 *	This is a simple accessor function that is not required to validate its inputs. The
 *	following approaches can be used to provide an efficient implementation\:
 *
 *	- This function can be declared as static or inline, instead of using the default external
 *	  linkage.
 *
 *	- This function can be provided as a function-like macro. In this form, the macro must
 *	  evaluate each of its arguments exactly once, as if it was a function call.
 *
 * Return:
 * &typedef psa_key_lifetime_t
 *
 * The lifetime value stored in the attribute object.
 */
static psa_key_lifetime_t
psa_get_key_lifetime(const psa_key_attributes_t *attributes);

/**
 * psa_get_key_type() - Retrieve the key type from key attributes.
 * @attributes: The key attribute object to query.
 *
 * **Implementation note**:
 *	This is a simple accessor function that is not required to validate its inputs. The
 *	following approaches can be used to provide an efficient implementation\:
 *
 *	- This function can be declared as static or inline, instead of using the default external
 *	  linkage.
 *
 *	- This function can be provided as a function-like macro. In this form, the macro must
 *	  evaluate each of its arguments exactly once, as if it was a function call.
 *
 * Return:
 * &typedef psa_key_type_t
 *
 * The key type stored in the attribute object.
 */
static psa_key_type_t psa_get_key_type(const psa_key_attributes_t *attributes);

/**
 * psa_get_key_usage_flags() - Retrieve the usage flags from key attributes.
 * @attributes: The key attribute object to query.
 *
 * **Implementation note**:
 *	This is a simple accessor function that is not required to validate its inputs. The
 *	following approaches can be used to provide an efficient implementation\:
 *
 *	- This function can be declared as static or inline, instead of using the default external
 *	  linkage.
 *
 *	- This function can be provided as a function-like macro. In this form, the macro must
 *	  evaluate each of its arguments exactly once, as if it was a function call.
 *
 * Return:
 * &typedef psa_key_usage_t
 *
 * The usage flags stored in the attribute object.
 */
static psa_key_usage_t
psa_get_key_usage_flags(const psa_key_attributes_t *attributes);

/**
 * psa_hash_abort() - Abort a hash operation.
 * @operation: Initialized hash operation.
 *
 * **Warning: Not supported**
 *
 * Aborting an operation frees all associated resources except for the operation object itself. Once
 * aborted, the operation object can be reused for another operation by calling psa_hash_setup()
 * again.
 *
 * This function can be called any time after the operation object has been initialized by one of
 * the methods described in &typedef psa_hash_operation_t.
 *
 * In particular, calling psa_hash_abort() after the operation has been terminated by a call to
 * psa_hash_abort(), psa_hash_finish() or psa_hash_verify() is safe and has no effect.
 *
 * Return:
 * * PSA_SUCCESS
 * * PSA_ERROR_COMMUNICATION_FAILURE
 * * PSA_ERROR_HARDWARE_FAILURE
 * * PSA_ERROR_CORRUPTION_DETECTED
 * * PSA_ERROR_BAD_STATE:
 *	The library has not been previously initialized by psa_crypto_init(). It is
 *	implementation-dependent whether a failure to initialize results in this error code.
 */
psa_status_t psa_hash_abort(psa_hash_operation_t *operation);

/**
 * psa_hash_clone() - Clone a hash operation.
 * @source_operation: The active hash operation to clone.
 * @target_operation: The operation object to set up. It must be initialized but not active.
 *
 * **Warning: Not supported**
 *
 * This function copies the state of an ongoing hash operation to a new operation object. In other
 * words, this function is equivalent to calling psa_hash_setup() on @target_operation with the same
 * algorithm that @source_operation was set up for, then psa_hash_update() on @target_operation with
 * the same input that was passed to @source_operation. After this function returns, the two objects
 * are independent, i.e. subsequent calls involving one of the objects do not affect the other
 * object.
 *
 * Return:
 * * PSA_SUCCESS
 * * PSA_ERROR_BAD_STATE:
 *	The @source_operation state is not valid: it must be active.
 * * PSA_ERROR_BAD_STATE:
 *	The @target_operation state is not valid: it must be inactive.
 * * PSA_ERROR_COMMUNICATION_FAILURE
 * * PSA_ERROR_HARDWARE_FAILURE
 * * PSA_ERROR_CORRUPTION_DETECTED
 * * PSA_ERROR_INSUFFICIENT_MEMORY
 * * PSA_ERROR_BAD_STATE:
 *	The library has not been previously initialized by psa_crypto_init(). It is
 *	implementation-dependent whether a failure to initialize results in this error code.
 */
psa_status_t psa_hash_clone(const psa_hash_operation_t *source_operation,
			    psa_hash_operation_t *target_operation);

/**
 * psa_hash_compare() - Calculate the hash (digest) of a message and compare it with a reference
 * value.
 * @alg: The hash algorithm to compute (PSA_ALG_XXX value such that PSA_ALG_IS_HASH(alg) is true).
 * @input: Buffer containing the message to hash.
 * @input_length: Size of the @input buffer in bytes.
 * @hash: Buffer containing the expected hash value.
 * @hash_length: Size of the @hash buffer in bytes.
 *
 * Return:
 * * PSA_SUCCESS:
 *	The expected hash is identical to the actual hash of the input.
 * * PSA_ERROR_INVALID_SIGNATURE:
 *	The hash of the message was calculated successfully, but it differs from the expected hash.
 * * PSA_ERROR_NOT_SUPPORTED:
 *	@alg is not supported or is not a hash algorithm.
 * * PSA_ERROR_INVALID_ARGUMENT:
 *	@input_length or @hash_length do not match the hash size for @alg
 * * PSA_ERROR_INSUFFICIENT_MEMORY
 * * PSA_ERROR_COMMUNICATION_FAILURE
 * * PSA_ERROR_HARDWARE_FAILURE
 * * PSA_ERROR_CORRUPTION_DETECTED
 * * PSA_ERROR_INSUFFICIENT_MEMORY
 * * PSA_ERROR_BAD_STATE:
 *	The library has not been previously initialized by psa_crypto_init(). It is
 *	implementation-dependent whether a failure to initialize results in this error code.
 */
psa_status_t psa_hash_compare(psa_algorithm_t alg, const uint8_t *input,
			      size_t input_length, const uint8_t *hash,
			      size_t hash_length);

/**
 * psa_hash_compute() - Calculate the hash (digest) of a message.
 * @alg: The hash algorithm to compute (PSA_ALG_XXX value such that PSA_ALG_IS_HASH(alg) is true).
 * @input: Buffer containing the message to hash.
 * @input_length: Size of the @input buffer in bytes.
 * @hash: Buffer where the hash is to be written.
 * @hash_size: Size of the @hash buffer in bytes. This must be at least PSA_HASH_LENGTH(alg).
 * @hash_length: On success, the number of bytes that make up the hash value. This is always
 *               PSA_HASH_LENGTH(alg).
 *
 * **Note**:
 *	To verify the hash of a message against an expected value, use psa_hash_compare() instead.
 *
 * Return:
 * * PSA_SUCCESS:
 *	Success.
 * * PSA_ERROR_NOT_SUPPORTED:
 *	@alg is not supported or is not a hash algorithm.
 * * PSA_ERROR_INVALID_ARGUMENT
 * * PSA_ERROR_BUFFER_TOO_SMALL:
 *	@hash_size is too small. PSA_HASH_LENGTH() can be used to determine the required buffer
 *	size.
 * * PSA_ERROR_INSUFFICIENT_MEMORY
 * * PSA_ERROR_COMMUNICATION_FAILURE
 * * PSA_ERROR_HARDWARE_FAILURE
 * * PSA_ERROR_CORRUPTION_DETECTED
 * * PSA_ERROR_INSUFFICIENT_MEMORY
 * * PSA_ERROR_BAD_STATE:
 *	The library has not been previously initialized by psa_crypto_init(). It is
 *	implementation-dependent whether a failure to initialize results in this error code.
 */
psa_status_t psa_hash_compute(psa_algorithm_t alg, const uint8_t *input,
			      size_t input_length, uint8_t *hash,
			      size_t hash_size, size_t *hash_length);

/**
 * psa_hash_finish() - Finish the calculation of the hash of a message.
 * @operation: Active hash operation.
 * @hash: Buffer where the hash is to be written.
 * @hash_size: Size of the @hash buffer in bytes. This must be at least PSA_HASH_LENGTH(alg) where
 *             alg is the algorithm that the operation performs.
 * @hash_length: On success, the number of bytes that make up the hash value. This is always
 *               PSA_HASH_LENGTH(alg) where alg is the hash algorithm that the operation performs.
 *
 * **Warning: Not supported**
 *
 * The application must call psa_hash_setup() or psa_hash_resume() before calling this function.
 * This function calculates the hash of the message formed by concatenating the inputs passed to
 * preceding calls to psa_hash_update().
 *
 * When this function returns successfully, the operation becomes inactive. If this function returns
 * an error status, the operation enters an error state and must be aborted by calling
 * psa_hash_abort().
 *
 * **Warning**:
 *	It is not recommended to use this function when a specific value is expected for the hash.
 *	Call psa_hash_verify() instead with the expected hash value.
 *
 *	Comparing integrity or authenticity data such as hash values with a function such as
 *	memcmp() is risky because the time taken by the comparison might leak information about the
 *	hashed data which could allow an attacker to guess a valid hash and thereby bypass security
 *	controls.
 *
 * Return:
 * * PSA_SUCCESS:
 *	Success.
 * * PSA_ERROR_BAD_STATE:
 *	The operation state is not valid: it must be active.
 * * PSA_ERROR_BUFFER_TOO_SMALL:
 *	The size of the @hash buffer is too small. PSA_HASH_LENGTH() can be used to determine the
 *	required buffer size.
 * * PSA_ERROR_INSUFFICIENT_MEMORY
 * * PSA_ERROR_COMMUNICATION_FAILURE
 * * PSA_ERROR_HARDWARE_FAILURE
 * * PSA_ERROR_CORRUPTION_DETECTED
 * * PSA_ERROR_BAD_STATE:
 *	The library has not been previously initialized by psa_crypto_init(). It is
 *	implementation-dependent whether a failure to initialize results in this error code.
 */
psa_status_t psa_hash_finish(psa_hash_operation_t *operation, uint8_t *hash,
			     size_t hash_size, size_t *hash_length);

/**
 * psa_hash_operation_init() - Return an initial value for a hash operation object.
 *
 * Return:
 * &typedef psa_hash_operation_t
 */
static psa_hash_operation_t psa_hash_operation_init(void);

/**
 * psa_hash_resume() - Set up a multi-part hash operation using the hash suspend state from a
 * previously suspended hash operation.
 * @operation: The operation object to set up. It must have been initialized as per the
 *             documentation for &typedef psa_hash_operation_t and not yet in use.
 * @hash_state: A buffer containing the suspended hash state which is to be resumed. This must be in
 *              the format output by psa_hash_suspend(), which is described in Hash suspend state
 *              format.
 * @hash_state_length: Length of @hash_state in bytes.
 *
 * **Warning: Not supported**
 *
 * See psa_hash_suspend() for an example of how to use this function to suspend and resume a hash
 * operation.
 *
 * After a successful call to psa_hash_resume(), the application must eventually terminate the
 * operation. The following events terminate an operation\:
 *
 * - A successful call to psa_hash_finish(), psa_hash_verify() or psa_hash_suspend().
 *
 * - A call to psa_hash_abort().
 *
 * Return:
 * * PSA_SUCCESS:
 *	Success.
 * * PSA_ERROR_NOT_SUPPORTED:
 *	The provided hash suspend state is for an algorithm that is not supported.
 * * PSA_ERROR_INVALID_ARGUMENT:
 *	@hash_state does not correspond to a valid hash suspend state. See Hash suspend state format
 *	for the definition.
 * * PSA_ERROR_BAD_STATE:
 *	The operation state is not valid: it must be inactive.
 * * PSA_ERROR_INSUFFICIENT_MEMORY
 * * PSA_ERROR_COMMUNICATION_FAILURE
 * * PSA_ERROR_HARDWARE_FAILURE
 * * PSA_ERROR_CORRUPTION_DETECTED
 * * PSA_ERROR_BAD_STATE:
 *	The library has not been previously initialized by psa_crypto_init(). It is
 *	implementation-dependent whether a failure to initialize results in this error code.
 */
psa_status_t psa_hash_resume(psa_hash_operation_t *operation,
			     const uint8_t *hash_state,
			     size_t hash_state_length);

/**
 * psa_hash_setup() - Set up a multi-part hash operation.
 * @operation: The operation object to set up. It must have been initialized as per the
 *             documentation for &typedef psa_hash_operation_t and not yet in use.
 * @alg: The hash algorithm to compute (PSA_ALG_XXX value such that PSA_ALG_IS_HASH(alg) is true).
 *
 * **Warning: Not supported**
 *
 * The sequence of operations to calculate a hash (message digest) is as follows\:
 *
 * #. Allocate an operation object which will be passed to all the functions listed here.
 *
 * #. Initialize the operation object with one of the methods described in the documentation for
 *    &typedef psa_hash_operation_t, e.g. PSA_HASH_OPERATION_INIT.
 *
 * #. Call psa_hash_setup() to specify the algorithm.
 *
 * #. Call psa_hash_update() zero, one or more times, passing a fragment of the message each time.
 *    The hash that is calculated is the hash of the concatenation of these messages in order.
 *
 * #. To calculate the hash, call psa_hash_finish(). To compare the hash with an expected value,
 *    call psa_hash_verify(). To suspend the hash operation and extract the current state, call
 *    psa_hash_suspend().
 *
 * If an error occurs at any step after a call to psa_hash_setup(), the operation will need to be
 * reset by a call to psa_hash_abort(). The application can call psa_hash_abort() at any time after
 * the operation has been initialized.
 *
 * After a successful call to psa_hash_setup(), the application must eventually terminate the
 * operation. The following events terminate an operation:
 *
 * - A successful call to psa_hash_finish() or psa_hash_verify() or psa_hash_suspend().
 *
 * - A call to psa_hash_abort().
 *
 * Return:
 * * PSA_SUCCESS:
 *	Success.
 * * PSA_ERROR_NOT_SUPPORTED:
 *	@alg is not a supported hash algorithm.
 * * PSA_ERROR_INVALID_ARGUMENT:
 *	@alg is not a hash algorithm.
 * * PSA_ERROR_BAD_STATE:
 *	The operation state is not valid: it must be inactive.
 * * PSA_ERROR_INSUFFICIENT_MEMORY
 * * PSA_ERROR_COMMUNICATION_FAILURE
 * * PSA_ERROR_HARDWARE_FAILURE
 * * PSA_ERROR_CORRUPTION_DETECTED
 * * PSA_ERROR_BAD_STATE:
 *	The library has not been previously initialized by psa_crypto_init(). It is
 *	implementation-dependent whether a failure to initialize results in this error code.
 */
psa_status_t psa_hash_setup(psa_hash_operation_t *operation,
			    psa_algorithm_t alg);

/**
 * psa_hash_suspend() - Halt the hash operation and extract the intermediate state of the hash
 * computation.
 * @operation: Active hash operation.
 * @hash_state: Buffer where the hash suspend state is to be written.
 * @hash_state_size: Size of the @hash_state buffer in bytes.
 * @hash_state_length: On success, the number of bytes that make up the hash suspend state.
 *
 * **Warning: Not supported**
 *
 * The application must call psa_hash_setup() or psa_hash_resume() before calling this function.
 * This function extracts an intermediate state of the hash computation of the message formed by
 * concatenating the inputs passed to preceding calls to psa_hash_update().
 *
 * This function can be used to halt a hash operation, and then resume the hash operation at a later
 * time, or in another application, by transferring the extracted hash suspend state to a call to
 * psa_hash_resume().
 *
 * When this function returns successfully, the operation becomes inactive. If this function returns
 * an error status, the operation enters an error state and must be aborted by calling
 * psa_hash_abort().
 *
 * Hash suspend and resume is not defined for the SHA3 family of hash algorithms. Hash suspend state
 * defines the format of the output from psa_hash_suspend().
 *
 * **Warning**:
 *	Applications must not use any of the hash suspend state as if it was a hash output. Instead,
 *	the suspend state must only be used to resume a hash operation, and psa_hash_finish() or
 *	psa_hash_verify() can then calculate or verify the final hash value.
 *
 * Parameter @hash_state_size must be appropriate for the selected algorithm:
 *
 * - A sufficient output size is PSA_HASH_SUSPEND_OUTPUT_SIZE(alg) where alg is the algorithm that
 *   was used to set up the operation.
 *
 * - PSA_HASH_SUSPEND_OUTPUT_MAX_SIZE evaluates to the maximum output size of any supported hash
 *   algorithm.
 *
 * Return:
 * * PSA_SUCCESS:
 *	Success.
 * * PSA_ERROR_BAD_STATE:
 *	The operation state is not valid: it must be active.
 * * PSA_ERROR_BUFFER_TOO_SMALL:
 *	The size of the @hash_state buffer is too small. PSA_HASH_SUSPEND_OUTPUT_SIZE() or
 *	PSA_HASH_SUSPEND_OUTPUT_MAX_SIZE can be used to determine the required buffer size.
 * * PSA_ERROR_NOT_SUPPORTED:
 *	The hash algorithm being computed does not support suspend and resume.
 * * PSA_ERROR_INSUFFICIENT_MEMORY
 * * PSA_ERROR_COMMUNICATION_FAILURE
 * * PSA_ERROR_HARDWARE_FAILURE
 * * PSA_ERROR_CORRUPTION_DETECTED
 * * PSA_ERROR_BAD_STATE:
 *	The library has not been previously initialized by psa_crypto_init(). It is
 *	implementation-dependent whether a failure to initialize results in this error code.
 */
psa_status_t psa_hash_suspend(psa_hash_operation_t *operation,
			      uint8_t *hash_state, size_t hash_state_size,
			      size_t *hash_state_length);

/**
 * psa_hash_update() - Add a message fragment to a multi-part hash operation.
 * @operation: Active hash operation.
 * @input: Buffer containing the message fragment to hash.
 * @input_length: Size of the @input buffer in bytes.
 *
 * **Warning: Not supported**
 *
 * The application must call psa_hash_setup() or psa_hash_resume() before calling this function.
 *
 * If this function returns an error status, the operation enters an error state and must be aborted
 * by calling psa_hash_abort().
 *
 * Return:
 * * PSA_SUCCESS:
 *	Success.
 * * PSA_ERROR_BAD_STATE:
 *	The operation state is not valid: it must be active.
 * * PSA_ERROR_INSUFFICIENT_MEMORY
 * * PSA_ERROR_COMMUNICATION_FAILURE
 * * PSA_ERROR_HARDWARE_FAILURE
 * * PSA_ERROR_CORRUPTION_DETECTED
 * * PSA_ERROR_BAD_STATE:
 *	The library has not been previously initialized by psa_crypto_init(). It is
 *	implementation-dependent whether a failure to initialize results in this error code.
 */
psa_status_t psa_hash_update(psa_hash_operation_t *operation,
			     const uint8_t *input, size_t input_length);

/**
 * psa_hash_verify() - Finish the calculation of the hash of a message and compare it with an
 * expected value.
 * @operation: Active hash operation.
 * @hash: Buffer containing the expected hash value.
 * @hash_length: Size of the @hash buffer in bytes.
 *
 * **Warning: Not supported**
 *
 * The application must call psa_hash_setup() before calling this function. This function calculates
 * the hash of the message formed by concatenating the inputs passed to preceding calls to
 * psa_hash_update(). It then compares the calculated hash with the expected hash passed as a
 * parameter to this function.
 *
 * When this function returns successfully, the operation becomes inactive. If this function returns
 * an error status, the operation enters an error state and must be aborted by calling
 * psa_hash_abort().
 *
 * **Note**:
 *	Implementations must make the best effort to ensure that the comparison between the actual
 *	hash and the expected hash is performed in constant time.
 *
 * Return:
 * * PSA_SUCCESS:
 *	The expected hash is identical to the actual hash of the message.
 * * PSA_ERROR_INVALID_SIGNATURE:
 *	The hash of the message was calculated successfully, but it differs from the expected hash.
 * * PSA_ERROR_BAD_STATE:
 *	The operation state is not valid: it must be active.
 * * PSA_ERROR_INSUFFICIENT_MEMORY
 * * PSA_ERROR_COMMUNICATION_FAILURE
 * * PSA_ERROR_HARDWARE_FAILURE
 * * PSA_ERROR_CORRUPTION_DETECTED
 * * PSA_ERROR_BAD_STATE:
 *	The library has not been previously initialized by psa_crypto_init(). It is
 *	implementation-dependent whether a failure to initialize results in this error code.
 */
psa_status_t psa_hash_verify(psa_hash_operation_t *operation,
			     const uint8_t *hash, size_t hash_length);

/**
 * psa_import_key() - Import a key in binary format.
 * @attributes: The attributes for the new key.
 * @data: Buffer containing the key data. The content of this buffer is interpreted according to the
 *        type declared in attributes. All implementations must support at least the format
 *        described in the documentation of psa_export_key() or psa_export_public_key() for the
 *        chosen type. Implementations can support other formats, but be conservative in
 *        interpreting the key data: it is recommended that implementations reject content if it
 *        might be erroneous, for example, if it is the wrong type or is truncated.
 * @data_length: Size of the @data buffer in bytes.
 * @key: On success, an identifier for the newly created key. PSA_KEY_ID_NULL on failure.
 *
 * **Warning: Import of private key may be not supported depending on the secure subsystem in use.**
 *
 * This function supports any output from psa_export_key(). Refer to the documentation of
 * psa_export_public_key() for the format of public keys and to the documentation of
 * psa_export_key() for the format for other key types.
 *
 * The key data determines the key size. The attributes can optionally specify a key size; in this
 * case it must match the size determined from the key data. A key size of 0 in attributes indicates
 * that the key size is solely determined by the key data.
 *
 * Implementations must reject an attempt to import a key of size 0.
 *
 * This specification defines a single format for each key type. Implementations can optionally
 * support other formats in addition to the standard format. It is recommended that implementations
 * that support other formats ensure that the formats are clearly unambiguous, to minimize the risk
 * that an invalid input is accidentally interpreted according to a different format.
 *
 * **Note**:
 *	The PSA Crypto API does not support asymmetric private key objects outside of a key pair. To
 *	import a private key, the attributes must specify the corresponding key pair type. Depending
 *	on the key type, either the import format contains the public key data or the implementation
 *	will reconstruct the public key from the private key as needed.
 *
 * This function uses the attributes as follows\:
 *
 * - The key type is required, and determines how the @data buffer is interpreted.
 *
 * - The key size is always determined from the data buffer. If the key size in attributes is
 *   nonzero, it must be equal to the size determined from @data.
 *
 * - The key permitted-algorithm policy is required for keys that will be used for a cryptographic
 *   peration, see Permitted algorithms.
 *
 * - The key usage flags define what operations are permitted with the key, see Key usage flags.
 *
 * - The key lifetime and identifier are required for a persistent key.
 *
 *   **Note**:
 *	This is an input parameter: it is not updated with the final key attributes. The final
 *	attributes of the new key can be queried by calling psa_get_key_attributes() with the
 *	key’s identifier.
 *
 * Return:
 * * PSA_SUCCESS:
 *	Success. If the key is persistent, the key material and the key’s metadata have been saved
 *	to persistent storage.
 * * PSA_ERROR_ALREADY_EXISTS:
 *	This is an attempt to create a persistent key, and there is already a persistent key with
 *	the given identifier.
 * * PSA_ERROR_NOT_SUPPORTED:
 *	The key type or key size is not supported, either by the implementation in general or in
 *	this particular persistent location.
 * * PSA_ERROR_INVALID_ARGUMENT:
 *	The key attributes, as a whole, are invalid.
 * * PSA_ERROR_INVALID_ARGUMENT:
 *	The key data is not correctly formatted.
 * * PSA_ERROR_INVALID_ARGUMENT:
 *	The size in @attributes is nonzero and does not match the size of the key data.
 * * PSA_ERROR_INSUFFICIENT_MEMORY
 * * PSA_ERROR_INSUFFICIENT_STORAGE
 * * PSA_ERROR_COMMUNICATION_FAILURE
 * * PSA_ERROR_STORAGE_FAILURE
 * * PSA_ERROR_DATA_CORRUPT
 * * PSA_ERROR_DATA_INVALID
 * * PSA_ERROR_HARDWARE_FAILURE
 * * PSA_ERROR_CORRUPTION_DETECTED
 * * PSA_ERROR_BAD_STATE:
 *	The library has not been previously initialized by psa_crypto_init(). It is
 *	implementation-dependent whether a failure to initialize results in this error code.
 */
psa_status_t psa_import_key(const psa_key_attributes_t *attributes,
			    const uint8_t *data, size_t data_length,
			    psa_key_id_t *key);

/**
 * psa_key_attributes_init() - Return an initial value for a key attribute object.
 *
 * Return:
 * &typedef psa_key_attributes_t
 */
static psa_key_attributes_t psa_key_attributes_init(void);

/**
 * psa_key_derivation_abort() - Abort a key derivation operation.
 * @operation: The operation to abort.
 *
 * **Warning: Not supported**
 *
 * Aborting an operation frees all associated resources except for the operation object itself.
 * Once aborted, the operation object can be reused for another operation by calling
 * psa_key_derivation_setup() again.
 *
 * This function can be called at any time after the operation object has been initialized as
 * described in &typedef psa_key_derivation_operation_t.
 *
 * In particular, it is valid to call psa_key_derivation_abort() twice, or to call
 * psa_key_derivation_abort() on an operation that has not been set up.
 *
 * Return:
 * * PSA_SUCCESS
 * * PSA_ERROR_COMMUNICATION_FAILURE
 * * PSA_ERROR_HARDWARE_FAILURE
 * * PSA_ERROR_CORRUPTION_DETECTED
 * * PSA_ERROR_BAD_STATE:
 *	The library has not been previously initialized by psa_crypto_init(). It is
 *	implementation-dependent whether a failure to initialize results in this error code.
 */
psa_status_t
psa_key_derivation_abort(psa_key_derivation_operation_t *operation);

/**
 * psa_key_derivation_get_capacity() - Retrieve the current capacity of a key derivation operation.
 * @operation: The operation to query.
 * @capacity: On success, the capacity of the operation.
 *
 * **Warning: Not supported**
 *
 * The capacity of a key derivation is the maximum number of bytes that it can return. Reading N
 * bytes of output from a key derivation operation reduces its capacity by at least N. The capacity
 * can be reduced by more than N in the following situations\:
 *
 * - Calling psa_key_derivation_output_key() can reduce the capacity by more than the key size,
 *   depending on the type of key being generated. See psa_key_derivation_output_key() for details
 *   of the key derivation process.
 *
 * - When the &typedef psa_key_derivation_operation_t object is operating as a deterministic random
 *   bit generator (DBRG), which reduces capacity in whole blocks, even when less than a block is
 *   read.
 *
 * Return:
 * * PSA_SUCCESS
 * * PSA_ERROR_COMMUNICATION_FAILURE
 * * PSA_ERROR_BAD_STATE:
 *	The operation state is not valid: it must be active.
 * * PSA_ERROR_HARDWARE_FAILURE
 * * PSA_ERROR_CORRUPTION_DETECTED
 * * PSA_ERROR_BAD_STATE:
 *	The library has not been previously initialized by psa_crypto_init(). It is
 *	implementation-dependent whether a failure to initialize results in this error code.
 */
psa_status_t
psa_key_derivation_get_capacity(const psa_key_derivation_operation_t *operation,
				size_t *capacity);

/**
 * psa_key_derivation_input_bytes() - Provide an input for key derivation or key agreement.
 * @operation: The key derivation operation object to use. It must have been set up with
 *             psa_key_derivation_setup() and must not have produced any output yet.
 * @step: Which step the input data is for.
 * @data: Input data to use.
 * @data_length: Size of the @data buffer in bytes.
 *
 * **Warning: Not supported**
 *
 * Which inputs are required and in what order depends on the algorithm. Refer to the documentation
 * of each key derivation or key agreement algorithm for information.
 *
 * This function passes direct inputs, which is usually correct for non-secret inputs. To pass a
 * secret input, which is normally in a key object, call psa_key_derivation_input_key() instead of
 * this function. Refer to the documentation of individual step types (PSA_KEY_DERIVATION_INPUT_xxx
 * values of &typedef psa_key_derivation_step_t) for more information.
 *
 * If this function returns an error status, the operation enters an error state and must be aborted
 * by calling psa_key_derivation_abort().
 *
 * Return:
 * * PSA_SUCCESS:
 *	Success.
 * * PSA_ERROR_INVALID_ARGUMENT:
 *	@step is not compatible with the operation’s algorithm.
 * * PSA_ERROR_INVALID_ARGUMENT:
 *	@step does not allow direct inputs.
 * * PSA_ERROR_INSUFFICIENT_MEMORY
 * * PSA_ERROR_COMMUNICATION_FAILURE
 * * PSA_ERROR_HARDWARE_FAILURE
 * * PSA_ERROR_CORRUPTION_DETECTED
 * * PSA_ERROR_STORAGE_FAILURE
 * * PSA_ERROR_DATA_CORRUPT
 * * PSA_ERROR_DATA_INVALID
 * * PSA_ERROR_BAD_STATE:
 *	The operation state is not valid for this input step. This can happen if the application
 *	provides a step out of order or repeats a step that may not be repeated.
 * * PSA_ERROR_BAD_STATE:
 *	The library has not been previously initialized by psa_crypto_init(). It is
 *	implementation-dependent whether a failure to initialize results in this error code.
 */
psa_status_t
psa_key_derivation_input_bytes(psa_key_derivation_operation_t *operation,
			       psa_key_derivation_step_t step,
			       const uint8_t *data, size_t data_length);

/**
 * psa_key_derivation_input_integer() - Provide a numeric input for key derivation or key
 * agreement.
 * @operation: The key derivation operation object to use. It must have been set up with
 *             psa_key_derivation_setup() and must not have produced any output yet.
 * @step: Which step the input data is for.
 * @value: The value of the numeric input.
 *
 * **Warning: Not supported**
 *
 * Which inputs are required and in what order depends on the algorithm. However, when an algorithm
 * requires a particular order, numeric inputs usually come first as they tend to be configuration
 * parameters.
 * Refer to the documentation of each key derivation or key agreement algorithm for information.
 *
 * This function is used for inputs which are fixed-size non-negative integers.
 *
 * If this function returns an error status, the operation enters an error state and must be
 * aborted by calling psa_key_derivation_abort().
 *
 * Return:
 * * PSA_SUCCESS:
 *	Success.
 * * PSA_ERROR_BAD_STATE:
 *	The following conditions can result in this error\:
 *
 *	- The operation state is not valid for this input @step. This can happen if the application
 *	  provides a step out of order or repeats a step that may not be repeated.
 *	- The library requires initializing by a call to psa_crypto_init().
 * * PSA_ERROR_INVALID_ARGUMENT:
 *	The following conditions can result in this error\:
 *
 *	- @step is not compatible with the operation’s algorithm.
 *	- @step does not allow numerical inputs.
 *	- @value is not valid for @step in the operation’s algorithm.
 * * PSA_ERROR_NOT_SUPPORTED:
 *	The following conditions can result in this error\:
 *
 *	- @step is not supported with the operation’s algorithm.
 *	- @value is not supported for @step in the operation’s algorithm.
 * * PSA_ERROR_INSUFFICIENT_MEMORY
 * * PSA_ERROR_COMMUNICATION_FAILURE
 * * PSA_ERROR_CORRUPTION_DETECTED
 * * PSA_ERROR_STORAGE_FAILURE
 * * PSA_ERROR_DATA_CORRUPT
 * * PSA_ERROR_DATA_INVALID
 */
psa_status_t
psa_key_derivation_input_integer(psa_key_derivation_operation_t *operation,
				 psa_key_derivation_step_t step,
				 uint64_t value);

/**
 * psa_key_derivation_input_key() - Provide an input for key derivation in the form of a key.
 * @operation: The key derivation operation object to use. It must have been set up with
 *             psa_key_derivation_setup() and must not have produced any output yet.
 * @step: Which step the input data is for.
 * @key: Identifier of the key. It must have an appropriate type for step and must allow the usage
 *       PSA_KEY_USAGE_DERIVE.
 *
 * **Warning: Not supported**
 *
 * Which inputs are required and in what order depends on the algorithm. Refer to the documentation
 * of each key derivation or key agreement algorithm for information.
 *
 * This function obtains input from a key object, which is usually correct for secret inputs or for
 * non-secret personalization strings kept in the key store. To pass a non-secret parameter which is
 * not in the key store, call psa_key_derivation_input_bytes() instead of this function. Refer to
 * the documentation of individual step types (PSA_KEY_DERIVATION_INPUT_xxx values of type
 * &typedef psa_key_derivation_step_t) for more information.
 *
 * If this function returns an error status, the operation enters an error state and must be aborted
 * by calling psa_key_derivation_abort().
 *
 * Return:
 * * PSA_SUCCESS:
 *	Success.
 * * PSA_ERROR_INVALID_HANDLE
 * * PSA_ERROR_NOT_PERMITTED:
 *	The key does not have the PSA_KEY_USAGE_DERIVE flag.
 * * PSA_ERROR_INVALID_ARGUMENT:
 *	@step is not compatible with the operation’s algorithm.
 * * PSA_ERROR_INVALID_ARGUMENT:
 *	@step does not allow key inputs of the given type or does not allow key inputs at all.
 * * PSA_ERROR_INSUFFICIENT_MEMORY
 * * PSA_ERROR_COMMUNICATION_FAILURE
 * * PSA_ERROR_HARDWARE_FAILURE
 * * PSA_ERROR_CORRUPTION_DETECTED
 * * PSA_ERROR_STORAGE_FAILURE
 * * PSA_ERROR_DATA_CORRUPT
 * * PSA_ERROR_DATA_INVALID
 * * PSA_ERROR_BAD_STATE:
 *	The operation state is not valid for this input step. This can happen if the application
 *	provides a step out of order or repeats a step that may not be repeated.
 * * PSA_ERROR_BAD_STATE:
 *	The library has not been previously initialized by psa_crypto_init(). It is
 *	implementation-dependent whether a failure to initialize results in this error code.
 */
psa_status_t
psa_key_derivation_input_key(psa_key_derivation_operation_t *operation,
			     psa_key_derivation_step_t step, psa_key_id_t key);

/**
 * psa_key_derivation_key_agreement() - Perform a key agreement and use the shared secret as input
 * to a key derivation.
 * @operation: The key derivation operation object to use. It must have been set up with
 *             psa_key_derivation_setup() with a key agreement and derivation algorithm alg
 *             (PSA_ALG_XXX value such that PSA_ALG_IS_KEY_AGREEMENT(alg) is true and
 *             PSA_ALG_IS_RAW_KEY_AGREEMENT(alg) is false). The operation must be ready for an input
 *             of the type given by step.
 * @step: Which step the input data is for.
 * @private_key: Identifier of the private key to use. It must allow the usage PSA_KEY_USAGE_DERIVE.
 * @peer_key: Public key of the peer. The peer key must be in the same format that psa_import_key()
 *            accepts for the public key type corresponding to the type of @private_key. That is,
 *            this function performs the equivalent of psa_import_key(..., peer_key,
 *            peer_key_length) where with key attributes indicating the public key type
 *            corresponding to the type of @private_key. For example, for EC keys, this means that
 *            @peer_key is interpreted as a point on the curve that the private key is on. The
 *            standard formats for public keys are documented in the documentation of
 *            psa_export_public_key().
 * @peer_key_length: Size of @peer_key in bytes.
 *
 * **Warning: Not supported**
 *
 * A key agreement algorithm takes two inputs: a private key @private_key a public key @peer_key.
 * The result of this function is passed as input to a key derivation. The output of this key
 * derivation can be extracted by reading from the resulting operation to produce keys and other
 * cryptographic material.
 *
 * If this function returns an error status, the operation enters an error state and must be aborted
 * by calling psa_key_derivation_abort().
 *
 * Return:
 * * PSA_SUCCESS:
 *	Success.
 * * PSA_ERROR_BAD_STATE:
 *	The operation state is not valid for this key agreement step.
 * * PSA_ERROR_INVALID_HANDLE
 * * PSA_ERROR_NOT_PERMITTED:
 *	The key does not have the PSA_KEY_USAGE_DERIVE flag, or it does not permit the requested
 *	algorithm.
 * * PSA_ERROR_INVALID_ARGUMENT:
 *	private_@key is not compatible with @alg, or @peer_key is not valid for alg or not
 *	compatible
 *	with @private_key.
 * * PSA_ERROR_NOT_SUPPORTED:
 *	@alg is not supported or is not a key derivation algorithm.
 * * PSA_ERROR_INVALID_ARGUMENT:
 *	@step does not allow an input resulting from a key agreement.
 * * PSA_ERROR_INSUFFICIENT_MEMORY
 * * PSA_ERROR_COMMUNICATION_FAILURE
 * * PSA_ERROR_HARDWARE_FAILURE
 * * PSA_ERROR_CORRUPTION_DETECTED
 * * PSA_ERROR_STORAGE_FAILURE
 * * PSA_ERROR_DATA_CORRUPT
 * * PSA_ERROR_DATA_INVALID
 * * PSA_ERROR_BAD_STATE:
 *	The library has not been previously initialized by psa_crypto_init(). It is
 *	implementation-dependent whether a failure to initialize results in this error code.
 */
psa_status_t
/* Without this comment clang-format does not meet the checkpatch requirement. */
psa_key_derivation_key_agreement(psa_key_derivation_operation_t *operation,
				 psa_key_derivation_step_t step,
				 psa_key_id_t private_key,
				 const uint8_t *peer_key,
				 size_t peer_key_length);

/**
 * psa_key_derivation_operation_init() - Return an initial value for a key derivation operation
 * object.
 *
 * Return:
 * &typedef psa_key_derivation_operation_t
 */
static psa_key_derivation_operation_t psa_key_derivation_operation_init(void);

/**
 * psa_key_derivation_output_bytes() - Read some data from a key derivation operation.
 * @operation: The key derivation operation object to read from.
 * @output: Buffer where the output will be written.
 * @output_length: Number of bytes to @output.
 *
 * **Warning: Not supported**
 *
 * This function calculates output bytes from a key derivation algorithm and returns those bytes.
 * If the key derivation’s output is viewed as a stream of bytes, this function consumes the
 * requested number of bytes from the stream and returns them to the caller. The operation’s
 * capacity decreases by the number of bytes read.
 *
 * If this function returns an error status other than PSA_ERROR_INSUFFICIENT_DATA, the operation
 * enters an error state and must be aborted by calling psa_key_derivation_abort().
 *
 * Return:
 * * PSA_SUCCESS
 * * PSA_ERROR_INSUFFICIENT_DATA:
 *	The operation’s capacity was less than @output_length bytes. Note that in this case, no
 *	output is written to the @output buffer. The operation’s capacity is set to 0, thus
 *	subsequent calls to this function will not succeed, even with a smaller @output buffer.
 * * PSA_ERROR_BAD_STATE:
 *	The operation state is not valid: it must be active and completed all required input steps.
 * * PSA_ERROR_INSUFFICIENT_MEMORY
 * * PSA_ERROR_COMMUNICATION_FAILURE
 * * PSA_ERROR_HARDWARE_FAILURE
 * * PSA_ERROR_CORRUPTION_DETECTED
 * * PSA_ERROR_STORAGE_FAILURE
 * * PSA_ERROR_DATA_CORRUPT
 * * PSA_ERROR_DATA_INVALID
 * * PSA_ERROR_BAD_STATE:
 *	The library has not been previously initialized by psa_crypto_init(). It is
 *	implementation-dependent whether a failure to initialize results in this error code.
 */
psa_status_t
psa_key_derivation_output_bytes(psa_key_derivation_operation_t *operation,
				uint8_t *output, size_t output_length);

/**
 * psa_key_derivation_output_key() - Derive a key from an ongoing key derivation operation.
 * @attributes: The attributes for the new key.
 * @operation: The key derivation operation object to read from.
 * @key: On success, an identifier for the newly created key. PSA_KEY_ID_NULL on failure.
 *
 * **Warning: Not supported**
 *
 * This function calculates output bytes from a key derivation algorithm and uses those bytes to
 * generate a key deterministically. The key’s location, policy, type and size are taken from
 * @attributes.
 *
 * If the key derivation’s output is viewed as a stream of bytes, this function consumes the
 * required number of bytes from the stream. The operation’s capacity decreases by the number of
 * bytes used to derive the key.
 *
 * If this function returns an error status other than PSA_ERROR_INSUFFICIENT_DATA, the operation
 * enters an error state and must be aborted by calling psa_key_derivation_abort().
 *
 * How much output is produced and consumed from the operation, and how the key is derived, depends
 * on the key type. The table below describes the required key derivation procedures for standard
 * key derivation algorithms. Implementations can use other methods for implementation-specific
 * algorithms.
 *
 * In all cases, the data that is read is discarded from the operation. The operation’s capacity
 * is decreased by the number of bytes read.
 *
 *   .. tabularcolumns:: |\Y{0.4}|\Y{0.6}|
 *
 *   +----------------------------------+---------------------------------------------------------+
 *   | **Key type**                     | **Key type details and derivation procedure**           |
 *   +==================================+=========================================================+
 *   | AES                              | PSA_KEY_TYPE_AES                                        |
 *   +----------------------------------+---------------------------------------------------------+
 *   | ARC4                             | PSA_KEY_TYPE_ARC4                                       |
 *   +----------------------------------+---------------------------------------------------------+
 *   | CAMELLIA                         | PSA_KEY_TYPE_CAMELLIA                                   |
 *   +----------------------------------+---------------------------------------------------------+
 *   | ChaCha20                         | PSA_KEY_TYPE_CHACHA20                                   |
 *   +----------------------------------+---------------------------------------------------------+
 *   | SM4                              | PSA_KEY_TYPE_SM4                                        |
 *   +----------------------------------+---------------------------------------------------------+
 *   | Secrets for derivation           | PSA_KEY_TYPE_DERIVE                                     |
 *   +----------------------------------+---------------------------------------------------------+
 *   | HMAC                             | PSA_KEY_TYPE_HMAC                                       |
 *   |                                  |                                                         |
 *   |                                  | For key types for which the key is an arbitrary         |
 *   |                                  | sequence of bytes of a given size, this function is     |
 *   |                                  | functionally equivalent to calling                      |
 *   |                                  | psa_key_derivation_output_bytes\() and passing the       |
 *   |                                  | resulting output to psa_import_key\(). However, this     |
 *   |                                  | function has a security benefit: if the implementation  |
 *   |                                  | provides an isolation boundary then the key material    |
 *   |                                  | is not exposed outside the isolation boundary. As a     |
 *   |                                  | consequence, for these key types, this function always  |
 *   |                                  | consumes exactly (bits/8) bytes from the operation.     |
 *   +----------------------------------+---------------------------------------------------------+
 *   | DES                              | PSA_KEY_TYPE_DES, 64 bits.                              |
 *   |                                  |                                                         |
 *   |                                  | This function generates a key using the following       |
 *   |                                  | process\:                                               |
 *   |                                  |                                                         |
 *   |                                  | #. Draw an 8-byte string.                               |
 *   |                                  |                                                         |
 *   |                                  | #. Set/clear the parity bits in each byte.              |
 *   |                                  |                                                         |
 *   |                                  | #. If the result is a forbidden weak key, discard the   |
 *   |                                  |    result and return to step 1.                         |
 *   |                                  |                                                         |
 *   |                                  | #. Output the string.                                   |
 *   +----------------------------------+---------------------------------------------------------+
 *   | 2-key 3DES                       | PSA_KEY_TYPE_DES, 192 bits.                             |
 *   +----------------------------------+---------------------------------------------------------+
 *   | 3-key 3DES                       | PSA_KEY_TYPE_DES, 128 bits.                             |
 *   |                                  |                                                         |
 *   |                                  | The two or three keys are generated by repeated         |
 *   |                                  | application of the process used to generate a DES key.  |
 *   |                                  |                                                         |
 *   |                                  | For example, for 3-key 3DES, if the first 8 bytes       |
 *   |                                  | specify a weak key and the next 8 bytes do not, discard |
 *   |                                  | the first 8 bytes, use the next 8 bytes as the first    |
 *   |                                  | key, and continue reading output from the operation to  |
 *   |                                  | derive the other two keys.                              |
 *   +----------------------------------+---------------------------------------------------------+
 *   | Finite-field Diffie-Hellman keys | PSA_KEY_TYPE_DH_KEY_PAIR(dh_family) where dh_family     |
 *   |                                  | designates any Diffie-Hellman family.                   |
 *   +----------------------------------+---------------------------------------------------------+
 *   | ECC keys on a                    | PSA_KEY_TYPE_ECC_KEY_PAIR(ecc_family) where ecc_family  |
 *   | Weierstrass elliptic curve       | designates a Weierstrass curve family.                  |
 *   |                                  |                                                         |
 *   |                                  | These key types require the generation of a private key |
 *   |                                  | which is an integer in the range [1, N - 1], where N is |
 *   |                                  | the boundary of the private key domain: N is the prime  |
 *   |                                  | p for Diffie-Hellman, or the order of the curve's base  |
 *   |                                  | point for ECC.                                          |
 *   |                                  |                                                         |
 *   |                                  | Let m be the bit size of N, such that                   |
 *   |                                  | 2^m > N >= 2^(m-1). This function generates the private |
 *   |                                  | key using the following process\:                       |
 *   |                                  |                                                         |
 *   |                                  | #. Draw a byte string of length ceiling(m/8) bytes.     |
 *   |                                  |                                                         |
 *   |                                  | #. If m is not a multiple of 8, set the most            |
 *   |                                  |    significant (8 * ceiling(m/8) - m) bits of the first |
 *   |                                  |    byte in the string to zero.                          |
 *   |                                  |                                                         |
 *   |                                  | #. Convert the string to integer k by decoding it as a  |
 *   |                                  |    big-endian byte string.                              |
 *   |                                  |                                                         |
 *   |                                  | #. If k > N - 2, discard the result and return to       |
 *   |                                  |    step 1.                                              |
 *   |                                  |                                                         |
 *   |                                  | #. Output k + 1 as the private key.                     |
 *   |                                  |                                                         |
 *   |                                  | This method allows compliance to NIST standards,        |
 *   |                                  | specifically the methods titled Key-Pair Generation by  |
 *   |                                  | Testing Candidates in the following publications:       |
 *   |                                  |                                                         |
 *   |                                  | - NIST Special Publication 800-56A: Recommendation for  |
 *   |                                  |   Pair-Wise Key-Establishment Schemes Using Discrete    |
 *   |                                  |   Logarithm Cryptography [SP800-56A] §5.6.1.1.4 for     |
 *   |                                  |   Diffie-Hellman keys.                                  |
 *   |                                  |                                                         |
 *   |                                  | - [SP800-56A] §5.6.1.2.2 or FIPS Publication 186-4:     |
 *   |                                  |   Digital Signature Standard (DSS) [FIPS186-4] §B.4.2   |
 *   |                                  |   for elliptic curve keys.                              |
 *   +----------------------------------+---------------------------------------------------------+
 *   | ECC keys on a                    | PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY)    |
 *   | Montgomery elliptic curve        |                                                         |
 *   |                                  | This function always draws a byte string whose length   |
 *   |                                  | is determined by the curve, and sets the mandatory bits |
 *   |                                  | accordingly. That is\:                                  |
 *   |                                  |                                                         |
 *   |                                  | - Curve25519 (PSA_ECC_FAMILY_MONTGOMERY, 255 bits):     |
 *   |                                  |   draw a 32-byte string and process it as specified in  |
 *   |                                  |   Elliptic Curves for Security [RFC7748] §5.            |
 *   |                                  |                                                         |
 *   |                                  | - Curve448 (PSA_ECC_FAMILY_MONTGOMERY, 448 bits): draw  |
 *   |                                  |   a 56-byte string and process it as specified in       |
 *   |                                  |   [RFC7748] §5.                                         |
 *   +----------------------------------+---------------------------------------------------------+
 *   | Other key types                  | This includes PSA_KEY_TYPE_RSA_KEY_PAIR.                |
 *   |                                  |                                                         |
 *   |                                  | The way in which the operation output is consumed is    |
 *   |                                  | implementation-defined.                                 |
 *   +----------------------------------+---------------------------------------------------------+
 *
 * For algorithms that take an input step PSA_KEY_DERIVATION_INPUT_SECRET, the input to that step
 * must be provided with psa_key_derivation_input_key(). Future versions of this specification might
 * include additional restrictions on the derived key based on the attributes and strength of the
 * secret key.
 *
 * This function uses the @attributes as follows\:
 *
 * - The key type is required. It cannot be an asymmetric public key.
 *
 * - The key size is required. It must be a valid size for the key type.
 *
 * - The key permitted-algorithm policy is required for keys that will be used for a cryptographic
 *   operation, see Permitted algorithms.
 *
 * - The key usage flags define what operations are permitted with the key, see Key usage flags.
 *
 * - The key lifetime and identifier are required for a persistent key.
 *
 *   **Note**:
 *	This is an input parameter: it is not updated with the final key attributes. The final
 *	attributes of the new key can be queried by calling psa_get_key_attributes() with the
 *	key’s identifier.
 *
 * Return:
 * * PSA_SUCCESS:
 *	Success. If the key is persistent, the key material and the key’s metadata have been saved
 *	to persistent storage.
 * * PSA_ERROR_ALREADY_EXISTS:
 *     This is an attempt to create a persistent key, and there is already a persistent key with the
 *	given identifier.
 * * PSA_ERROR_INSUFFICIENT_DATA:
 *	There was not enough data to create the desired key. Note that in this case, no output is
 *	written to the output buffer. The operation’s capacity is set to 0, thus subsequent calls
 *	to this function will not succeed, even with a smaller output buffer.
 * * PSA_ERROR_NOT_SUPPORTED:
 *	The key type or key size is not supported, either by the implementation in general or in
 *	this particular location.
 * * PSA_ERROR_INVALID_ARGUMENT:
 *	The key attributes, as a whole, are invalid.
 * * PSA_ERROR_INVALID_ARGUMENT:
 *	The key type is an asymmetric public key type.
 * * PSA_ERROR_INVALID_ARGUMENT:
 *	The key size is not a valid size for the key type.
 * * PSA_ERROR_NOT_PERMITTED:
 *	The PSA_KEY_DERIVATION_INPUT_SECRET input was neither provided through a key nor the result
 *	of a key agreement.
 * * PSA_ERROR_BAD_STATE:
 *	The operation state is not valid: it must be active and completed all required input steps.
 * * PSA_ERROR_INSUFFICIENT_MEMORY
 * * PSA_ERROR_INSUFFICIENT_STORAGE
 * * PSA_ERROR_COMMUNICATION_FAILURE
 * * PSA_ERROR_HARDWARE_FAILURE
 * * PSA_ERROR_CORRUPTION_DETECTED
 * * PSA_ERROR_STORAGE_FAILURE
 * * PSA_ERROR_DATA_CORRUPT
 * * PSA_ERROR_DATA_INVALID
 * * PSA_ERROR_BAD_STATE:
 *	The library has not been previously initialized by psa_crypto_init(). It is
 *	implementation-dependent whether a failure to initialize results in this error code.
 */
psa_status_t
psa_key_derivation_output_key(const psa_key_attributes_t *attributes,
			      psa_key_derivation_operation_t *operation,
			      psa_key_id_t *key);

/**
 * psa_key_derivation_set_capacity() - Set the maximum capacity of a key derivation operation.
 * @operation: The key derivation operation object to modify.
 * @capacity: The new capacity of the operation. It must be less or equal to the operation’s
 *            current capacity.
 *
 * **Warning: Not supported**
 *
 * The capacity of a key derivation operation is the maximum number of bytes that the key derivation
 * operation can return from this point onwards.
 *
 * Return:
 * * PSA_SUCCESS
 * * PSA_ERROR_INVALID_ARGUMENT:
 *	@capacity is larger than the operation’s current capacity. In this case, the operation
 *	object remains valid and its capacity remains unchanged.
 * * PSA_ERROR_BAD_STATE:
 *	The operation state is not valid: it must be active.
 * * PSA_ERROR_COMMUNICATION_FAILURE
 * * PSA_ERROR_HARDWARE_FAILURE
 * * PSA_ERROR_CORRUPTION_DETECTED
 * * PSA_ERROR_BAD_STATE:
 *	The library has not been previously initialized by psa_crypto_init(). It is
 *	implementation-dependent whether a failure to initialize results in this error code.
 *
 */
psa_status_t
psa_key_derivation_set_capacity(psa_key_derivation_operation_t *operation,
				size_t capacity);

/**
 * psa_key_derivation_setup() - Set up a key derivation operation.
 * @operation: The key derivation operation object to set up. It must have been initialized but not
 *             set up yet.
 * @alg: The key derivation algorithm to compute (PSA_ALG_XXX value such that
 *       PSA_ALG_IS_KEY_DERIVATION(alg) is true).
 *
 * **Warning: Not supported**
 *
 * A key derivation algorithm takes some inputs and uses them to generate a byte stream in a
 * deterministic way. This byte stream can be used to produce keys and other cryptographic material.
 *
 * To derive a key\:
 *
 * #. Start with an initialized object of &typedef psa_key_derivation_operation_t.
 *
 * #. Call psa_key_derivation_setup() to select the algorithm.
 *
 * #. Provide the inputs for the key derivation by calling psa_key_derivation_input_bytes() or
 *    psa_key_derivation_input_key() as appropriate. Which inputs are needed, in what order, whether
 *    keys are permitted, and what type of keys depends on the algorithm.
 *
 * #. Optionally set the operation’s maximum capacity with psa_key_derivation_set_capacity(). This
 *    can be done before, in the middle of, or after providing inputs. For some algorithms, this
 *    step is mandatory because the output depends on the maximum capacity.
 *
 * #. To derive a key, call psa_key_derivation_output_key(). To derive a byte string for a different
 *    purpose, call psa_key_derivation_output_bytes(). Successive calls to these functions use
 *    successive output bytes calculated by the key derivation algorithm.
 *
 * #. Clean up the key derivation operation object with psa_key_derivation_abort().
 *
 * If this function returns an error, the key derivation operation object is not changed.
 *
 * If an error occurs at any step after a call to psa_key_derivation_setup(), the operation will
 * need to be reset by a call to psa_key_derivation_abort().
 *
 * Implementations must reject an attempt to derive a key of size 0.
 *
 * Return:
 * * PSA_SUCCESS:
 *	Success.
 * * PSA_ERROR_INVALID_ARGUMENT:
 *	@alg is not a key derivation algorithm.
 * * PSA_ERROR_NOT_SUPPORTED:
 *	@alg is not supported or is not a key derivation algorithm.
 * * PSA_ERROR_INSUFFICIENT_MEMORY
 * * PSA_ERROR_COMMUNICATION_FAILURE
 * * PSA_ERROR_HARDWARE_FAILURE
 * * PSA_ERROR_CORRUPTION_DETECTED
 * * PSA_ERROR_STORAGE_FAILURE
 * * PSA_ERROR_DATA_CORRUPT
 * * PSA_ERROR_DATA_INVALID
 * * PSA_ERROR_BAD_STATE:
 *	The operation state is not valid: it must be inactive.
 * * PSA_ERROR_BAD_STATE:
 *	The library has not been previously initialized by psa_crypto_init(). It is
 *	implementation-dependent whether a failure to initialize results in this error code.
 */
psa_status_t psa_key_derivation_setup(psa_key_derivation_operation_t *operation,
				      psa_algorithm_t alg);

/**
 * psa_key_derivation_verify_bytes - Compare output data from a key derivation operation to an
 * expected value.
 * @operation: The key derivation operation object to read from.
 * @expected_output: Buffer containing the expected derivation output.
 * @output_length: Length ot the expected output. This is also the number of bytes that will be
 *                 read.
 *
 * **Warning: Not supported**
 *
 * This function calculates output bytes from a key derivation algorithm and compares those bytes
 * to an expected value. If the key derivation’s output is viewed as a stream of bytes, this
 * function destructively reads output_length bytes from the stream before comparing them with
 * @expected_output. The operation’s capacity decreases by the number of bytes read.
 *
 * This is functionally equivalent to the following code\:
 *
 *   .. code-block:: c
 *
 *      uint8_t tmp[output_length];
 *      psa_key_derivation_output_bytes(operation, tmp, output_length);
 *      if (memcmp(expected_output, tmp, output_length) != 0)
 *      return PSA_ERROR_INVALID_SIGNATURE;
 *
 * However, calling psa_key_derivation_verify_bytes() works even if the key’s policy does not
 * allow output of the bytes.
 *
 * If this function returns an error status other than PSA_ERROR_INSUFFICIENT_DATA or
 * PSA_ERROR_INVALID_SIGNATURE, the operation enters an error state and must be aborted by calling
 * psa_key_derivation_abort().
 *
 * **Note**:
 *	Implementations must make the best effort to ensure that the comparison between the actual
 *	key derivation output and the expected output is performed in constant time.
 *
 * Return:
 * * PSA_SUCCESS:
 *	Success. The output of the key derivation operation matches @expected_output.
 * * PSA_ERROR_BAD_STATE:
 *	The following conditions can result in this error\:
 *
 *	- The operation state is not valid: it must be active, with all required input steps
 *	  complete.
 *	- The library requires initializing by a call to psa_crypto_init().
 * * PSA_ERROR_NOT_PERMITTED:
 *	One of the inputs is a key whose policy does not permit PSA_KEY_USAGE_VERIFY_DERIVATION.
 * * PSA_ERROR_INVALID_SIGNATURE:
 *	The output of the key derivation operation does not match the value in @expected_output.
 * * PSA_ERROR_INSUFFICIENT_DATA:
 *	The operation’s capacity was less than @output_length bytes. In this case, the
 *	operation’s capacity is set to zero — subsequent calls to this function will not
 *	succeed, even with a smaller expected output length.
 * * PSA_ERROR_INSUFFICIENT_MEMORY
 * * PSA_ERROR_COMMUNICATION_FAILURE
 * * PSA_ERROR_CORRUPTION_DETECTED
 * * PSA_ERROR_STORAGE_FAILURE
 * * PSA_ERROR_DATA_CORRUPT
 * * PSA_ERROR_DATA_INVALID
 */
psa_status_t
psa_key_derivation_verify_bytes(psa_key_derivation_operation_t *operation,
				const uint8_t *expected_output,
				size_t output_length);

/**
 * psa_key_derivation_verify_key() - Compare output data from a key derivation operation to an
 * expected value stored in a key.
 * @operation: The key derivation operation object to read from.
 * @expected: A key of type PSA_KEY_TYPE_PASSWORD_HASH containing the expected output. The key must
 *            allow the usage PSA_KEY_USAGE_VERIFY_DERIVATION, and the permitted algorithm must
 *            match the operation’s algorithm. The value of this key is typically computed by a
 *            previous call to psa_key_derivation_output_key().
 *
 * **Warning: Not supported**
 *
 * This function calculates output bytes from a key derivation algorithm and compares those bytes
 * to an expected value, provided as key of type PSA_KEY_TYPE_PASSWORD_HASH. If the key
 * derivation’s output is viewed as a stream of bytes, this function destructively reads the
 * number of bytes corresponding to the length of the expected key from the stream before
 * comparing them with the key value. The operation’s capacity decreases by the number of bytes
 * read.
 *
 * This is functionally equivalent to exporting the expected key and calling
 * psa_key_derivation_verify_bytes() on the result, except that it works when the key cannot be
 * exported.
 *
 * If this function returns an error status other than PSA_ERROR_INSUFFICIENT_DATA or
 * PSA_ERROR_INVALID_SIGNATURE, the operation enters an error state and must be aborted by calling
 * psa_key_derivation_abort().
 *
 * **Note**:
 *	Implementations must make the best effort to ensure that the comparison between the actual
 *	key derivation output and the expected output is performed in constant time.
 *
 * Return:
 * * PSA_SUCCESS:
 *	Success. The output of the key derivation operation matches the expected key value.
 * * PSA_ERROR_BAD_STATE:
 *	The following conditions can result in this error\:
 *
 *	- The operation state is not valid: it must be active, with all required input steps
 *	  complete.
 *	- The library requires initializing by a call to psa_crypto_init().
 * * PSA_ERROR_INVALID_HANDLE:
 *	@expected is not a valid key identifier.
 * * PSA_ERROR_NOT_PERMITTED:
 *	The following conditions can result in this error\:
 *
 *	- The key does not have the PSA_KEY_USAGE_VERIFY_DERIVATION flag, or it does not permit the
 *	  requested algorithm.
 *	- One of the inputs is a key whose policy does not permit PSA_KEY_USAGE_VERIFY_DERIVATION.
 * * PSA_ERROR_INVALID_SIGNATURE:
 *	The output of the key derivation operation does not match the value of the expected key.
 * * PSA_ERROR_INSUFFICIENT_DATA:
 *	The operation’s capacity was less than the length of the expected key.
 *	In this case, the operation’s capacity is set to zero — subsequent calls to this
 *	function will not succeed, even with a smaller expected key length.
 * * PSA_ERROR_INVALID_ARGUMENT:
 *	The key type is not PSA_KEY_TYPE_PASSWORD_HASH.
 * * PSA_ERROR_INSUFFICIENT_MEMORY
 * * PSA_ERROR_COMMUNICATION_FAILURE
 * * PSA_ERROR_CORRUPTION_DETECTED
 * * PSA_ERROR_STORAGE_FAILURE
 * * PSA_ERROR_DATA_CORRUPT
 * * PSA_ERROR_DATA_INVALID
 */
psa_status_t
psa_key_derivation_verify_key(psa_key_derivation_operation_t *operation,
			      psa_key_id_t expected);

/**
 * psa_mac_abort() - Abort a MAC operation.
 * @operation: Initialized MAC operation.
 *
 * **Warning: Not supported**
 *
 * Aborting an operation frees all associated resources except for the operation object itself. Once
 * aborted, the operation object can be reused for another operation by calling psa_mac_sign_setup()
 * or psa_mac_verify_setup() again.
 *
 * This function can be called any time after the operation object has been initialized by one of
 * the methods described in &typedef psa_mac_operation_t.
 *
 * In particular, calling psa_mac_abort() after the operation has been terminated by a call to
 * psa_mac_abort(), psa_mac_sign_finish() or psa_mac_verify_finish() is safe and has no effect.
 *
 * Return:
 * * PSA_SUCCESS
 * * PSA_ERROR_COMMUNICATION_FAILURE
 * * PSA_ERROR_HARDWARE_FAILURE
 * * PSA_ERROR_CORRUPTION_DETECTED
 * * PSA_ERROR_BAD_STATE
 *	The library has not been previously initialized by psa_crypto_init(). It is
 *	implementation-dependent whether a failure to initialize results in this error code.
 */
psa_status_t psa_mac_abort(psa_mac_operation_t *operation);

/**
 * psa_mac_compute() - Calculate the message authentication code (MAC) of a message.
 * @key: Identifier of the key to use for the operation. It must allow the usage
 *       PSA_KEY_USAGE_SIGN_MESSAGE.
 * @alg: The MAC algorithm to compute (PSA_ALG_XXX value such that PSA_ALG_IS_MAC(alg) is true).
 * @input: Buffer containing the input message.
 * @input_length: Size of the @input buffer in bytes.
 * @mac: Buffer where the MAC value is to be written.
 * @mac_size: Size of the @mac buffer in bytes.
 * @mac_length: On success, the number of bytes that make up the MAC value.
 *
 * **Note**:
 *	To verify the MAC of a message against an expected value, use psa_mac_verify() instead.
 *	Beware that comparing integrity or authenticity data such as MAC values with a function such
 *	as memcmp() is risky because the time taken by the comparison might leak information about
 *	the MAC value which could allow an attacker to guess a valid MAC and thereby bypass security
 *	controls.
 *
 * Parameter @mac_size must be appropriate for the selected algorithm and key\:
 *
 * - The exact MAC size is PSA_MAC_LENGTH(key_type, key_bits, alg) where key_type and key_bits are
 *   attributes of the key used to compute the MAC.
 *
 * - PSA_MAC_MAX_SIZE evaluates to the maximum MAC size of any supported MAC algorithm.
 *
 * Return:
 * * PSA_SUCCESS:
 *	Success.
 * * PSA_ERROR_INVALID_HANDLE
 * * PSA_ERROR_NOT_PERMITTED:
 *	The key does not have the PSA_KEY_USAGE_SIGN_MESSAGE flag, or it does not permit the
 *	requested algorithm.
 * * PSA_ERROR_INVALID_ARGUMENT:
 *	@key is not compatible with @alg.
 * * PSA_ERROR_NOT_SUPPORTED:
 *	@alg is not supported or is not a MAC algorithm.
 * * PSA_ERROR_BUFFER_TOO_SMALL:
 *	The size of the @mac buffer is too small. PSA_MAC_LENGTH() or PSA_MAC_MAX_SIZE can be used
 *	to determine the required buffer size.
 * * PSA_ERROR_INSUFFICIENT_MEMORY
 * * PSA_ERROR_COMMUNICATION_FAILURE
 * * PSA_ERROR_HARDWARE_FAILURE
 * * PSA_ERROR_CORRUPTION_DETECTED
 * * PSA_ERROR_STORAGE_FAILURE:
 *	The key could not be retrieved from storage.
 * * PSA_ERROR_DATA_CORRUPT:
 *	The key could not be retrieved from storage.
 * * PSA_ERROR_DATA_INVALID:
 *	The key could not be retrieved from storage.
 * * PSA_ERROR_BAD_STATE:
 *	The library has not been previously initialized by psa_crypto_init(). It is
 *	implementation-dependent whether a failure to initialize results in this error code.
 */
psa_status_t psa_mac_compute(psa_key_id_t key, psa_algorithm_t alg,
			     const uint8_t *input, size_t input_length,
			     uint8_t *mac, size_t mac_size, size_t *mac_length);

/**
 * psa_mac_operation_init() - Return an initial value for a MAC operation object.
 *
 * Return:
 * &typedef psa_mac_operation_t
 */
static psa_mac_operation_t psa_mac_operation_init(void);

/**
 * psa_mac_sign_finish() - Finish the calculation of the MAC of a message.
 * @operation: Active MAC operation.
 * @mac: Buffer where the MAC value is to be written.
 * @mac_size: Size of the @mac buffer in bytes.
 * @mac_length: On success, the number of bytes that make up the MAC value. This is always
 *              PSA_MAC_FINAL_SIZE(key_type, key_bits, alg) where key_type and key_bits are the type
 *              and bit-size respectively of the key and alg is the MAC algorithm that is
 *              calculated.
 *
 * **Warning: Not supported**
 *
 * The application must call psa_mac_sign_setup() before calling this function. This function
 * calculates the MAC of the message formed by concatenating the inputs passed to preceding calls to
 * psa_mac_update().
 *
 * When this function returns successfully, the operation becomes inactive. If this function returns
 * an error status, the operation enters an error state and must be aborted by calling
 * psa_mac_abort().
 *
 * **Warning**:
 *	It is not recommended to use this function when a specific value is expected for the MAC.
 *	Call psa_mac_verify_finish() instead with the expected MAC value.
 *
 *	Comparing integrity or authenticity data such as MAC values with a function such as memcmp()
 *	is risky because the time taken by the comparison might leak information about the hashed
 *	data which could allow an attacker to guess a valid MAC and thereby bypass security
 *	controls.
 *
 * Parameter @mac_size must be appropriate for the selected algorithm and key\:
 *
 * - The exact MAC size is PSA_MAC_LENGTH(key_type, key_bits, alg) where key_type and key_bits are
 *   attributes of the key, and alg is the algorithm used to compute the MAC.
 *
 * - PSA_MAC_MAX_SIZE evaluates to the maximum MAC size of any supported MAC algorithm.
 *
 * Return:
 * * PSA_SUCCESS:
 *	Success.
 * * PSA_ERROR_BAD_STATE:
 *	The operation state is not valid: it must be an active mac sign operation.
 * * PSA_ERROR_BUFFER_TOO_SMALL:
 *	The size of the @mac buffer is too small. PSA_MAC_LENGTH() or PSA_MAC_MAX_SIZE can be used
 *	to determine the required buffer size.
 * * PSA_ERROR_INSUFFICIENT_MEMORY
 * * PSA_ERROR_COMMUNICATION_FAILURE
 * * PSA_ERROR_HARDWARE_FAILURE
 * * PSA_ERROR_CORRUPTION_DETECTED
 * * PSA_ERROR_STORAGE_FAILURE
 * * PSA_ERROR_DATA_CORRUPT
 * * PSA_ERROR_DATA_INVALID
 * * PSA_ERROR_BAD_STATE:
 *	The library has not been previously initialized by psa_crypto_init(). It is
 *	implementation-dependent whether a failure to initialize results in this error code.
 */
psa_status_t psa_mac_sign_finish(psa_mac_operation_t *operation, uint8_t *mac,
				 size_t mac_size, size_t *mac_length);

/**
 * psa_mac_sign_setup() - Set up a multi-part MAC calculation operation.
 * @operation: The operation object to set up. It must have been initialized as per the
 *             documentation for psa_mac_operation_t and not yet in use.
 * @key: Identifier of the key to use for the operation. It must remain valid until the operation
 *       terminates. It must allow the usage PSA_KEY_USAGE_SIGN_MESSAGE.
 * @alg: The MAC algorithm to compute (PSA_ALG_XXX value such that PSA_ALG_IS_MAC(alg) is true).
 *
 * **Warning: Not supported**
 *
 * This function sets up the calculation of the message authentication code (MAC) of a byte string.
 * To verify the MAC of a message against an expected value, use psa_mac_verify_setup() instead.
 *
 * The sequence of operations to calculate a MAC is as follows\:
 *
 * #. Allocate an operation object which will be passed to all the functions listed here.
 *
 * #. Initialize the operation object with one of the methods described in the documentation for
 *    &typedef psa_mac_operation_t, e.g. PSA_MAC_OPERATION_INIT.
 *
 * #. Call psa_mac_sign_setup() to specify the algorithm and key.
 *
 * #. Call psa_mac_update() zero, one or more times, passing a fragment of the message each time.
 *    The MAC that is calculated is the MAC of the concatenation of these messages in order.
 *
 * #. At the end of the message, call psa_mac_sign_finish() to finish calculating the MAC value and
 *    retrieve it.
 *
 * If an error occurs at any step after a call to psa_mac_sign_setup(), the operation will need to
 * be reset by a call to psa_mac_abort(). The application can call psa_mac_abort() at any time after
 * the operation has been initialized.
 *
 * After a successful call to psa_mac_sign_setup(), the application must eventually terminate the
 * operation through one of the following methods\:
 *
 * - A successful call to psa_mac_sign_finish().
 *
 * - A call to psa_mac_abort().
 *
 * Return:
 * * PSA_SUCCESS:
 *	Success.
 * * PSA_ERROR_INVALID_HANDLE
 * * PSA_ERROR_NOT_PERMITTED:
 *	The key does not have the PSA_KEY_USAGE_SIGN_MESSAGE flag, or it does not permit the
 *	requested algorithm.
 * * PSA_ERROR_INVALID_ARGUMENT:
 *	@key is not compatible with @alg.
 * * PSA_ERROR_NOT_SUPPORTED:
 *	@alg is not supported or is not a MAC algorithm.
 * * PSA_ERROR_INSUFFICIENT_MEMORY
 * * PSA_ERROR_COMMUNICATION_FAILURE
 * * PSA_ERROR_HARDWARE_FAILURE
 * * PSA_ERROR_CORRUPTION_DETECTED
 * * PSA_ERROR_STORAGE_FAILURE:
 *	The key could not be retrieved from storage.
 * * PSA_ERROR_DATA_CORRUPT:
 *	The key could not be retrieved from storage.
 * * PSA_ERROR_DATA_INVALID:
 *	The key could not be retrieved from storage.
 * * PSA_ERROR_BAD_STATE:
 *	The operation state is not valid: it must be inactive.
 * * PSA_ERROR_BAD_STATE:
 *	The library has not been previously initialized by psa_crypto_init(). It is
 *	implementation-dependent whether a failure to initialize results in this error code.
 */
psa_status_t psa_mac_sign_setup(psa_mac_operation_t *operation,
				psa_key_id_t key, psa_algorithm_t alg);

/**
 * psa_mac_update() - Add a message fragment to a multi-part MAC operation.
 * @operation: Active MAC operation.
 * @input: Buffer containing the message fragment to add to the MAC calculation.
 * @input_length: Size of the @input buffer in bytes.
 *
 * **Warning: Not supported**
 *
 * The application must call psa_mac_sign_setup() or psa_mac_verify_setup() before calling this
 * function.
 *
 * If this function returns an error status, the operation enters an error state and must be aborted
 * by calling psa_mac_abort().
 *
 * Return:
 * * PSA_SUCCESS:
 *	Success.
 * * PSA_ERROR_BAD_STATE:
 *	The operation state is not valid: it must be active.
 * * PSA_ERROR_INSUFFICIENT_MEMORY
 * * PSA_ERROR_COMMUNICATION_FAILURE
 * * PSA_ERROR_HARDWARE_FAILURE
 * * PSA_ERROR_CORRUPTION_DETECTED
 * * PSA_ERROR_STORAGE_FAILURE
 * * PSA_ERROR_DATA_CORRUPT
 * * PSA_ERROR_DATA_INVALID
 * * PSA_ERROR_BAD_STATE:
 *	The library has not been previously initialized by psa_crypto_init(). It is
 *	implementation-dependent whether a failure to initialize results in this error code.
 */
psa_status_t psa_mac_update(psa_mac_operation_t *operation,
			    const uint8_t *input, size_t input_length);

/**
 * psa_mac_verify() - Calculate the MAC of a message and compare it with a reference value.
 * @key: Identifier of the key to use for the operation. It must allow the usage
 *       PSA_KEY_USAGE_VERIFY_MESSAGE.
 * @alg: The MAC algorithm to compute (PSA_ALG_XXX value such that PSA_ALG_IS_MAC(alg) is true).
 * @input: Buffer containing the input message.
 * @input_length: Size of the @input buffer in bytes.
 * @mac: Buffer containing the expected MAC value.
 * @mac_length: Size of the @mac buffer in bytes.
 *
 * Return:
 * * PSA_SUCCESS:
 *	The expected MAC is identical to the actual MAC of the input.
 * * PSA_ERROR_INVALID_SIGNATURE:
 *	The MAC of the message was calculated successfully, but it differs from the expected value.
 * * PSA_ERROR_INVALID_HANDLE
 * * PSA_ERROR_NOT_PERMITTED:
 *	The key does not have the PSA_KEY_USAGE_VERIFY_MESSAGE flag, or it does not permit the
 *	requested algorithm.
 * * PSA_ERROR_INVALID_ARGUMENT:
 *	@key is not compatible with @alg.
 * * PSA_ERROR_NOT_SUPPORTED:
 *	@alg is not supported or is not a MAC algorithm.
 * * PSA_ERROR_INSUFFICIENT_MEMORY
 * * PSA_ERROR_COMMUNICATION_FAILURE
 * * PSA_ERROR_HARDWARE_FAILURE
 * * PSA_ERROR_CORRUPTION_DETECTED
 * * PSA_ERROR_STORAGE_FAILURE:
 *	The key could not be retrieved from storage.
 * * PSA_ERROR_DATA_CORRUPT:
 *	The key could not be retrieved from storage.
 * * PSA_ERROR_DATA_INVALID:
 *	The key could not be retrieved from storage.
 * * PSA_ERROR_BAD_STATE:
 *	The library has not been previously initialized by psa_crypto_init(). It is
 *	implementation-dependent whether a failure to initialize results in this error code.
 */
psa_status_t psa_mac_verify(psa_key_id_t key, psa_algorithm_t alg,
			    const uint8_t *input, size_t input_length,
			    const uint8_t *mac, size_t mac_length);

/**
 * psa_mac_verify_finish() - Finish the calculation of the MAC of a message and compare it with an
 * expected value.
 * @operation: Active MAC operation.
 * @mac: Buffer containing the expected MAC value.
 * @mac_length: Size of the @mac buffer in bytes.
 *
 * **Warning: Not supported**
 *
 * The application must call psa_mac_verify_setup() before calling this function. This function
 * calculates the MAC of the message formed by concatenating the inputs passed to preceding calls to
 * psa_mac_update(). It then compares the calculated MAC with the expected MAC passed as a parameter
 * to this function.
 *
 * When this function returns successfully, the operation becomes inactive. If this function returns
 * an error status, the operation enters an error state and must be aborted by calling
 * psa_mac_abort().
 *
 * **Note**:
 *	Implementations must make the best effort to ensure that the comparison between the actual
 *	MAC and the expected MAC is performed in constant time.
 *
 * Return:
 * * PSA_SUCCESS:
 *	The expected MAC is identical to the actual MAC of the message.
 * * PSA_ERROR_INVALID_SIGNATURE:
 *	The MAC of the message was calculated successfully, but it differs from the expected MAC.
 * * PSA_ERROR_BAD_STATE:
 *	The operation state is not valid: it must be an active mac verify operation.
 * * PSA_ERROR_INSUFFICIENT_MEMORY
 * * PSA_ERROR_COMMUNICATION_FAILURE
 * * PSA_ERROR_HARDWARE_FAILURE
 * * PSA_ERROR_CORRUPTION_DETECTED
 * * PSA_ERROR_STORAGE_FAILURE
 * * PSA_ERROR_DATA_CORRUPT
 * * PSA_ERROR_DATA_INVALID
 * * PSA_ERROR_BAD_STATE:
 *	The library has not been previously initialized by psa_crypto_init(). It is
 *	implementation-dependent whether a failure to initialize results in this error code.
 */
psa_status_t psa_mac_verify_finish(psa_mac_operation_t *operation,
				   const uint8_t *mac, size_t mac_length);

/**
 * psa_mac_verify_setup() - Set up a multi-part MAC verification operation.
 * @operation: The operation object to set up. It must have been initialized as per the
 *             documentation for &typedef psa_mac_operation_t and not yet in use.
 * @key: Identifier of the key to use for the operation. It must remain valid until the operation
 *       terminates. It must allow the usage PSA_KEY_USAGE_VERIFY_MESSAGE.
 * @alg: The MAC algorithm to compute (PSA_ALG_XXX value such that PSA_ALG_IS_MAC(alg) is true).
 *
 * **Warning: Not supported**
 *
 * This function sets up the verification of the message authentication code (MAC) of a byte string
 * against an expected value.
 *
 * The sequence of operations to verify a MAC is as follows\:
 *
 * #. Allocate an operation object which will be passed to all the functions listed here.
 *
 * #. Initialize the operation object with one of the methods described in the documentation for
 *    &typedef psa_mac_operation_t, e.g. PSA_MAC_OPERATION_INIT.
 *
 * #. Call psa_mac_verify_setup() to specify the algorithm and key.
 *
 * #. Call psa_mac_update() zero, one or more times, passing a fragment of the message each time.
 *    The MAC that is calculated is the MAC of the concatenation of these messages in order.
 *
 * #. At the end of the message, call psa_mac_verify_finish() to finish calculating the actual MAC
 *    of the message and verify it against the expected value.
 *
 * If an error occurs at any step after a call to psa_mac_verify_setup(), the operation will need to
 * be reset by a call to psa_mac_abort(). The application can call psa_mac_abort() at any time after
 * the operation has been initialized.
 *
 * After a successful call to psa_mac_verify_setup(), the application must eventually terminate the
 * operation through one of the following methods\:
 *
 * - A successful call to psa_mac_verify_finish().
 *
 * - A call to psa_mac_abort().
 *
 * Return:
 * * PSA_SUCCESS:
 *	Success.
 * * PSA_ERROR_INVALID_HANDLE
 * * PSA_ERROR_NOT_PERMITTED:
 *	The key does not have the PSA_KEY_USAGE_VERIFY_MESSAGE flag, or it does not permit the
 *	requested algorithm.
 * * PSA_ERROR_INVALID_ARGUMENT:
 *	@key is not compatible with @alg.
 * * PSA_ERROR_NOT_SUPPORTED:
 *	@alg is not supported or is not a MAC algorithm.
 * * PSA_ERROR_INSUFFICIENT_MEMORY
 * * PSA_ERROR_COMMUNICATION_FAILURE
 * * PSA_ERROR_HARDWARE_FAILURE
 * * PSA_ERROR_CORRUPTION_DETECTED
 * * PSA_ERROR_STORAGE_FAILURE:
 *	The key could not be retrieved from storage
 * * PSA_ERROR_DATA_CORRUPT:
 *	The key could not be retrieved from storage.
 * * PSA_ERROR_DATA_INVALID:
 *	The key could not be retrieved from storage.
 * * PSA_ERROR_BAD_STATE:
 *	The operation state is not valid: it must be inactive.
 * * PSA_ERROR_BAD_STATE:
 *	The library has not been previously initialized by psa_crypto_init(). It is
 *	implementation-dependent whether a failure to initialize results in this error code.
 */
psa_status_t psa_mac_verify_setup(psa_mac_operation_t *operation,
				  psa_key_id_t key, psa_algorithm_t alg);

/**
 * psa_purge_key() - Remove non-essential copies of key material from memory.
 * @key: Identifier of the key to purge.
 *
 * **Warning: Not supported**
 *
 * For keys that have been created with the PSA_KEY_USAGE_CACHE usage flag, an implementation is
 * permitted to make additional copies of the key material that are not in storage and not for the
 * purpose of ongoing operations.
 *
 * This function will remove these extra copies of the key material from memory.
 *
 * This function is not required to remove key material from memory in any of the following
 * situations\:
 *
 * - The key is currently in use in a cryptographic operation.
 *
 * - The key is volatile.
 *
 * Return:
 * * PSA_SUCCESS:
 *	The key material will have been removed from memory if it is not currently required.
 * * PSA_ERROR_INVALID_HANDLE
 * * PSA_ERROR_COMMUNICATION_FAILURE
 * * PSA_ERROR_STORAGE_FAILURE
 * * PSA_ERROR_DATA_CORRUPT
 * * PSA_ERROR_DATA_INVALID
 * * PSA_ERROR_CORRUPTION_DETECTED
 * * PSA_ERROR_BAD_STATE:
 *	The library has not been previously initialized by psa_crypto_init(). It is
 *	implementation-dependent whether a failure to initialize results in this error code.
 */
psa_status_t psa_purge_key(psa_key_id_t key);

/**
 * psa_raw_key_agreement() - Perform a key agreement and return the raw shared secret.
 * @alg: The key agreement algorithm to compute (PSA_ALG_XXX value such that
 *       PSA_ALG_IS_RAW_KEY_AGREEMENT(alg) is true).
 * @private_key: Identifier of the private key to use. It must allow the usage PSA_KEY_USAGE_DERIVE.
 * @peer_key: Public key of the peer. It must be in the same format that psa_import_key() accepts.
 *            The standard formats for public keys are documented in the documentation of
 *            psa_export_public_key().
 * @peer_key_length: Size of @peer_key in bytes.
 * @output: Buffer where the raw shared secret is to be written.
 * @output_size: Size of the @output buffer in bytes.
 * @output_length: On success, the number of bytes that make up the returned output.
 *
 * **Warning: Not supported**
 *
 * **Warning**:
 *	The raw result of a key agreement algorithm such as finite-field Diffie-Hellman or elliptic
 *	curve Diffie-Hellman has biases, and is not suitable for use as key material. Instead it is
 *	recommended that the result is used as input to a key derivation algorithm. To chain a key
 *	agreement with a key derivation, use psa_key_derivation_key_agreement() and other functions
 *	from the key derivation interface.
 *
 * Parameter @output_size must be appropriate for the keys\:
 *
 * - The required output size is PSA_RAW_KEY_AGREEMENT_OUTPUT_SIZE(type, bits) where type is the
 *   type of @private_key and bits is the bit-size of either @private_key or the @peer_key.
 *
 * - PSA_RAW_KEY_AGREEMENT_OUTPUT_MAX_SIZE evaluates to the maximum output size of any supported raw
 *   key agreement algorithm.
 *
 * Return:
 * * PSA_SUCCESS:
 *	Success.
 * * PSA_ERROR_INVALID_HANDLE
 * * PSA_ERROR_NOT_PERMITTED:
 *	The key does not have the PSA_KEY_USAGE_DERIVE flag, or it does not permit the requested
 *	algorithm.
 * * PSA_ERROR_INVALID_ARGUMENT:
 *	@alg is not a key agreement algorithm
 * * PSA_ERROR_INVALID_ARGUMENT:
 *	private_@key is not compatible with @alg, or @peer_key is not valid for @alg or not
 *	compatible with @private_key.
 * * PSA_ERROR_BUFFER_TOO_SMALL:
 *	The size of the @output buffer is too small. PSA_RAW_KEY_AGREEMENT_OUTPUT_SIZE() or
 *	PSA_RAW_KEY_AGREEMENT_OUTPUT_MAX_SIZE can be used to determine the required buffer size.
 * * PSA_ERROR_NOT_SUPPORTED:
 *	@alg is not a supported key agreement algorithm.
 * * PSA_ERROR_INSUFFICIENT_MEMORY
 * * PSA_ERROR_COMMUNICATION_FAILURE
 * * PSA_ERROR_HARDWARE_FAILURE
 * * PSA_ERROR_CORRUPTION_DETECTED
 * * PSA_ERROR_STORAGE_FAILURE
 * * PSA_ERROR_DATA_CORRUPT
 * * PSA_ERROR_DATA_INVALID
 * * PSA_ERROR_BAD_STATE:
 *	The library has not been previously initialized by psa_crypto_init(). It is
 *	implementation-dependent whether a failure to initialize results in this error code.
 */
psa_status_t psa_raw_key_agreement(psa_algorithm_t alg,
				   psa_key_id_t private_key,
				   const uint8_t *peer_key,
				   size_t peer_key_length, uint8_t *output,
				   size_t output_size, size_t *output_length);

/**
 * psa_reset_key_attributes() - Reset a key attribute object to a freshly initialized state.
 * @attributes: The attribute object to reset.
 *
 * The attribute object must be initialized as described in the documentation of the type
 * &typedef psa_key_attributes_t before calling this function. Once the object has been initialized,
 * this function can be called at any time.
 *
 * This function frees any auxiliary resources that the object might contain.
 *
 * Return:
 * void
 */
void psa_reset_key_attributes(psa_key_attributes_t *attributes);

/**
 * psa_set_key_algorithm() - Declare the permitted algorithm policy for a key.
 * @attributes: The attribute object to write to.
 * @alg: The permitted algorithm to write.
 *
 * The permitted algorithm policy of a key encodes which algorithm or algorithms are permitted to be
 * used with this key.
 *
 * This function overwrites any permitted algorithm policy previously set in @attributes.
 *
 * **Implementation note**:
 *	This is a simple accessor function that is not required to validate its inputs. The
 *	following approaches can be used to provide an efficient implementation\:
 *
 *	- This function can be declared as static or inline, instead of using the default external
 *	  linkage.
 *
 *	- This function can be provided as a function-like macro. In this form, the macro must
 *	  evaluate each of its arguments exactly once, as if it was a function call.
 *
 * Return:
 * void
 */
static void psa_set_key_algorithm(psa_key_attributes_t *attributes,
				  psa_algorithm_t alg);

/**
 * psa_set_key_bits() - Declare the size of a key.
 * @attributes: The attribute object to write to.
 * @bits: The key size in bits. If this is 0, the key size in @attributes becomes unspecified. Keys
 *        of size 0 are not supported.
 *
 * This function overwrites any key size previously set in @attributes.
 *
 * **Implementation note**:
 *	This is a simple accessor function that is not required to validate its inputs. The
 *	following approaches can be used to provide an efficient implementation\:
 *
 *	- This function can be declared as static or inline, instead of using the default external
 *	  linkage.
 *
 *	- This function can be provided as a function-like macro. In this form, the macro must
 *	  evaluate each of its arguments exactly once, as if it was a function call.
 *
 * Return:
 * void
 */
static void psa_set_key_bits(psa_key_attributes_t *attributes, size_t bits);

/**
 * psa_set_key_id() - Declare a key as persistent and set its key identifier.
 * @attributes: The attribute object to write to.
 * @id: The persistent identifier for the key.
 *
 * The application must choose a value for @id between PSA_KEY_ID_USER_MIN and PSA_KEY_ID_USER_MAX.
 *
 * If the attribute object currently declares the key as volatile, which is the default lifetime of
 * an attribute object, this function sets the lifetime attribute to PSA_KEY_LIFETIME_PERSISTENT.
 *
 * This function does not access storage, it merely stores the given value in the attribute object.
 * The persistent key will be written to storage when the attribute object is passed to a key
 * creation function such as psa_import_key(), psa_generate_key(), psa_key_derivation_output_key()
 * or psa_copy_key().
 *
 * **Implementation note**:
 *	This is a simple accessor function that is not required to validate its inputs. The
 *	following approaches can be used to provide an efficient implementation\:
 *
 *	- This function can be declared as static or inline, instead of using the default external
 *	  linkage.
 *
 *	- This function can be provided as a function-like macro. In this form, the macro must
 *	  evaluate each of its arguments exactly once, as if it was a function call.
 *
 * Return:
 * void
 */
static void psa_set_key_id(psa_key_attributes_t *attributes, psa_key_id_t id);

/**
 * psa_set_key_lifetime() - Set the location of a persistent key.
 * @attributes: The attribute object to write to.
 * @lifetime: The lifetime for the key. If this is PSA_KEY_LIFETIME_VOLATILE, the key will be
 *            volatile, and the key identifier attribute is reset to PSA_KEY_ID_NULL.
 *
 * To make a key persistent, give it a persistent key identifier by using psa_set_key_id(). By
 * default, a key that has a persistent identifier is stored in the default storage area identifier
 * by PSA_KEY_LIFETIME_PERSISTENT. Call this function to choose a storage area, or to explicitly
 * declare the key as volatile.
 *
 * This function does not access storage, it merely stores the given value in the attribute object.
 * The persistent key will be written to storage when the attribute object is passed to a key
 * creation function such as psa_import_key(), psa_generate_key(), psa_key_derivation_output_key()
 * or psa_copy_key().
 *
 * **Implementation note**:
 *	This is a simple accessor function that is not required to validate its inputs. The
 *	following approaches can be used to provide an efficient implementation\:
 *
 *	- This function can be declared as static or inline, instead of using the default external
 *	  linkage.
 *
 *	- This function can be provided as a function-like macro. In this form, the macro must
 *	  evaluate each of its arguments exactly once, as if it was a function call.
 *
 * Return:
 * void
 */
static void psa_set_key_lifetime(psa_key_attributes_t *attributes,
				 psa_key_lifetime_t lifetime);

/**
 * psa_set_key_type() - Declare the type of a key.
 * @attributes: The attribute object to write to.
 * @type: The key type to write. If this is PSA_KEY_TYPE_NONE, the key type in @attributes becomes
 *        unspecified.
 *
 * This function overwrites any key type previously set in @attributes.
 *
 * **Implementation note**:
 *	This is a simple accessor function that is not required to validate its inputs. The
 *	following approaches can be used to provide an efficient implementation\:
 *
 *	- This function can be declared as static or inline, instead of using the default external
 *	  linkage.
 *
 *	- This function can be provided as a function-like macro. In this form, the macro must
 *	  evaluate each of its arguments exactly once, as if it was a function call.
 *
 * Return:
 * void
 */
static void psa_set_key_type(psa_key_attributes_t *attributes,
			     psa_key_type_t type);

/**
 * psa_set_key_usage_flags() - Declare usage flags for a key.
 * @attributes: The attribute object to write to.
 * @usage_flags:psa_set_key_usage_flags The usage flags to write.
 *
 * Usage flags are part of a key’s policy. They encode what kind of operations are permitted on
 * the key. For more details, see Key policies.
 *
 * This function overwrites any usage flags previously set in @attributes.
 *
 * **Implementation note**:
 *	This is a simple accessor function that is not required to validate its inputs. The
 *	following approaches can be used to provide an efficient implementation\:
 *
 *	- This function can be declared as static or inline, instead of using the default external
 *	  linkage.
 *
 *	- This function can be provided as a function-like macro. In this form, the macro must
 *	  evaluate each of its arguments exactly once, as if it was a function call.
 *
 * Return:
 * void
 */
static void psa_set_key_usage_flags(psa_key_attributes_t *attributes,
				    psa_key_usage_t usage_flags);

/**
 * psa_sign_hash() - Sign an already-calculated hash with a private key.
 * @key: Identifier of the key to use for the operation. It must be an asymmetric key pair. The key
 *       must allow the usage PSA_KEY_USAGE_SIGN_HASH.
 * @alg: An asymmetric signature algorithm that separates the hash and sign operations
 *       (PSA_ALG_XXX value such that PSA_ALG_IS_SIGN_HASH(alg) is true), that is compatible with
 *       the type of key.
 * @hash: The input to sign. This is usually the hash of a message. See the detailed description of
 *        this function and the description of individual signature algorithms for a detailed
 *        description of acceptable inputs.
 * @hash_length: Size of the hash buffer in bytes.
 * @signature: Buffer where the signature is to be written.
 * @signature_size: Size of the @signature buffer in bytes.
 * @signature_length: On success, the number of bytes that make up the returned signature value.
 *
 * With most signature mechanisms that follow the hash-and-sign paradigm, the hash input to this
 * function is the hash of the message to sign. The hash algorithm is encoded in the signature
 * algorithm.
 *
 * Some hash-and-sign mechanisms apply a padding or encoding to the hash. In such cases, the encoded
 * hash must be passed to this function. The current version of this specification defines one such
 * signature algorithm: PSA_ALG_RSA_PKCS1V15_SIGN_RAW.
 *
 * **Note**:
 *	To perform a hash-and-sign algorithm, the hash must be calculated before passing it to this
 *	function. This can be done by calling psa_hash_compute() or with a multi-part hash
 *	operation. Alternatively, to hash and sign a message in a single call, use
 *	psa_sign_message().
 *
 * Parameter @signature_size must be appropriate for the selected algorithm and key\:
 *
 * - The required signature size is PSA_SIGN_OUTPUT_SIZE(key_type, key_bits, alg) where key_type
 *   and key_bits are the type and bit-size respectively of @key.
 *
 * - PSA_SIGNATURE_MAX_SIZE evaluates to the maximum signature size of any supported signature
 *   algorithm.
 *
 * Return:
 * * PSA_SUCCESS
 * * PSA_ERROR_INVALID_HANDLE
 * * PSA_ERROR_NOT_PERMITTED:
 *	The key does not have the PSA_KEY_USAGE_SIGN_HASH flag, or it does not permit the requested
 *	algorithm.
 * * PSA_ERROR_BUFFER_TOO_SMALL:
 *	The size of the @signature buffer is too small. PSA_SIGN_OUTPUT_SIZE() or
 *	PSA_SIGNATURE_MAX_SIZE can be used to determine the required buffer size.
 * * PSA_ERROR_NOT_SUPPORTED
 * * PSA_ERROR_INVALID_ARGUMENT
 * * PSA_ERROR_INSUFFICIENT_MEMORY
 * * PSA_ERROR_COMMUNICATION_FAILURE
 * * PSA_ERROR_HARDWARE_FAILURE
 * * PSA_ERROR_CORRUPTION_DETECTED
 * * PSA_ERROR_STORAGE_FAILURE
 * * PSA_ERROR_DATA_CORRUPT
 * * PSA_ERROR_DATA_INVALID
 * * PSA_ERROR_INSUFFICIENT_ENTROPY
 * * PSA_ERROR_BAD_STATE:
 *	The library has not been previously initialized by psa_crypto_init(). It is
 *	implementation-dependent whether a failure to initialize results in this error code.
 */
psa_status_t psa_sign_hash(psa_key_id_t key, psa_algorithm_t alg,
			   const uint8_t *hash, size_t hash_length,
			   uint8_t *signature, size_t signature_size,
			   size_t *signature_length);

/**
 * psa_sign_message() - Sign a message with a private key. For hash-and-sign algorithms, this
 * includes the hashing step.
 * @key: Identifier of the key to use for the operation. It must be an asymmetric key pair. The key
 *       must allow the usage PSA_KEY_USAGE_SIGN_MESSAGE.
 * @alg: An asymmetric signature algorithm (PSA_ALG_XXX value such that
 *       PSA_ALG_IS_SIGN_MESSAGE(alg) is true), that is compatible with the type of key.
 * @input: The input message to sign.
 * @input_length: Size of the @input buffer in bytes.
 * @signature: Buffer where the signature is to be written.
 * @signature_size: Size of the @signature buffer in bytes.
 * @signature_length: On success, the number of bytes that make up the returned signature value.
 *
 * **Note**:
 *	To perform a multi-part hash-and-sign signature algorithm, first use a multi-part hash
 *	operation and then pass the resulting hash to psa_sign_hash(). PSA_ALG_GET_HASH(alg) can be
 *	used to determine the hash algorithm to use.
 *
 * Parameter @signature_size must be appropriate for the selected algorithm and key\:
 *
 * - The required signature size is PSA_SIGN_OUTPUT_SIZE(key_type, key_bits, alg) where key_type
 *   and key_bits are the type and bit-size respectively of key.
 *
 * - PSA_SIGNATURE_MAX_SIZE evaluates to the maximum signature size of any supported signature
 *   algorithm.
 *
 * Return:
 * * PSA_SUCCESS
 * * PSA_ERROR_INVALID_HANDLE
 * * PSA_ERROR_NOT_PERMITTED:
 *	The key does not have the PSA_KEY_USAGE_SIGN_MESSAGE flag, or it does not permit the
 *	requested algorithm.
 * * PSA_ERROR_BUFFER_TOO_SMALL:
 *	The size of the signature buffer is too small. PSA_SIGN_OUTPUT_SIZE() or
 *	PSA_SIGNATURE_MAX_SIZE can be used to determine the required buffer size.
 * * PSA_ERROR_NOT_SUPPORTED
 * * PSA_ERROR_INVALID_ARGUMENT
 * * PSA_ERROR_INSUFFICIENT_MEMORY
 * * PSA_ERROR_COMMUNICATION_FAILURE
 * * PSA_ERROR_HARDWARE_FAILURE
 * * PSA_ERROR_CORRUPTION_DETECTED
 * * PSA_ERROR_STORAGE_FAILURE
 * * PSA_ERROR_DATA_CORRUPT
 * * PSA_ERROR_DATA_INVALID
 * * PSA_ERROR_INSUFFICIENT_ENTROPY
 * * PSA_ERROR_BAD_STATE:
 *	The library has not been previously initialized by psa_crypto_init(). It is
 *	implementation-dependent whether a failure to initialize results in this error code.
 */
psa_status_t psa_sign_message(psa_key_id_t key, psa_algorithm_t alg,
			      const uint8_t *input, size_t input_length,
			      uint8_t *signature, size_t signature_size,
			      size_t *signature_length);

/**
 * psa_verify_hash() - Verify the signature of a hash or short message using a public key.
 * @key: Identifier of the key to use for the operation. It must be a public key or an asymmetric
 *       key pair. The key must allow the usage PSA_KEY_USAGE_VERIFY_HASH.
 * @alg: An asymmetric signature algorithm that separates the hash and sign operations
 *       (PSA_ALG_XXX value such that PSA_ALG_IS_SIGN_HASH(alg) is true), that is compatible with
 *       the type of key.
 * @hash: The input whose signature is to be verified. This is usually the hash of a message. See
 *        the detailed description of this function and the description of individual signature
 *        algorithms for a detailed description of acceptable inputs.
 * @hash_length: Size of the @hash buffer in bytes.
 * @signature: Buffer containing the signature to verify.
 * @signature_length: Size of the signature buffer in bytes.
 *
 * With most signature mechanisms that follow the hash-and-sign paradigm, the hash input to this
 * function is the hash of the message to sign. The hash algorithm is encoded in the signature
 * algorithm.
 *
 * Some hash-and-sign mechanisms apply a padding or encoding to the hash. In such cases, the encoded
 * hash must be passed to this function. The current version of this specification defines one such
 * signature algorithm: PSA_ALG_RSA_PKCS1V15_SIGN_RAW.
 *
 * **Note**:
 *	To perform a hash-and-sign verification algorithm, the hash must be calculated before
 *	passing it to this function. This can be done by calling psa_hash_compute() or with a
 *	multi-part hash operation. Alternatively, to hash and verify a message signature in a single
 *	call, use psa_verify_message().
 *
 * Return:
 * * PSA_SUCCESS:
 *	The signature is valid.
 * * PSA_ERROR_INVALID_HANDLE
 * * PSA_ERROR_NOT_PERMITTED:
 *	The key does not have the PSA_KEY_USAGE_VERIFY_HASH flag, or it does not permit the
 *	requested algorithm.
 * * PSA_ERROR_INVALID_SIGNATURE:
 *	The calculation was performed successfully, but the passed signature is not a valid
 *	signature.
 * * PSA_ERROR_NOT_SUPPORTED
 * * PSA_ERROR_INVALID_ARGUMENT
 * * PSA_ERROR_INSUFFICIENT_MEMORY
 * * PSA_ERROR_COMMUNICATION_FAILURE
 * * PSA_ERROR_HARDWARE_FAILURE
 * * PSA_ERROR_CORRUPTION_DETECTED
 * * PSA_ERROR_STORAGE_FAILURE
 * * PSA_ERROR_DATA_CORRUPT
 * * PSA_ERROR_DATA_INVALID
 * * PSA_ERROR_BAD_STATE:
 *	The library has not been previously initialized by psa_crypto_init(). It is
 *	implementation-dependent whether a failure to initialize results in this error code.
 */
psa_status_t psa_verify_hash(psa_key_id_t key, psa_algorithm_t alg,
			     const uint8_t *hash, size_t hash_length,
			     const uint8_t *signature, size_t signature_length);

/**
 * psa_verify_message() - Verify the signature of a message with a public key, using a hash-and-sign
 * verification algorithm.
 * @key: Identifier of the key to use for the operation. It must be a public key or an asymmetric
 *       key pair. The key must allow the usage PSA_KEY_USAGE_VERIFY_MESSAGE.
 * @alg: An asymmetric signature algorithm (PSA_ALG_XXX value such that
 *       PSA_ALG_IS_SIGN_MESSAGE(alg) is true), that is compatible with the type of key.
 * @input: The message whose signature is to be verified.
 * @input_length: Size of the @input buffer in bytes.
 * @signature: Buffer containing the signature to verify.
 * @signature_length: Size of the @signature buffer in bytes.
 *
 * **Note**:
 *	To perform a multi-part hash-and-sign signature verification algorithm, first use a
 *	multi-part hash operation to hash the message and then pass the resulting hash to
 *	psa_verify_hash(). PSA_ALG_GET_HASH(alg) can be used to determine the hash algorithm to
 *	use.
 *
 * Return:
 * * PSA_SUCCESS:
 *	The signature is valid.
 * * PSA_ERROR_INVALID_HANDLE
 * * PSA_ERROR_NOT_PERMITTED:
 *	The key does not have the PSA_KEY_USAGE_VERIFY_MESSAGE flag, or it does not permit the
 *	requested algorithm.
 * * PSA_ERROR_INVALID_SIGNATURE:
 *	The calculation was performed successfully, but the passed signature is not a valid
 *	signature.
 * * PSA_ERROR_NOT_SUPPORTED
 * * PSA_ERROR_INVALID_ARGUMENT
 * * PSA_ERROR_INSUFFICIENT_MEMORY
 * * PSA_ERROR_COMMUNICATION_FAILURE
 * * PSA_ERROR_HARDWARE_FAILURE
 * * PSA_ERROR_CORRUPTION_DETECTED
 * * PSA_ERROR_STORAGE_FAILURE
 * * PSA_ERROR_DATA_CORRUPT
 * * PSA_ERROR_DATA_INVALID
 * * PSA_ERROR_BAD_STATE:
 *	The library has not been previously initialized by psa_crypto_init(). It is
 *	implementation-dependent whether a failure to initialize results in this error code.
 */
psa_status_t psa_verify_message(psa_key_id_t key, psa_algorithm_t alg,
				const uint8_t *input, size_t input_length,
				const uint8_t *signature,
				size_t signature_length);

#include "psa/crypto_sizes.h"
#include "psa/crypto_struct.h"

#endif /* __PSA_CRYPTO_H__ */
