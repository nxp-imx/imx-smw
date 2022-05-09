/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2022 NXP
 */

#ifndef __PSA_STATUS_H__
#define __PSA_STATUS_H__

#include <stdint.h>

/**
 * DOC:
 * This file defines the error codes returned by the PSA Cryptography API
 */

/**
 * DOC: Reference
 * Documentation:
 *	PSA Cryptography API v1.0.1
 * Link:
 *	https://developer.arm.com/documentation/ihi0086/a
 */

/**
 * typedef psa_status_t - Function return status.
 *
 * This is either PSA_SUCCESS, which is zero, indicating success; or a small negative value
 * indicating that an error occurred. Errors are encoded as one of the PSA_ERROR_xxx values defined
 * here.
 *
 * Values:
 * * PSA_SUCCESS:
 *	The action was completed successfully.
 * * PSA_ERROR_ALREADY_EXISTS:
 *	Asking for an item that already exists.
 *
 *	It is recommended that implementations return this error code when attempting to write to a
 *	location where a key is already present.
 * * PSA_ERROR_BAD_STATE:
 *	The requested action cannot be performed in the current state.
 *
 *	Multi-part operations return this error when one of the functions is called out of
 *	sequence.
 *	Refer to the function descriptions for permitted sequencing of functions.
 *
 *	Implementations must not return this error code to indicate that a key identifier is
 *	invalid, but must return PSA_ERROR_INVALID_HANDLE instead.
 * * PSA_ERROR_BUFFER_TOO_SMALL:
 *	An output buffer is too small.
 *
 *	Applications can call the PSA_xxx_SIZE macro listed in the function description to
 *	determine a sufficient buffer size.
 *
 *	It is recommended that implementations only return this error code in cases when performing
 *	the operation with a larger output buffer would succeed. However, implementations can also
 *	return this error if a function has invalid or unsupported parameters in addition to an
 *	insufficient output buffer size.
 * * PSA_ERROR_COMMUNICATION_FAILURE:
 *	There was a communication failure inside the implementation.
 *
 *	This can indicate a communication failure between the application and an external
 *	cryptoprocessor or between the cryptoprocessor and an external volatile or persistent
 *	memory. A communication failure can be transient or permanent depending on the cause.
 *
 *	**Warning**:
 *	  If a function returns this error, it is undetermined whether the requested action
 *	  has completed. Returning PSA_SUCCESS is recommended on successful completion
 *	  whenever possible, however functions can return PSA_ERROR_COMMUNICATION_FAILURE if
 *	  the requested action was completed successfully in an external cryptoprocessor but
 *	  there was a breakdown of communication before the cryptoprocessor could report the
 *	  status to the application.
 * * PSA_ERROR_CORRUPTION_DETECTED:
 *	A tampering attempt was detected.
 *
 *	If an application receives this error code, there is no guarantee that previously accessed
 *	or computed data was correct and remains confidential. In this situation, it is recommended
 *	that applications perform no further security functions and enter a safe failure state.
 *
 *	Implementations can return this error code if they detect an invalid state that cannot
 *	happen during normal operation and that indicates that the implementation’s security
 *	guarantees no longer hold. Depending on the implementation architecture and on its security
 *	and safety goals, the implementation might forcibly terminate the application.
 *
 *	This error code is intended as a last resort when a security breach is detected and it is
 *	unsure whether the keystore data is still protected. Implementations must only return this
 *	error code to report an alarm from a tampering detector, to indicate that the
 *	confidentiality of stored data can no longer be guaranteed, or to indicate that the
 *	integrity of previously returned data is now considered compromised. Implementations must
 *	not use this error code to indicate a hardware failure that merely makes it impossible to
 *	perform the requested operation, instead use PSA_ERROR_COMMUNICATION_FAILURE,
 *	PSA_ERROR_STORAGE_FAILURE, PSA_ERROR_HARDWARE_FAILURE, PSA_ERROR_INSUFFICIENT_ENTROPY or
 *	other applicable error code.
 *
 *	This error indicates an attack against the application. Implementations must not return
 *	this error code as a consequence of the behavior of the application itself.
 * * PSA_ERROR_DATA_CORRUPT:
 *	Stored data has been corrupted.
 *
 *	This error indicates that some persistent storage has suffered corruption. It does not
 *	indicate the following situations, which have specific error codes:
 *
 *	- A corruption of volatile memory - use PSA_ERROR_CORRUPTION_DETECTED.
 *
 *	- A communication error between the cryptoprocessor and its external storage - use
 *	  PSA_ERROR_COMMUNICATION_FAILURE.
 *
 *	- When the storage is in a valid state but is full - use PSA_ERROR_INSUFFICIENT_STORAGE.
 *
 *	- When the storage fails for other reasons - use PSA_ERROR_STORAGE_FAILURE.
 *
 *	- When the stored data is not valid - use PSA_ERROR_DATA_INVALID.
 *
 *	Note that a storage corruption does not indicate that any data that was previously read is
 *	invalid. However this previously read data might no longer be readable from storage.
 *
 *	When a storage failure occurs, it is no longer possible to ensure the global integrity of
 *	the keystore. Depending on the global integrity guarantees offered by the implementation,
 *	access to other data might fail even if the data is still readable but its integrity cannot
 *	be guaranteed.
 *
 *	It is recommended to only use this error code to report when a storage component indicates
 *	that the stored data is corrupt, or fails an integrity check. For example, in situations
 *	that the PSA Storage API [PSA-ITS] reports PSA_ERROR_DATA_CORRUPT or
 *	PSA_ERROR_INVALID_SIGNATURE.
 * * PSA_ERROR_DATA_INVALID:
 *	Data read from storage is not valid for the implementation.
 *
 *	This error indicates that some data read from storage does not have a valid format. It does
 *	not indicate the following situations, which have specific error codes:
 *
 *	- When the storage or stored data is corrupted - use PSA_ERROR_DATA_CORRUPT.
 *
 *	- When the storage fails for other reasons - use PSA_ERROR_STORAGE_FAILURE.
 *
 *	- An invalid argument to the API - use PSA_ERROR_INVALID_ARGUMENT.
 *
 *	This error is typically a result of an integration failure, where the implementation
 *	reading the data is not compatible with the implementation that stored the data.
 *
 *	It is recommended to only use this error code to report when data that is successfully read
 *	from storage is invalid.
 * * PSA_ERROR_DOES_NOT_EXIST:
 *	Asking for an item that doesn’t exist.
 *
 *	Implementations must not return this error code to indicate that a key identifier is
 *	invalid, but must return PSA_ERROR_INVALID_HANDLE instead.
 * * PSA_ERROR_GENERIC_ERROR:
 *	An error occurred that does not correspond to any defined failure cause.
 *
 *	Implementations can use this error code if none of the other standard error codes are
 *	applicable.
 * * PSA_ERROR_HARDWARE_FAILURE:
 *	A hardware failure was detected.
 *
 *	A hardware failure can be transient or permanent depending on the cause.
 * * PSA_ERROR_INSUFFICIENT_DATA:
 *	Return this error when there’s insufficient data when attempting to read from a resource.
 * * PSA_ERROR_INSUFFICIENT_ENTROPY:
 *	There is not enough entropy to generate random data needed for the requested action.
 *
 *	This error indicates a failure of a hardware random generator. Application writers must
 *	note that this error can be returned not only by functions whose purpose is to generate
 *	random data, such as key, IV or nonce generation, but also by functions that execute an
 *	algorithm with a randomized result, as well as functions that use randomization of
 *	intermediate computations as a countermeasure to certain attacks.
 *
 *	It is recommended that implementations do not return this error after psa_crypto_init() has
 *	succeeded. This can be achieved if the implementation generates sufficient entropy during
 *	initialization and subsequently a cryptographically secure pseudorandom generator (PRNG) is
 *	used. However, implementations might return this error at any time, for example, if a
 *	policy requires the PRNG to be reseeded during normal operation.
 * * PSA_ERROR_INSUFFICIENT_MEMORY:
 *	There is not enough runtime memory.
 *
 *	If the action is carried out across multiple security realms, this error can refer to
 *	available memory in any of the security realms.
 * * PSA_ERROR_INSUFFICIENT_STORAGE:
 *	There is not enough persistent storage.
 *
 *	Functions that modify the key storage return this error code if there is insufficient
 *	storage space on the host media. In addition, many functions that do not otherwise access
 *	storage might return this error code if the implementation requires a mandatory log entry
 *	for the requested action and the log storage space is full.
 * * PSA_ERROR_INVALID_ARGUMENT:
 *	The parameters passed to the function are invalid.
 *
 *	Implementations can return this error any time a parameter or combination of parameters are
 *	recognized as invalid.
 *
 *	Implementations must not return this error code to indicate that a key identifier is
 *	invalid, but must return PSA_ERROR_INVALID_HANDLE instead.
 * * PSA_ERROR_INVALID_HANDLE:
 *	The key identifier is not valid.
 * * PSA_ERROR_INVALID_PADDING:
 *	The decrypted padding is incorrect.
 *
 *	**Warning**:
 *	  In some protocols, when decrypting data, it is essential that the behavior of the
 *	  application does not depend on whether the padding is correct, down to precise timing.
 *	  Protocols that use authenticated encryption are recommended for use by applications,
 *	  rather than plain encryption. If the application must perform a decryption of
 *	  unauthenticated data, the application writer must take care not to reveal whether the
 *	  padding is invalid.
 *
 *	Implementations must handle padding carefully, aiming to make it impossible for an external
 *	observer to distinguish between valid and invalid padding. In particular, it is recommended
 *	that the timing of a decryption operation does not depend on the validity of the padding.
 * * PSA_ERROR_INVALID_SIGNATURE:
 *	The signature, MAC or hash is incorrect.
 *
 *	Verification functions return this error if the verification calculations completed
 *	successfully, and the value to be verified was determined to be incorrect.
 *
 *	If the value to verify has an invalid size, implementations can return either
 *	PSA_ERROR_INVALID_ARGUMENT or PSA_ERROR_INVALID_SIGNATURE.
 * * PSA_ERROR_NOT_PERMITTED:
 *	The requested action is denied by a policy.
 *
 *	It is recommended that implementations return this error code when the parameters are
 *	recognized as valid and supported, and a policy explicitly denies the requested operation.
 *
 *	If a subset of the parameters of a function call identify a forbidden operation, and
 *	another subset of the parameters are not valid or not supported, it is unspecified whether
 *	the function returns PSA_ERROR_NOT_PERMITTED, PSA_ERROR_NOT_SUPPORTED or
 *	PSA_ERROR_INVALID_ARGUMENT.
 * * PSA_ERROR_NOT_SUPPORTED:
 *	The requested operation or a parameter is not supported by this implementation.
 *
 *	It is recommended that implementations return this error code when an enumeration parameter
 *	such as a key type, algorithm, etc. is not recognized. If a combination of parameters is
 *	recognized and identified as not valid, return PSA_ERROR_INVALID_ARGUMENT instead.
 * * PSA_ERROR_STORAGE_FAILURE:
 *	There was a storage failure that might have led to data loss.
 *
 *	This error indicates that some persistent storage could not be read or written by the
 *	implementation. It does not indicate the following situations, which have specific error
 *	codes\:
 *
 *	- A corruption of volatile memory - use PSA_ERROR_CORRUPTION_DETECTED.
 *
 *	- A communication error between the cryptoprocessor and its external storage - use
 *	  PSA_ERROR_COMMUNICATION_FAILURE.
 *
 *	- When the storage is in a valid state but is full - use PSA_ERROR_INSUFFICIENT_STORAGE.
 *
 *	- When the storage or stored data is corrupted - use PSA_ERROR_DATA_CORRUPT.
 *
 *	- When the stored data is not valid - use PSA_ERROR_DATA_INVALID.
 *
 *	A storage failure does not indicate that any data that was previously read is invalid.
 *	However this previously read data might no longer be readable from storage.
 *
 *	When a storage failure occurs, it is no longer possible to ensure the global integrity of
 *	the keystore. Depending on the global integrity guarantees offered by the implementation,
 *	access to other data might fail even if the data is still readable but its integrity cannot
 *	be guaranteed.
 *
 *	It is recommended to only use this error code to report a permanent storage corruption.
 *	However application writers must keep in mind that transient errors while reading the
 *	storage might be reported using this error code.
 * * PSA_ERROR_INVALID_SIGNATURE:
 *	A PSA storage specific error code.
 *
 *	The signature on the data is invalid.
 * * PSA_ERROR_DATA_CORRUPT:
 *	A PSA storage specific error code.
 *
 *	The data on the underlying storage is corrupt.
 */
typedef int32_t psa_status_t;

#define PSA_SUCCESS			((psa_status_t)0)
#define PSA_ERROR_ALREADY_EXISTS	((psa_status_t)-139)
#define PSA_ERROR_BAD_STATE		((psa_status_t)-137)
#define PSA_ERROR_BUFFER_TOO_SMALL	((psa_status_t)-138)
#define PSA_ERROR_COMMUNICATION_FAILURE ((psa_status_t)-145)
#define PSA_ERROR_CORRUPTION_DETECTED	((psa_status_t)-151)
#define PSA_ERROR_DATA_CORRUPT		((psa_status_t)-152)
#define PSA_ERROR_DATA_INVALID		((psa_status_t)-153)
#define PSA_ERROR_DOES_NOT_EXIST	((psa_status_t)-140)
#define PSA_ERROR_GENERIC_ERROR		((psa_status_t)-132)
#define PSA_ERROR_HARDWARE_FAILURE	((psa_status_t)-147)
#define PSA_ERROR_INSUFFICIENT_DATA	((psa_status_t)-143)
#define PSA_ERROR_INSUFFICIENT_ENTROPY	((psa_status_t)-148)
#define PSA_ERROR_INSUFFICIENT_MEMORY	((psa_status_t)-141)
#define PSA_ERROR_INSUFFICIENT_STORAGE	((psa_status_t)-142)
#define PSA_ERROR_INVALID_ARGUMENT	((psa_status_t)-135)
#define PSA_ERROR_INVALID_HANDLE	((psa_status_t)-136)
#define PSA_ERROR_INVALID_PADDING	((psa_status_t)-150)
#define PSA_ERROR_INVALID_SIGNATURE	((psa_status_t)-149)
#define PSA_ERROR_NOT_PERMITTED		((psa_status_t)-133)
#define PSA_ERROR_NOT_SUPPORTED		((psa_status_t)-134)
#define PSA_ERROR_STORAGE_FAILURE	((psa_status_t)-146)
#define PSA_ERROR_INVALID_SIGNATURE	((psa_status_t)-149)
#define PSA_ERROR_DATA_CORRUPT		((psa_status_t)-152)

#endif /* __PSA_STATUS_H__ */
