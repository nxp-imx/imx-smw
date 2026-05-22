/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2022, 2026 NXP
 */

#ifndef __PSA_INITIAL_ATTESTATION_H__
#define __PSA_INITIAL_ATTESTATION_H__

#include <stdint.h>
#include <stddef.h>

#include "psa/error.h"
#include "psa/crypto.h"

/*
 * The PSA Attestation API is a standard interface provided by the PSA Root of
 * Trust. The definition of the PSA Root of Trust is described in the PSA
 * Security Model (PSA-SM - https://www.arm.com/architecture/security-features).
 *
 * The API can be used either to directly sign data or as a way to bootstrap
 * trust in other attestation schemes. PSA provides a framework and the minimal
 * generic security features allowing OEM and service providers to integrate
 * various attestation schemes on top of the PSA Root of Trust.
 */

/*
 * Reference
 * Documentation:
 *  PSA Certified Attestation API v1.0.4
 * Link:
 *  https://arm-software.github.io/psa-api/attestation/1.0/
 */

#define PSA_INITIAL_ATTEST_API_VERSION_MAJOR (1)
#define PSA_INITIAL_ATTEST_API_VERSION_MINOR (0)
#define PSA_INITIAL_ATTEST_MAX_TOKEN_SIZE    /*...*/

/* Supported Challenge sizes */
#define PSA_INITIAL_ATTEST_CHALLENGE_SIZE_32 (32u)
#define PSA_INITIAL_ATTEST_CHALLENGE_SIZE_48 (48u)
#define PSA_INITIAL_ATTEST_CHALLENGE_SIZE_64 (64u)

/**
 * psa_initial_attest_get_token() - Retrieve the Initial Attestation Token.
 * @auth_challenge: [in] Buffer with a challenge object. The challenge object is
 *                       data provided by the caller. For example, it may be a
 *                       cryptographic nonce or a hash of data (such as an
 *                       external object record).
 * @challenge_size: [in] Size of the buffer @auth_challenge in bytes. The size
 *                       must always be a supported challenge size.
 * @token_buf: [out] Output buffer where the attestation token is to be written.
 * @token_buf_size: [in] Size of @token_buf. The expected size can be determined
 *                       by using psa_initial_attest_get_token_size().
 * @token_size: [out] Output variable for the actual token size.
 *
 * .. warning::
 *    Not supported.
 *
 * Retrieves the Initial Attestation Token. A challenge can be passed as an
 * input to mitigate replay attacks.
 *
 * If the @auth_challenge is a hash of data is then it is the caller’s
 * responsibility to ensure that the data is protected against replay attacks
 * (for example, by including a cryptographic nonce within the data).
 *
 * Return:
 *  - PSA_SUCCESS:
 *      Action was performed successfully.
 *  - PSA_ERROR_SERVICE_FAILURE:
 *      Secure target failed to initialize.
 *  - PSA_ERROR_BUFFER_TOO_SMALL:
 *	@token_buf is too small for the attestation token.
 *  - PSA_ERROR_INVALID_ARGUMENT:
 *      The challenge size is not supported.
 *  - PSA_ERROR_GENERIC_ERROR:
 *      An unspecified internal error has occurred.
 */
psa_status_t psa_initial_attest_get_token(const uint8_t *auth_challenge,
					  size_t challenge_size,
					  uint8_t *token_buf,
					  size_t token_buf_size,
					  size_t *token_size);

/**
 * psa_initial_attest_get_token_size() - Calculate the size of an Initial
 *                                       Attestation Token.
 * @challenge_size: [in] Size of a challenge object in bytes. This must be a
 *                       supported challenge size.
 * @token_size: [out] Output variable for the token size.
 *
 * .. warning::
 *    Not supported.
 *
 * Retrieve the exact size of the Initial Attestation Token in bytes, given a
 * specific challenge size.
 *
 * Return:
 *  - PSA_SUCCESS:
 *      Action was performed successfully.
 *  - PSA_ERROR_SERVICE_FAILURE:
 *      Secure target failed to initialize.
 *  - PSA_ERROR_INVALID_ARGUMENT:
 *      The challenge size is not supported.
 *  - PSA_ERROR_GENERIC_ERROR:
 *      An unspecified internal error has occurred.
 */
psa_status_t psa_initial_attest_get_token_size(size_t challenge_size,
					       size_t *token_size);

#endif /* __PSA_INITIAL_ATTESTATION_H__ */
