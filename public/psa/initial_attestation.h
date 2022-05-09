/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2022 NXP
 */

#ifndef __PSA_INITIAL_ATTESTATION_H__
#define __PSA_INITIAL_ATTESTATION_H__

#include <stdint.h>
#include <stddef.h>

#include "psa/error.h"
#include "psa/crypto.h"

/**
 * DOC:
 * The PSA Attestation API is a standard interface provided by the PSA Root of Trust. The
 * definition of the PSA Root of Trust is described in the PSA Security Model
 * (PSA-SM - https://www.arm.com/architecture/security-features).
 *
 * The API can be used either to directly sign data or as a way to bootstrap trust in other
 * attestation schemes. PSA provides a framework and the minimal generic security features allowing
 * OEM and service providers to integrate various attestation schemes on top of the PSA Root of
 * Trust.
 */

/**
 * DOC: Reference
 * Documentation:
 *	PSA Attestation API v1.0.2
 * Link:
 *	https://armkeil.blob.core.windows.net/developer/Files/pdf/PlatformSecurityArchitecture/Implement/IHI0085-PSA_Attestation_API-1.0.2.pdf
 */

#define PSA_INITIAL_ATTEST_API_VERSION_MAJOR (1)
#define PSA_INITIAL_ATTEST_API_VERSION_MINOR (0)
#define PSA_INITIAL_ATTEST_MAX_TOKEN_SIZE    /*...*/
#define PSA_INITIAL_ATTEST_CHALLENGE_SIZE_32 (32u)
#define PSA_INITIAL_ATTEST_CHALLENGE_SIZE_48 (48u)
#define PSA_INITIAL_ATTEST_CHALLENGE_SIZE_64 (64u)

/**
 * psa_initial_attest_get_token() - Retrieve the Initial Attestation Token.
 * @auth_challenge: Buffer with a challenge object. The challenge object is data provided by the
 *		    caller. For example, it may be a cryptographic nonce or a hash of data (such as
 *		    an external object record). If a hash of data is provided then it is the
 *		    caller’s responsibility to ensure that the data is protected against replay
 *		    attacks (for example, by including a cryptographic nonce within the data).
 * @challenge_size: Size of the buffer @auth_challenge in bytes. The size must always be a
 *		    supported challenge size. Supported challenge sizes are defined by the
 *		    PSA_INITIAL_ATTEST_CHALLENGE_SIZE_xxx constant.
 * @token_buf: Output buffer where the attestation token is to be written.
 * @token_buf_size: Size of @token_buf. The expected size can be determined by using
 *		    psa_initial_attest_get_token_size().
 * @token_size: Output variable for the actual token size.
 *
 * **Warning: Not supported**
 *
 * Retrieves the Initial Attestation Token. A challenge can be passed as an input to mitigate
 * replay attacks.
 *
 * Return:
 * * PSA_SUCCESS:
 *	Action was performed successfully.
 * * PSA_ERROR_SERVICE_FAILURE:
 *	The implementation failed to fully initialize.
 * * PSA_ERROR_BUFFER_TOO_SMALL:
 *	@token_buf is too small for the attestation token.
 * * PSA_ERROR_INVALID_ARGUMENT:
 *	The challenge size is not supported.
 * * PSA_ERROR_GENERIC_ERROR:
 *	An unspecified internal error has occurred.
 */
psa_status_t psa_initial_attest_get_token(const uint8_t *auth_challenge,
					  size_t challenge_size,
					  uint8_t *token_buf,
					  size_t token_buf_size,
					  size_t *token_size);

/**
 * psa_initial_attest_get_token_size() - Calculate the size of an Initial Attestation Token.
 * @challenge_size: Size of a challenge object in bytes. This must be a supported challenge size as
 *		    defined by the PSA_INITIAL_ATTEST_CHALLENGE_SIZE_xxx constant.
 * @token_size: Output variable for the token size.
 *
 * **Warning: Not supported**
 *
 * Retrieve the exact size of the Initial Attestation Token in bytes, given a specific challenge
 * size.
 *
 * Return:
 * * PSA_SUCCESS:
 *	Action was performed successfully.
 * * PSA_ERROR_SERVICE_FAILURE:
 *	The implementation failed to fully initialize.
 * * PSA_ERROR_INVALID_ARGUMENT:
 *	The challenge size is not supported.
 * * PSA_ERROR_GENERIC_ERROR:
 *	An unspecified internal error has occurred.
 */
psa_status_t psa_initial_attest_get_token_size(size_t challenge_size,
					       size_t *token_size);

/**
 * psa_attest_key() - Retrieve a Key Attestation.
 * @key: Key identifier.
 * @auth_challenge: Buffer with a challenge object. The challenge object is data provided by the
 *		    caller. For example, it may be a cryptographic nonce or a hash of data (such as
 *		    an external object record). If a hash of data is provided then it is the
 *		    caller’s responsibility to ensure that the data is protected against replay
 *		    attacks (for example, by including a cryptographic nonce within the data).
 * @challenge_size: Size of a challenge object in bytes. This must be a supported challenge size as
 *		    defined by the PSA_INITIAL_ATTEST_CHALLENGE_SIZE_xxx constant.
 * @cert_buf: Output variable for the Key Attestation certificate.
 * @cert_buf_size: Maximum size of the Key Attestation certificate.
 * @cert_size: Output variable for the actual Key Attestation certificate size.
 *
 * **Warning: Not supported**
 *
 * Retrieves the Key Attestation certificate. A challenge can be passed as an input to mitigate
 * replay attacks.
 *
 * Return:
 * * PSA_SUCCESS:
 *	Action was performed successfully.
 * * PSA_ERROR_SERVICE_FAILURE:
 *	The implementation failed to fully initialize.
 * * PSA_ERROR_INVALID_ARGUMENT:
 *	The challenge size is not supported.
 * * PSA_ERROR_GENERIC_ERROR:
 *	An unspecified internal error has occurred.
 */
psa_status_t psa_attest_key(psa_key_id_t key, const uint8_t *auth_challenge,
			    size_t *challenge_size, uint8_t *cert_buf,
			    size_t cert_buf_size, size_t *cert_size);

/**
 * psa_attest_key_get_size() - Calculate the size of a Key Attestation certificate.
 * @key: Key identifier.
 * @challenge_size: Size of a challenge object in bytes. This must be a supported challenge size as
 *		    defined by the PSA_INITIAL_ATTEST_CHALLENGE_SIZE_xxx constant.
 * @cert_size: Output variable for the certificate size.
 *
 * **Warning: Not supported**
 *
 * Retrieve the exact size of the Key Attestation certificate in bytes, given a specific challenge
 * size.
 *
 * Return:
 * * PSA_SUCCESS:
 *	Action was performed successfully.
 * * PSA_ERROR_SERVICE_FAILURE:
 *	The implementation failed to fully initialize.
 * * PSA_ERROR_INVALID_ARGUMENT:
 *	The challenge size is not supported.
 * * PSA_ERROR_GENERIC_ERROR:
 *	An unspecified internal error has occurred.
 */
psa_status_t psa_attest_key_get_size(psa_key_id_t key, size_t challenge_size,
				     size_t *cert_size);

#endif /* __PSA_INITIAL_ATTESTATION_H__ */
