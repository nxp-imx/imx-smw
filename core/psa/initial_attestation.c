// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022 NXP
 */

#include <psa/initial_attestation.h>

#include "compiler.h"
#include "debug.h"

__export psa_status_t
/* Without this comment clang-format does not meet the checkpatch requirement. */
psa_initial_attest_get_token(const uint8_t *auth_challenge,
			     size_t challenge_size, uint8_t *token_buf,
			     size_t token_buf_size, size_t *token_size)
{
	(void)auth_challenge;
	(void)challenge_size;
	(void)token_buf;
	(void)token_buf_size;
	(void)token_size;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

__export psa_status_t psa_initial_attest_get_token_size(size_t challenge_size,
							size_t *token_size)
{
	(void)challenge_size;
	(void)token_size;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

__export psa_status_t psa_attest_key(psa_key_id_t key,
				     const uint8_t *auth_challenge,
				     size_t *auth_challenge_size,
				     uint8_t *cert_buf, size_t cert_buf_size,
				     size_t *cert_size)
{
	(void)key;
	(void)auth_challenge;
	(void)auth_challenge_size;
	(void)cert_buf;
	(void)cert_buf_size;
	(void)cert_size;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

__export psa_status_t psa_attest_key_get_size(psa_key_id_t key,
					      size_t auth_challenge_size,
					      size_t *cert_size)
{
	(void)key;
	(void)auth_challenge_size;
	(void)cert_size;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}
