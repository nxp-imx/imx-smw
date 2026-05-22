// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2026 NXP
 */

#include "psa/initial_attestation.h"

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
