// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <tss2/tss2_mu.h>

#include "utils.h"
#include "session.h"
#include "commands.h"
#include "crypto.h"
#include "trace.h"

uint32_t handle_startauthsession(tcti_smw_context_t *ctx, uint16_t tag,
				 const uint8_t *cmd, size_t cmd_size)
{
	uint32_t session_handle = 0;
	TPM2_RC rc = TPM2_RC_SUCCESS;
	TSS2_RC tss2_rc = TSS2_TCTI_RC_GENERAL_FAILURE;
	start_auth_session_params_t params = { 0 };
	size_t offset = TPM_HEADER_SIZE, resp_size = 0;
	uint16_t nonce_size = 0;
	TPM2B_NONCE nonce_tpm = { 0 };
	struct smw_rng_args rng_args = { 0 };
	enum smw_status_code smw_status = SMW_STATUS_OK;

	if (!ctx->initialized) {
		tss2_rc = TSS2_TCTI_RC_BAD_SEQUENCE;
		goto end;
	}

	tss2_rc = start_auth_session_unmarshal(cmd, cmd_size, &params);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	/* Prepare the nonce */
	tss2_rc = map_hash_info(params.auth_hash, &nonce_size, NULL);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	nonce_tpm.size = nonce_size;
	rng_args.output = nonce_tpm.buffer;
	rng_args.output_length = nonce_tpm.size;

	smw_status = smw_rng(&rng_args);
	if (smw_status != SMW_STATUS_OK) {
		DBG_TRACE("SMW RNG generation failed\n");
		tss2_rc = smw_rc_to_tcti_rc(smw_status);
		goto end;
	}

	tss2_rc = smw_session_alloc(ctx, &session_handle, nonce_tpm, &params);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	/*
	 * Minimal valid response payload:
	 *  sessionHandle        : 4
	 *  nonce_tpm (TPM2B)    : 2 (size = 0)
	 */
	resp_size = TPM_HEADER_SIZE + sizeof(uint32_t) + /* sessionHandle */
		    sizeof(uint16_t) +			 /* nonce_tpm.size */
		    nonce_size;

	tss2_rc = build_rc_response(ctx, resp_size, tag, TPM2_RC_SUCCESS);
	if (tss2_rc != TSS2_RC_SUCCESS)
		return tss2_rc;

	/* sessionHandle */
	tss2_rc = Tss2_MU_UINT32_Marshal(session_handle, ctx->resp_buf,
					 ctx->resp_size, &offset);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	/* nonce_tpm = empty TPM2B */
	tss2_rc = Tss2_MU_TPM2B_NONCE_Marshal(&nonce_tpm, ctx->resp_buf,
					      ctx->resp_size, &offset);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	/* Final sanity check */
	if (offset != resp_size) {
		DBG_TRACE("StartAuthSession response size mismatch ");
		DBG_TRACE("(offset=%zu, expected=%zu)\n", offset, resp_size);
		tss2_rc = TSS2_TCTI_RC_GENERAL_FAILURE;
		goto end;
	}

end:
	if (tss2_rc != TSS2_RC_SUCCESS) {
		rc = tcti_rc_to_tpm2_rc(tss2_rc);
		return build_rc_response(ctx, TPM_HEADER_SIZE, tag, rc);
	}

	return tss2_rc;
}
