// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <tss2/tss2_mu.h>

#include "utils.h"
#include "commands.h"

uint32_t handle_startup(tcti_smw_context_t *ctx, uint16_t tag,
			const uint8_t *cmd, size_t cmd_size)
{
	uint32_t resp_size = TPM_HEADER_SIZE; /* header only */
	TPM2_SU startup_type = TPM2_SU_STATE;
	TSS2_RC tss2_rc = TSS2_TCTI_RC_GENERAL_FAILURE;
	TPM2_RC rc = TPM2_RC_SUCCESS;

	tss2_rc = param_su_unmarshal(cmd, cmd_size, &startup_type);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	if (startup_type != TPM2_SU_CLEAR) {
		tss2_rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	ctx->initialized = 1;
	tss2_rc = build_rc_response(ctx, resp_size, tag, TPM2_RC_SUCCESS);
	if (tss2_rc != TSS2_RC_SUCCESS)
		return tss2_rc;

end:
	if (tss2_rc != TSS2_RC_SUCCESS) {
		rc = tcti_rc_to_tpm2_rc(tss2_rc);
		return build_rc_response(ctx, TPM_HEADER_SIZE, tag, rc);
	}

	return tss2_rc;
}

uint32_t handle_shutdown(tcti_smw_context_t *ctx, uint16_t tag,
			 const uint8_t *cmd, size_t cmd_size)
{
	uint32_t resp_size = TPM_HEADER_SIZE; /* header only */
	TPM2_SU shutdown_type = TPM2_SU_STATE;
	TSS2_RC tss2_rc = TSS2_TCTI_RC_GENERAL_FAILURE;
	TPM2_RC rc = TPM2_RC_SUCCESS;

	tss2_rc = param_su_unmarshal(cmd, cmd_size, &shutdown_type);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	if (shutdown_type != TPM2_SU_CLEAR) {
		tss2_rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	ctx->initialized = 0;
	tss2_rc = build_rc_response(ctx, resp_size, tag, TPM2_RC_SUCCESS);
	if (tss2_rc != TSS2_RC_SUCCESS)
		return tss2_rc;

end:
	if (tss2_rc != TSS2_RC_SUCCESS) {
		rc = tcti_rc_to_tpm2_rc(tss2_rc);
		return build_rc_response(ctx, TPM_HEADER_SIZE, tag, rc);
	}

	return tss2_rc;
}
