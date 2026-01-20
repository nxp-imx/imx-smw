// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <stdlib.h>

#include "utils.h"

void free_resp(tcti_smw_context_t *ctx)
{
	if (ctx && ctx->resp_buf) {
		free(ctx->resp_buf);
		ctx->resp_buf = NULL;
		ctx->resp_size = 0;
	}
}

uint32_t build_rc_response(tcti_smw_context_t *ctx, uint32_t resp_size,
			   uint16_t tag, TPM2_RC rc)
{
	TSS2_RC ret = TSS2_TCTI_RC_BAD_REFERENCE;
	tpm_smw_header_t header = { 0 };

	if (!ctx)
		return ret;

	/* Free any previous response */
	free_resp(ctx);

	/* Allocate minimal TPM response buffer */
	ctx->resp_size = resp_size;
	ctx->resp_buf = malloc(ctx->resp_size);
	if (!ctx->resp_buf)
		return TSS2_TCTI_RC_MEMORY;

	/* Build TPM response header */
	header.tag = tag;
	header.size = resp_size;
	header.code = rc;

	/* Marshal header into response buffer */
	ret = header_marshal(&header, ctx->resp_buf);
	if (ret != TSS2_RC_SUCCESS) {
		free_resp(ctx);
		return ret;
	}

	return TSS2_RC_SUCCESS;
}

uint32_t tcti_rc_to_tpm2_rc(TSS2_RC tcti_rc)
{
	switch (tcti_rc) {
	case TSS2_RC_SUCCESS:
		return TPM2_RC_SUCCESS;
	case TSS2_TCTI_RC_BAD_REFERENCE:
		return TPM2_RC_REFERENCE_H0;
	case TSS2_TCTI_RC_MEMORY:
		return TPM2_RC_MEMORY;
	case TSS2_TCTI_RC_BAD_VALUE:
		return TPM2_RC_VALUE;
	case TSS2_TCTI_RC_BAD_SEQUENCE:
		return TPM2_RC_SEQUENCE;
	case TSS2_TCTI_RC_INSUFFICIENT_BUFFER:
		return TPM2_RC_SIZE;
	case TSS2_TCTI_RC_NOT_IMPLEMENTED:
		return TPM2_RC_NOT_USED;
	case TSS2_TCTI_RC_MALFORMED_RESPONSE:
		return TPM2_RC_BAD_TAG;
	case TSS2_TCTI_RC_IO_ERROR:
	case TSS2_TCTI_RC_GENERAL_FAILURE:
	case TSS2_TCTI_RC_TRY_AGAIN:
	default:
		return TPM2_RC_FAILURE;
	}
}
