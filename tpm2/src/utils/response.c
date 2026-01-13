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
