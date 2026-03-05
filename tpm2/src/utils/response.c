// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <stdlib.h>
#include <string.h>

#include "utils.h"
#include "trace.h"

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

uint32_t build_auth_response(tcti_smw_context_t *ctx, tcti_smw_session_t *sess,
			     TPM2_RC response_code, TPM2_CC command_code,
			     uint16_t tag, uint8_t *params_buffer,
			     size_t params_size, TPM2B_NONCE *nonce_caller,
			     TPM2_HANDLE *handle)
{
	TSS2_RC rc = TSS2_RC_SUCCESS;
	uint8_t *response_hmac = NULL;
	uint16_t response_hmac_size = 0, nonce_size = 0;
	uint8_t tpma_attrs = TPMA_SESSION_CONTINUESESSION;
	size_t resp_offset = TPM_HEADER_SIZE;
	uint32_t total_resp_size = 0;
	bool has_auth_area = (tag == TPM2_ST_SESSIONS);
	bool has_session = (sess && nonce_caller);

	if (!ctx || (params_size > 0 && !params_buffer)) {
		rc = TSS2_TCTI_RC_BAD_REFERENCE;
		goto end;
	}

	/* Calculate response HMAC only if authorization area and session are present */
	if (has_auth_area && has_session) {
		rc = calculate_response_hmac(sess, response_code, command_code,
					     params_buffer, params_size,
					     nonce_caller->buffer,
					     nonce_caller->size, &response_hmac,
					     &response_hmac_size);
		if (rc != TSS2_RC_SUCCESS) {
			DBG_TRACE("Failed to calculate response HMAC\n");
			goto end;
		}
		nonce_size = sess->nonce.size;
	}

	/* Calculate total response size */
	total_resp_size = TPM_HEADER_SIZE;

	/* Handle (zero or one) */
	if (handle) {
		if (ADD_OVERFLOW(total_resp_size, sizeof(TPM2_HANDLE),
				 &total_resp_size)) {
			rc = TSS2_TCTI_RC_BAD_VALUE;
			goto end;
		}
	}

	if (has_auth_area) {
		/* Parameters size */
		if (ADD_OVERFLOW(total_resp_size, sizeof(uint32_t),
				 &total_resp_size)) {
			rc = TSS2_TCTI_RC_BAD_VALUE;
			goto end;
		}

		/* Nonce size + nonce data */
		if (ADD_OVERFLOW(total_resp_size, sizeof(uint16_t) + nonce_size,
				 &total_resp_size)) {
			rc = TSS2_TCTI_RC_BAD_VALUE;
			goto end;
		}

		/* Session attributes */
		if (ADD_OVERFLOW(total_resp_size, sizeof(uint8_t),
				 &total_resp_size)) {
			rc = TSS2_TCTI_RC_BAD_VALUE;
			goto end;
		}

		/* HMAC size + HMAC data */
		if (ADD_OVERFLOW(total_resp_size,
				 sizeof(uint16_t) + response_hmac_size,
				 &total_resp_size)) {
			rc = TSS2_TCTI_RC_BAD_VALUE;
			goto end;
		}
	}

	/* Parameters area */
	if (ADD_OVERFLOW(total_resp_size, params_size, &total_resp_size)) {
		rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	/* Build response */
	rc = build_rc_response(ctx, total_resp_size, tag, response_code);
	if (rc != TSS2_RC_SUCCESS)
		goto end;

	if (!ctx->resp_buf) {
		rc = TSS2_TCTI_RC_MEMORY;
		goto end;
	}

	/* Marshal handles */
	if (handle) {
		rc = Tss2_MU_UINT32_Marshal(*handle, ctx->resp_buf,
					    ctx->resp_size, &resp_offset);
		if (rc != TSS2_RC_SUCCESS)
			goto end;
	}

	/* Marshal parameters size */
	if (has_auth_area) {
		rc = Tss2_MU_UINT32_Marshal((uint32_t)params_size,
					    ctx->resp_buf, ctx->resp_size,
					    &resp_offset);
		if (rc != TSS2_RC_SUCCESS)
			goto end;
	}

	/* Marshal parameters */
	if (params_size > 0 && params_buffer) {
		memcpy(&ctx->resp_buf[resp_offset], params_buffer, params_size);
		resp_offset += params_size;
	}

	/* Marshal auth response area */
	if (has_auth_area) {
		if (has_session) {
			rc = Tss2_MU_TPM2B_NONCE_Marshal(&sess->nonce,
							 ctx->resp_buf,
							 ctx->resp_size,
							 &resp_offset);
			if (rc != TSS2_RC_SUCCESS)
				goto end;
		} else {
			/* Empty nonce */
			rc = Tss2_MU_UINT16_Marshal(0, ctx->resp_buf,
						    ctx->resp_size,
						    &resp_offset);
			if (rc != TSS2_RC_SUCCESS)
				goto end;
		}

		rc = Tss2_MU_UINT8_Marshal(tpma_attrs, ctx->resp_buf,
					   ctx->resp_size, &resp_offset);
		if (rc != TSS2_RC_SUCCESS)
			goto end;

		if (has_session && response_hmac_size > 0) {
			rc = Tss2_MU_UINT16_Marshal(response_hmac_size,
						    ctx->resp_buf,
						    ctx->resp_size,
						    &resp_offset);
			if (rc != TSS2_RC_SUCCESS)
				goto end;

			memcpy(&ctx->resp_buf[resp_offset], response_hmac,
			       response_hmac_size);
		} else {
			/* Empty HMAC */
			rc = Tss2_MU_UINT16_Marshal(0, ctx->resp_buf,
						    ctx->resp_size,
						    &resp_offset);
			if (rc != TSS2_RC_SUCCESS)
				goto end;
		}
	}

end:
	if (response_hmac)
		free(response_hmac);

	DBG_TRACE_COND(rc != TSS2_RC_SUCCESS, "return error: 0x%08x\n", rc);
	return rc;
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
