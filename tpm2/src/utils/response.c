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

static uint32_t calc_single_auth_size(tcti_smw_session_t *sess,
				      uint32_t *size_out,
				      uint16_t *hmac_size_out)
{
	TSS2_RC rc = TSS2_RC_SUCCESS;
	uint32_t size = 0;
	uint16_t nonce_size = 0;
	uint16_t hmac_size = 0;

	if (!size_out) {
		rc = TSS2_TCTI_RC_BAD_REFERENCE;
		goto end;
	}

	if (sess && sess->active) {
		nonce_size = sess->nonce.size;
		hmac_size = TPM2_SHA256_DIGEST_SIZE; /* Assuming SHA256 HMAC */
	}

	/* nonceTPM (TPM2B_NONCE) */
	if (ADD_OVERFLOW(size, sizeof(uint16_t), &size)) {
		rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	if (ADD_OVERFLOW(size, nonce_size, &size)) {
		rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	/* sessionAttributes (TPMA_SESSION) */
	if (ADD_OVERFLOW(size, sizeof(uint8_t), &size)) {
		rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	/* hmac (TPM2B_AUTH) */
	if (ADD_OVERFLOW(size, sizeof(uint16_t), &size)) {
		rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	if (ADD_OVERFLOW(size, hmac_size, &size)) {
		rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	*size_out = size;

	if (hmac_size_out)
		*hmac_size_out = hmac_size;

end:
	DBG_TRACE_COND(rc != TSS2_RC_SUCCESS, "return error: 0x%08x\n", rc);
	return rc;
}

static uint32_t
marshal_single_auth_response(/* Without this comment */
			     /* clang-format does not meet the checkpatch requirement. */
			     tcti_smw_context_t *ctx, size_t *offset,
			     tcti_smw_session_t *sess,
			     TPM2B_NONCE *nonce_caller, TPM2_RC response_code,
			     TPM2_CC command_code, uint8_t *params_buffer,
			     size_t params_size)
{
	TSS2_RC rc = TSS2_RC_SUCCESS;
	uint8_t *response_hmac = NULL;
	uint16_t response_hmac_size = 0;
	uint8_t tpma_attrs = TPMA_SESSION_CONTINUESESSION;
	bool has_session = (sess && sess->active && nonce_caller->size > 0);

	/* Calculate HMAC if session is active */
	if (has_session) {
		rc = calculate_response_hmac(sess, response_code, command_code,
					     params_buffer, params_size,
					     nonce_caller->buffer,
					     nonce_caller->size, &response_hmac,
					     &response_hmac_size);
		if (rc != TSS2_RC_SUCCESS) {
			DBG_TRACE("Failed to calculate response HMAC\n");
			goto end;
		}
	}

	/* Marshal nonceTPM */
	if (has_session) {
		rc = Tss2_MU_TPM2B_NONCE_Marshal(&sess->nonce, ctx->resp_buf,
						 ctx->resp_size, offset);
	} else {
		/* Empty nonce for password session */
		rc = Tss2_MU_UINT16_Marshal(0, ctx->resp_buf, ctx->resp_size,
					    offset);
	}
	if (rc != TSS2_RC_SUCCESS)
		goto end;

	/* Marshal sessionAttributes */
	rc = Tss2_MU_UINT8_Marshal(tpma_attrs, ctx->resp_buf, ctx->resp_size,
				   offset);
	if (rc != TSS2_RC_SUCCESS)
		goto end;

	/* Marshal HMAC */
	if (has_session && response_hmac_size > 0) {
		rc = Tss2_MU_UINT16_Marshal(response_hmac_size, ctx->resp_buf,
					    ctx->resp_size, offset);
		if (rc != TSS2_RC_SUCCESS)
			goto end;

		memcpy(&ctx->resp_buf[*offset], response_hmac,
		       response_hmac_size);
		*offset += response_hmac_size;
	} else {
		/* Empty HMAC for password session */
		rc = Tss2_MU_UINT16_Marshal(0, ctx->resp_buf, ctx->resp_size,
					    offset);
	}

end:
	if (response_hmac)
		free(response_hmac);

	return rc;
}

uint32_t build_auth_response_multi(tcti_smw_context_t *ctx,
				   auth_session_info_t *auth_sessions,
				   size_t nb_sessions, TPM2_RC response_code,
				   TPM2_CC command_code, uint16_t tag,
				   uint8_t *params_buffer, size_t params_size,
				   TPM2_HANDLE *handle)
{
	TSS2_RC rc = TSS2_RC_SUCCESS;
	size_t resp_offset = TPM_HEADER_SIZE;
	uint32_t total_resp_size = 0;
	uint32_t auth_area_size = 0;
	uint32_t single_auth_size = 0;
	uint8_t i = 0;
	bool has_auth_area = (tag == TPM2_ST_SESSIONS);

	if (!ctx || (params_size > 0 && !params_buffer)) {
		rc = TSS2_TCTI_RC_BAD_REFERENCE;
		goto end;
	}

	if (nb_sessions > MAX_AUTH_SESSIONS) {
		DBG_TRACE("Too many auth sessions: %zu > %d\n", nb_sessions,
			  MAX_AUTH_SESSIONS);
		rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
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
		/* Parameters size field */
		if (ADD_OVERFLOW(total_resp_size, sizeof(uint32_t),
				 &total_resp_size)) {
			rc = TSS2_TCTI_RC_BAD_VALUE;
			goto end;
		}

		/* Parameters */
		if (ADD_OVERFLOW(total_resp_size, params_size,
				 &total_resp_size)) {
			rc = TSS2_TCTI_RC_BAD_VALUE;
			goto end;
		}

		/* Auth area for each session */
		for (; i < nb_sessions; i++) {
			rc = calc_single_auth_size(/* Without this comment */
						   /* clang-format does not */
						   /* meet the checkpatch requirement. */
						   auth_sessions[i].session ?
							   auth_sessions[i]
								   .session :
							   NULL,
						   &single_auth_size, NULL);
			if (rc != TSS2_RC_SUCCESS)
				goto end;

			if (ADD_OVERFLOW(auth_area_size, single_auth_size,
					 &auth_area_size)) {
				rc = TSS2_TCTI_RC_BAD_VALUE;
				goto end;
			}
		}

		if (ADD_OVERFLOW(total_resp_size, auth_area_size,
				 &total_resp_size)) {
			rc = TSS2_TCTI_RC_BAD_VALUE;
			goto end;
		}
	} else {
		/* No auth area - just parameters */
		if (ADD_OVERFLOW(total_resp_size, params_size,
				 &total_resp_size)) {
			rc = TSS2_TCTI_RC_BAD_VALUE;
			goto end;
		}
	}

	DBG_TRACE("Building response:\n"
		  "  total_size: %u\n"
		  "  nb_sessions: %zu\n"
		  "  params_size: %zu\n"
		  "  auth_area_size: %u\n",
		  total_resp_size, nb_sessions, params_size, auth_area_size);

	/* Build response header */
	rc = build_rc_response(ctx, total_resp_size, tag, response_code);
	if (rc != TSS2_RC_SUCCESS)
		goto end;

	if (!ctx->resp_buf) {
		rc = TSS2_TCTI_RC_MEMORY;
		goto end;
	}

	/* Marshal handle if present */
	if (handle) {
		rc = Tss2_MU_UINT32_Marshal(*handle, ctx->resp_buf,
					    ctx->resp_size, &resp_offset);
		if (rc != TSS2_RC_SUCCESS)
			goto end;
	}

	if (has_auth_area) {
		/* Marshal parameters size */
		rc = Tss2_MU_UINT32_Marshal((uint32_t)params_size,
					    ctx->resp_buf, ctx->resp_size,
					    &resp_offset);
		if (rc != TSS2_RC_SUCCESS)
			goto end;

		/* Marshal parameters */
		if (params_size > 0 && params_buffer) {
			memcpy(&ctx->resp_buf[resp_offset], params_buffer,
			       params_size);
			resp_offset += params_size;
		}

		/* Marshal auth response for each session */
		for (i = 0; i < nb_sessions; i++) {
			tcti_smw_session_t *sess =
				auth_sessions[i].session ?
					auth_sessions[i].session :
					NULL;
			TPM2B_NONCE *nonce = &auth_sessions[i].nonce_caller;

			rc = marshal_single_auth_response(/* Without this comment */
							  /* clang-format does not meet the */
							  /* checkpatch requirement. */
							  ctx, &resp_offset,
							  sess, nonce,
							  response_code,
							  command_code,
							  params_buffer,
							  params_size);
			if (rc != TSS2_RC_SUCCESS)
				goto end;
		}
	} else {
		/* No auth area - just marshal parameters */
		if (params_size > 0 && params_buffer) {
			memcpy(&ctx->resp_buf[resp_offset], params_buffer,
			       params_size);
			resp_offset += params_size;
		}
	}

	DBG_TRACE("Response built successfully: %zu bytes\n", resp_offset);

end:
	DBG_TRACE_COND(rc != TSS2_RC_SUCCESS, "return error: 0x%08x\n", rc);
	return rc;
}

uint32_t build_auth_response(tcti_smw_context_t *ctx, tcti_smw_session_t *sess,
			     TPM2_RC response_code, TPM2_CC command_code,
			     uint16_t tag, uint8_t *params_buffer,
			     size_t params_size, TPM2B_NONCE *nonce_caller,
			     TPM2_HANDLE *handle)
{
	TPM2B_AUTH hmac = { 0 };
	TPM2B_NONCE nonce = { 0 };
	size_t nb_sessions = (tag == TPM2_ST_SESSIONS) ? 1 : 0;

	if (nonce_caller)
		nonce = *nonce_caller;

	auth_session_info_t auth_session[1] = { { .session_handle = 0,
						  .nonce_caller = nonce,
						  .session_attributes = 0,
						  .hmac = hmac,
						  .session = sess } };

	return build_auth_response_multi(ctx, auth_session, nb_sessions,
					 response_code, command_code, tag,
					 params_buffer, params_size, handle);
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
