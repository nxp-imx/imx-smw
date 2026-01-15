// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <string.h>
#include <stdio.h>

#include <tss2/tss2_mu.h>

#include "utils.h"
#include "session.h"
#include "commands.h"
#include "crypto.h"
#include "trace.h"

static uint32_t context_save_transient(TPMS_CONTEXT *tpms_context,
				       TPMI_DH_CONTEXT handle)
{
	TSS2_RC tss2_rc = TSS2_RC_SUCCESS;

	/*
	 * For transient objects, the hierarchy depends on how they were created
	 * Since we don't track object creation yet,
	 * we use TPM2_RH_NULL for simplicity (valid for temporary objects)
	 */
	tpms_context->hierarchy = TPM2_RH_NULL;

	DBG_TRACE("Transient object context - ");
	DBG_TRACE("hierarchy set to TPM2_RH_NULL\n");

	/*
	 * In a full implementation, you would track:
	 * - TPM2_RH_OWNER: for objects created under owner hierarchy
	 * - TPM2_RH_PLATFORM: for objects created under platform hierarchy
	 * - TPM2_RH_ENDORSEMENT: for objects created under endorsement hierarchy
	 * - TPM2_RH_NULL: for temporary objects
	 *
	 * Transient object - for now just store handle
	 * In a full implementation, would store object's public/private data
	 */
	DBG_TRACE("Transient object save ");
	DBG_TRACE("(minimal implementation)\n");

	tpms_context->contextBlob.size = sizeof(uint32_t);

	memcpy(tpms_context->contextBlob.buffer, &handle, sizeof(uint32_t));

	return tss2_rc;
}

static uint32_t context_save_session(TPMS_CONTEXT *tpms_context,
				     TPMI_DH_CONTEXT handle,
				     tcti_smw_session_t *session)
{
	TSS2_RC tss2_rc = TSS2_RC_SUCCESS;
	smw_session_blob_t blob = { 0 };
	int ret = 0;

	tpms_context->hierarchy = TPM2_RH_NULL;
	DBG_TRACE("Session context - hierarchy set to TPM2_RH_NULL\n");

	if (session) {
		/*
		 * Fullfillment of contextBlob (TPM2B_CONTEXT_DATA)
		 * Here, we store necessary info for SMW (ie: session ID)
		 */

		ret = snprintf((char *)blob.metadata, sizeof(blob.metadata),
			       "SMW_SESSION_ID_%03lu", tpms_context->sequence);
		if (ret < 0 || (size_t)ret >= sizeof(blob.metadata)) {
			DBG_TRACE("Failed to format session metadata\n");
			tss2_rc = TSS2_TCTI_RC_GENERAL_FAILURE;
			goto end;
		}

		blob.handle = handle;
		blob.type = session->type;
		blob.auth_hash = session->auth_hash;
		blob.metadata_size = sizeof(blob.metadata);
		tpms_context->contextBlob.size = sizeof(blob);

		memcpy(tpms_context->contextBlob.buffer, &blob,
		       tpms_context->contextBlob.size);

		if (tpms_context->contextBlob.size > TPM2_MAX_CONTEXT_SIZE) {
			DBG_TRACE("Context blob too large!\n");
			tss2_rc = TSS2_TCTI_RC_INSUFFICIENT_BUFFER;
			goto end;
		}
	} else {
		DBG_TRACE("No session found link to the handle 0x%08x\n",
			  handle);
		tss2_rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

end:
	return tss2_rc;
}

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

uint32_t handle_contextsave(tcti_smw_context_t *ctx, uint16_t tag,
			    const uint8_t *cmd, size_t cmd_size)
{
	TPM2_RC rc = TPM2_RC_SUCCESS;
	TSS2_RC tss2_rc = TSS2_TCTI_RC_GENERAL_FAILURE;
	TPMI_DH_CONTEXT handle_to_save = 0;
	size_t offset = TPM_HEADER_SIZE, context_size = 0,
	       resp_offset = TPM_HEADER_SIZE;
	bool is_transient = false, is_session = false;
	uint32_t total_resp_size = 0;
	TPMS_CONTEXT tpms_context = { 0 };
	tcti_smw_session_t *session = NULL;

	/* 1. Extract handle from command (Parameter 1: handle_to_save) */
	tss2_rc = Tss2_MU_UINT32_Unmarshal(cmd, cmd_size, &offset,
					   &handle_to_save);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	DBG_TRACE("handle_to_save: 0x%08x\n", handle_to_save);

	/*
	 * 2. Validate the handle can be saved according to TPM2 spec
	 * Check handle ranges:
	 * - 0x02000000-0x02FFFFFF: HMAC sessions (includes our SMW_SESSION_HANDLE_BASE)
	 * - 0x03000000-0x03FFFFFF: Policy sessions
	 * - 0x80000000-0x80000002: Transient objects
	 *
	 * Reference: TPM 2.0 Part 2 - Structures, Section 14.6.2 (Context Data)
	 * Table 245 (website link: https://trustedcomputinggroup.org/wp-content/uploads/Trusted-Platform-Module-2.0-Library-Part-2-Version-184_pub.pdf
	 */
	is_session =
		(handle_to_save >= 0x02000000 &&
		 handle_to_save <= 0x02FFFFFF) ||
		(handle_to_save >= 0x03000000 && handle_to_save <= 0x03FFFFFF);
	is_transient =
		(handle_to_save >= 0x80000000 && handle_to_save <= 0x80FFFFFF);

	if (!is_session && !is_transient) {
		DBG_TRACE("Handle 0x%08x cannot be saved\n", handle_to_save);
		tss2_rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	/* Sequence number incremented for each save */
	tpms_context.sequence = ctx->ctx_sequence++;
	tpms_context.savedHandle = handle_to_save;

	/*
	 * 3. Set hierarchy based on handle type
	 * Build the context blob based on handle type
	 */
	if (is_session) {
		/* Try to find this session in our SMW context */
		session = find_session_by_handle(ctx, handle_to_save);

		tss2_rc = context_save_session(&tpms_context, handle_to_save,
					       session);
		if (tss2_rc != TSS2_RC_SUCCESS)
			goto end;
	} else if (is_transient) {
		tss2_rc = context_save_transient(&tpms_context, handle_to_save);
		if (tss2_rc != TSS2_RC_SUCCESS)
			goto end;
	}

	/*
	 * 4. Calculation of response's total size
	 * We use Tss2_MU_TPMS_CONTEXT_Marshal with NULL for calculation of the exact size
	 */
	tss2_rc = Tss2_MU_TPMS_CONTEXT_Marshal(&tpms_context, NULL, 0,
					       &context_size);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	total_resp_size = TPM_HEADER_SIZE + (uint32_t)context_size;

	/* 5. Build of response's header */
	tss2_rc = build_rc_response(ctx, total_resp_size, tag, TPM2_RC_SUCCESS);
	if (tss2_rc != TSS2_RC_SUCCESS)
		return tss2_rc;

	/* 6. Marshaling of complete structure */
	tss2_rc = Tss2_MU_TPMS_CONTEXT_Marshal(&tpms_context, ctx->resp_buf,
					       ctx->resp_size, &resp_offset);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	DBG_TRACE("Context marshaled, total size: %zu\n", resp_offset);
	DBG_TRACE("ContextSave successful: sequence=%llu, ",
		  (unsigned long long)tpms_context.sequence);
	DBG_TRACE("hierarchy=0x%08x, size=%zu\n", tpms_context.hierarchy,
		  resp_offset);

end:
	if (tss2_rc != TSS2_RC_SUCCESS) {
		rc = tcti_rc_to_tpm2_rc(tss2_rc);
		return build_rc_response(ctx, TPM_HEADER_SIZE, tag, rc);
	}

	return tss2_rc;
}

uint32_t handle_flushcontext(tcti_smw_context_t *ctx, uint16_t tag,
			     const uint8_t *cmd, size_t cmd_size)
{
	TPM2_RC rc = TPM2_RC_SUCCESS;
	TSS2_RC tss2_rc = TSS2_TCTI_RC_GENERAL_FAILURE;
	TPMI_DH_CONTEXT flush_handle = 0;
	size_t offset = TPM_HEADER_SIZE;
	bool is_transient = false, is_session = false;
	tcti_smw_session_t *session = NULL;

	/* Extract the handle to flush from command */
	tss2_rc =
		Tss2_MU_UINT32_Unmarshal(cmd, cmd_size, &offset, &flush_handle);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	DBG_TRACE("Flushing handle 0x%08x\n", flush_handle);

	/* Check if it's a session handle */
	is_session = (flush_handle >= TPM2_HMAC_SESSION_FIRST &&
		      flush_handle <= TPM2_HMAC_SESSION_LAST) ||
		     (flush_handle >= TPM2_POLICY_SESSION_FIRST &&
		      flush_handle <= TPM2_POLICY_SESSION_LAST);

	if (is_session) {
		/* Find and free the session */
		session = find_session_by_handle(ctx, flush_handle);

		if (!session || !session->active) {
			/*
			 * Session not found or not active, shall return TPM2_RC_HANDLE
			 * Per TPM 2.0 Part 3, Section 28.4
			 */
			DBG_TRACE("Session 0x%08x not found or not active\n",
				  flush_handle);
			goto end_handle_error;
		}
		DBG_TRACE("Flushing session 0x%08x (type=%d, hash=%d)\n",
			  flush_handle, session->type, session->auth_hash);

		/* Clear the session data */
		memset(session, 0, sizeof(tcti_smw_session_t));

		DBG_TRACE("Session 0x%08x successfully flushed\n",
			  flush_handle);
	} else if (is_transient) {
		/* For transient objects or other handles */
		DBG_TRACE("Flushing non-session handle 0x%08x ", flush_handle);
		DBG_TRACE("(not implemented)\n");
		/* In a full implementation, it should handle transient objects here */
	} else {
		DBG_TRACE("Invalid handle type: 0x%08x\n", flush_handle);
		goto end_handle_error;
	}

	/* Response is just the header with success code */
	tss2_rc = build_rc_response(ctx, TPM_HEADER_SIZE, tag, TPM2_RC_SUCCESS);
	if (tss2_rc != TSS2_RC_SUCCESS)
		return tss2_rc;

end:
	if (tss2_rc != TSS2_RC_SUCCESS) {
		rc = tcti_rc_to_tpm2_rc(tss2_rc);
		return build_rc_response(ctx, TPM_HEADER_SIZE, tag, rc);
	}

	return tss2_rc;

end_handle_error:
	return build_rc_response(ctx, TPM_HEADER_SIZE, tag, TPM2_RC_HANDLE);
}
