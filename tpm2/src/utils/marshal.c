// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <tss2/tss2_mu.h>

#include "common.h"
#include "session.h"
#include "crypto.h"
#include "utils.h"
#include "trace.h"

uint32_t header_unmarshal(const uint8_t *buf, tpm_smw_header_t *header)
{
	TSS2_RC rc = TSS2_TCTI_RC_GENERAL_FAILURE;
	size_t offset = 0;

	DBG_TRACE("Parsing header from buffer: 0x%p", buf);
	rc = Tss2_MU_TPM2_ST_Unmarshal(buf, TPM_HEADER_SIZE, &offset,
				       &header->tag);
	if (rc != TSS2_RC_SUCCESS) {
		DBG_TRACE("Failed to unmarshal tag.");
		goto end;
	}

	rc = Tss2_MU_UINT32_Unmarshal(buf, TPM_HEADER_SIZE, &offset,
				      &header->size);
	if (rc != TSS2_RC_SUCCESS) {
		DBG_TRACE("Failed to unmarshal command size.");
		goto end;
	}

	rc = Tss2_MU_UINT32_Unmarshal(buf, TPM_HEADER_SIZE, &offset,
				      &header->code);
	if (rc != TSS2_RC_SUCCESS) {
		DBG_TRACE("Failed to unmarshal command code.");
		goto end;
	}

end:
	DBG_TRACE_COND(rc != TSS2_RC_SUCCESS, "return error: 0x%08x\n", rc);
	return rc;
}

uint32_t header_marshal(const tpm_smw_header_t *header, uint8_t *buf)
{
	TSS2_RC rc = TSS2_TCTI_RC_GENERAL_FAILURE;
	size_t offset = 0;

	DBG_TRACE("Parsing header from buffer: 0x%p", buf);
	rc = Tss2_MU_TPM2_ST_Marshal(header->tag, buf, TPM_HEADER_SIZE,
				     &offset);
	if (rc != TSS2_RC_SUCCESS) {
		DBG_TRACE("Failed to marshal tag.");
		goto end;
	}

	rc = Tss2_MU_UINT32_Marshal(header->size, buf, TPM_HEADER_SIZE,
				    &offset);
	if (rc != TSS2_RC_SUCCESS) {
		DBG_TRACE("Failed to marshal command size.");
		goto end;
	}

	rc = Tss2_MU_UINT32_Marshal(header->code, buf, TPM_HEADER_SIZE,
				    &offset);
	if (rc != TSS2_RC_SUCCESS) {
		DBG_TRACE("Failed to marshal command code.");
		goto end;
	}

end:
	DBG_TRACE_COND(rc != TSS2_RC_SUCCESS, "return error: 0x%08x\n", rc);
	return rc;
}

uint32_t param_su_unmarshal(const uint8_t *buf, size_t buf_size,
			    TPM2_SU *su_type)
{
	TSS2_RC rc = TSS2_TCTI_RC_BAD_VALUE;
	size_t offset = TPM_HEADER_SIZE;

	if (!buf || !su_type)
		goto end;

	if (buf_size < TPM_HEADER_SIZE + sizeof(uint16_t)) {
		DBG_TRACE("Command too short");
		goto end;
	}

	DBG_TRACE("Parsing Type from buffer: 0x%p", buf);

	rc = Tss2_MU_UINT16_Unmarshal(buf, buf_size, &offset,
				      (TPM2_SU *)su_type);
	if (rc != TSS2_RC_SUCCESS) {
		DBG_TRACE("Failed to unmarshal Type");
		goto end;
	}

end:
	DBG_TRACE_COND(rc != TSS2_RC_SUCCESS, "return error: 0x%08x\n", rc);
	return rc;
}

uint32_t start_auth_session_unmarshal(const uint8_t *cmd, size_t cmd_size,
				      start_auth_session_params_t *params)
{
	TSS2_RC rc = TSS2_TCTI_RC_GENERAL_FAILURE;
	size_t offset = TPM_HEADER_SIZE;

	/* 1. tpmKey (4 octets) */
	rc = Tss2_MU_UINT32_Unmarshal(cmd, cmd_size, &offset, &params->tpmKey);
	if (rc != TSS2_RC_SUCCESS)
		goto end;

	/* 2. bind (4 octets) */
	rc = Tss2_MU_UINT32_Unmarshal(cmd, cmd_size, &offset, &params->bind);
	if (rc != TSS2_RC_SUCCESS)
		goto end;

	/* 3. nonceCaller (TPM2B_NONCE) */
	rc = Tss2_MU_TPM2B_NONCE_Unmarshal(cmd, cmd_size, &offset,
					   &params->nonceCaller);
	if (rc != TSS2_RC_SUCCESS)
		goto end;

	/* 4. encryptedSalt (TPM2B_ENCRYPTED_SECRET) */
	rc = Tss2_MU_TPM2B_ENCRYPTED_SECRET_Unmarshal(cmd, cmd_size, &offset,
						      &params->encryptedSalt);
	if (rc != TSS2_RC_SUCCESS)
		goto end;

	/* 5. sessionType (1 octet) */
	rc = Tss2_MU_UINT8_Unmarshal(cmd, cmd_size, &offset,
				     &params->session_type);
	if (rc != TSS2_RC_SUCCESS)
		goto end;

	/* 6. symmetric (TPMT_SYM_DEF) */
	rc = Tss2_MU_TPMT_SYM_DEF_Unmarshal(cmd, cmd_size, &offset,
					    &params->symmetric);
	if (rc != TSS2_RC_SUCCESS)
		goto end;

	/* 7. authHash (2 octets) */
	rc = Tss2_MU_UINT16_Unmarshal(cmd, cmd_size, &offset,
				      &params->auth_hash);
	if (rc != TSS2_RC_SUCCESS)
		goto end;

	DBG_TRACE("StartAuthSession parameters:\n");
	DBG_TRACE("  tpmKey: 0x%08X\n", params->tpmKey);
	DBG_TRACE("  bind: 0x%08X\n", params->bind);
	DBG_TRACE("  nonceCaller size: %d\n", params->nonceCaller.size);
	DBG_TRACE("  encryptedSalt size: %d\n", params->encryptedSalt.size);
	DBG_TRACE("  sessionType: 0x%02X\n", params->session_type);
	DBG_TRACE("  symmetric.algorithm: 0x%04X\n",
		  params->symmetric.algorithm);
	DBG_TRACE("  authHash: 0x%04X\n", params->auth_hash);

end:
	DBG_TRACE_COND(rc != TSS2_RC_SUCCESS, "return error: 0x%08x\n", rc);
	return rc;
}

uint32_t unmarshal_auth_area_multi(const uint8_t *cmd, size_t cmd_size,
				   size_t *offset,
				   auth_session_info_t *auth_sessions,
				   size_t *nb_sessions)
{
	TSS2_RC rc = TSS2_TCTI_RC_GENERAL_FAILURE;

	size_t auth_start = 0;
	size_t auth_end = 0;
	size_t session_count = 0;
	uint32_t auth_size = 0;

	if (!cmd || !offset || !auth_sessions) {
		rc = TSS2_TCTI_RC_BAD_REFERENCE;
		goto end;
	}

	/* Unmarshal authorization area size */
	rc = Tss2_MU_UINT32_Unmarshal(cmd, cmd_size, offset, &auth_size);
	if (rc != TSS2_RC_SUCCESS)
		goto end;

	auth_start = *offset;

	if (auth_size == 0) {
		DBG_TRACE("Requires authorization area\n");
		rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	/*
	 * Ensure the authorization area fits in the remaining command buffer
	 * Use overflow-safe checks instead of computing *offset + auth_size directly
	 */
	if (*offset > cmd_size || auth_size > cmd_size - *offset) {
		DBG_TRACE("Authorization area exceeds\n"
			  "remaining command buffer\n");
		rc = TSS2_TCTI_RC_INSUFFICIENT_BUFFER;
		goto end;
	}

	if (ADD_OVERFLOW(auth_start, (size_t)auth_size, &auth_end) ||
	    auth_end > cmd_size) {
		DBG_TRACE("Invalid authorization area size\n");
		rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	/* Parse each auth session until we reach the end of auth area */
	while (*offset < auth_end && session_count < MAX_AUTH_SESSIONS) {
		auth_session_info_t *auth = &auth_sessions[session_count];

		/* Parse session handle */
		rc = Tss2_MU_UINT32_Unmarshal(cmd, cmd_size, offset,
					      &auth->session_handle);
		if (rc != TSS2_RC_SUCCESS)
			goto end;

		/* Parse nonce */
		rc = Tss2_MU_TPM2B_NONCE_Unmarshal(cmd, cmd_size, offset,
						   &auth->nonce_caller);
		if (rc != TSS2_RC_SUCCESS)
			goto end;

		/* Parse session attributes */
		rc = Tss2_MU_UINT8_Unmarshal(cmd, cmd_size, offset,
					     &auth->session_attributes);
		if (rc != TSS2_RC_SUCCESS)
			goto end;

		/* Parse HMAC */
		rc = Tss2_MU_TPM2B_AUTH_Unmarshal(cmd, cmd_size, offset,
						  &auth->hmac);
		if (rc != TSS2_RC_SUCCESS)
			goto end;

		session_count++;

		DBG_TRACE("Auth session %zu:\n"
			  "  handle: 0x%08x\n"
			  "  nonce size: %u\n"
			  "  attributes: 0x%02x\n"
			  "  hmac size: %u\n",
			  session_count, auth->session_handle,
			  auth->nonce_caller.size, auth->session_attributes,
			  auth->hmac.size);
	}

	/* Verify we consumed exactly the auth area */
	if (*offset != auth_end) {
		DBG_TRACE("Auth area size mismatch: parsed %zu, expected %zu\n",
			  *offset - auth_start, (size_t)auth_size);
		rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	*nb_sessions = session_count;

	DBG_TRACE("Unmarshaled %zu auth session(s)\n", session_count);

end:
	DBG_TRACE_COND(rc != TSS2_RC_SUCCESS, "return error: 0x%08x\n", rc);
	return rc;
}

uint32_t unmarshal_auth_area(const uint8_t *cmd, size_t cmd_size,
			     size_t *offset, TPM2B_NONCE *nonce_caller,
			     uint32_t *session_handle)
{
	TSS2_RC rc = TSS2_TCTI_RC_GENERAL_FAILURE;
	TPM2B_AUTH hmac = { 0 };
	size_t nb_sessions = 0;

	if (!nonce_caller || !session_handle) {
		rc = TSS2_TCTI_RC_BAD_REFERENCE;
		goto end;
	}

	auth_session_info_t auth_sessions[1] = { { .session_handle =
							   *session_handle,
						   .nonce_caller = { 0 },
						   .session_attributes = 0,
						   .hmac = hmac,
						   .session = NULL } };

	/* Use the multi-session version */
	rc = unmarshal_auth_area_multi(cmd, cmd_size, offset, auth_sessions,
				       &nb_sessions);
	if (rc != TSS2_RC_SUCCESS)
		goto end;

	if (nb_sessions != 1) {
		DBG_TRACE("Expected 1 auth session, got %zu\n", nb_sessions);
		rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	/* Copy results */
	*session_handle = auth_sessions[0].session_handle;
	*nonce_caller = auth_sessions[0].nonce_caller;

end:
	DBG_TRACE_COND(rc != TSS2_RC_SUCCESS, "return error: 0x%08x\n", rc);
	return rc;
}

uint32_t create_primary_unmarshal(const uint8_t *cmd, size_t cmd_size,
				  createprimary_input_t *input,
				  TPM2B_NONCE *nonce_caller,
				  uint32_t *session_handle)
{
	TSS2_RC rc = TSS2_TCTI_RC_GENERAL_FAILURE;
	size_t offset = TPM_HEADER_SIZE;

	/* Unmarshal primary handle */
	rc = Tss2_MU_UINT32_Unmarshal(cmd, cmd_size, &offset,
				      &input->primary_handle);
	if (rc != TSS2_RC_SUCCESS)
		goto end;

	DBG_TRACE("Hierarchy=0x%08x\n", input->primary_handle);

	/* Unmarshal authorization area */
	rc = unmarshal_auth_area(cmd, cmd_size, &offset, nonce_caller,
				 session_handle);
	if (rc != TSS2_RC_SUCCESS)
		goto end;

	/* Unmarshal remaining parameters */
	rc = Tss2_MU_TPM2B_SENSITIVE_CREATE_Unmarshal(cmd, cmd_size, &offset,
						      &input->in_sensitive);
	if (rc != TSS2_RC_SUCCESS)
		goto end;

	rc = Tss2_MU_TPM2B_PUBLIC_Unmarshal(cmd, cmd_size, &offset,
					    &input->in_public);
	if (rc != TSS2_RC_SUCCESS)
		goto end;

	rc = Tss2_MU_TPM2B_DATA_Unmarshal(cmd, cmd_size, &offset,
					  &input->outside_info);
	if (rc != TSS2_RC_SUCCESS)
		goto end;

	rc = Tss2_MU_TPML_PCR_SELECTION_Unmarshal(cmd, cmd_size, &offset,
						  &input->creation_pcr);
	if (rc != TSS2_RC_SUCCESS)
		goto end;

end:
	DBG_TRACE_COND(rc != TSS2_RC_SUCCESS, "return error: 0x%08x\n", rc);
	return rc;
}

uint32_t create_unmarshal(const uint8_t *cmd, size_t cmd_size,
			  create_input_t *input, TPM2B_NONCE *nonce_caller,
			  uint32_t *session_handle)
{
	return create_primary_unmarshal(cmd, cmd_size, input, nonce_caller,
					session_handle);
}

uint32_t load_unmarshal(const uint8_t *cmd, size_t cmd_size,
			load_input_t *input, TPM2B_NONCE *nonce_caller,
			uint32_t *session_handle)
{
	TSS2_RC rc = TSS2_TCTI_RC_GENERAL_FAILURE;
	size_t offset = TPM_HEADER_SIZE;

	/* Unmarshal parent handle */
	rc = Tss2_MU_UINT32_Unmarshal(cmd, cmd_size, &offset,
				      &input->parent_handle);
	if (rc != TSS2_RC_SUCCESS)
		goto end;

	DBG_TRACE("Parent handle=0x%08x\n", input->parent_handle);

	/* Unmarshal authorization area */
	rc = unmarshal_auth_area(cmd, cmd_size, &offset, nonce_caller,
				 session_handle);
	if (rc != TSS2_RC_SUCCESS)
		goto end;

	/* Unmarshal remaining parameters */
	rc = Tss2_MU_TPM2B_PRIVATE_Unmarshal(cmd, cmd_size, &offset,
					     &input->in_private);
	if (rc != TSS2_RC_SUCCESS)
		goto end;

	rc = Tss2_MU_TPM2B_PUBLIC_Unmarshal(cmd, cmd_size, &offset,
					    &input->in_public);
	if (rc != TSS2_RC_SUCCESS)
		goto end;

end:
	DBG_TRACE_COND(rc != TSS2_RC_SUCCESS, "return error: 0x%08x\n", rc);
	return rc;
}

uint32_t sign_unmarshal(const uint8_t *cmd, size_t cmd_size,
			sign_input_t *input, TPM2B_NONCE *nonce_caller,
			uint32_t *session_handle)
{
	TSS2_RC rc = TSS2_TCTI_RC_GENERAL_FAILURE;
	size_t offset = TPM_HEADER_SIZE;

	/* Unmarshal key handle */
	rc = Tss2_MU_UINT32_Unmarshal(cmd, cmd_size, &offset,
				      &input->key_handle);
	if (rc != TSS2_RC_SUCCESS)
		goto end;

	DBG_TRACE("Key handle=0x%08x\n", input->key_handle);

	/* Unmarshal authorization area */
	rc = unmarshal_auth_area(cmd, cmd_size, &offset, nonce_caller,
				 session_handle);
	if (rc != TSS2_RC_SUCCESS)
		goto end;

	/* Unmarshal digest */
	rc = Tss2_MU_TPM2B_DIGEST_Unmarshal(cmd, cmd_size, &offset,
					    &input->digest);
	if (rc != TSS2_RC_SUCCESS)
		goto end;

	/* Unmarshal signing scheme */
	rc = Tss2_MU_TPMT_SIG_SCHEME_Unmarshal(cmd, cmd_size, &offset,
					       &input->in_scheme);
	if (rc != TSS2_RC_SUCCESS)
		goto end;

	/* Unmarshal validation ticket */
	rc = Tss2_MU_TPMT_TK_HASHCHECK_Unmarshal(cmd, cmd_size, &offset,
						 &input->validation);
	if (rc != TSS2_RC_SUCCESS)
		goto end;

end:
	DBG_TRACE_COND(rc != TSS2_RC_SUCCESS, "return error: 0x%08x\n", rc);
	return rc;
}

uint32_t verifysignature_unmarshal(const uint8_t *cmd, size_t cmd_size,
				   verifysignature_input_t *input)
{
	TSS2_RC rc = TSS2_TCTI_RC_GENERAL_FAILURE;
	size_t offset = TPM_HEADER_SIZE;

	/* Unmarshal key handle */
	rc = Tss2_MU_UINT32_Unmarshal(cmd, cmd_size, &offset,
				      &input->key_handle);
	if (rc != TSS2_RC_SUCCESS)
		goto end;

	DBG_TRACE("Key handle=0x%08x\n", input->key_handle);

	/* Unmarshal digest */
	rc = Tss2_MU_TPM2B_DIGEST_Unmarshal(cmd, cmd_size, &offset,
					    &input->digest);
	if (rc != TSS2_RC_SUCCESS)
		goto end;

	/* Unmarshal signature */
	rc = Tss2_MU_TPMT_SIGNATURE_Unmarshal(cmd, cmd_size, &offset,
					      &input->signature);
	if (rc != TSS2_RC_SUCCESS)
		goto end;

end:
	DBG_TRACE_COND(rc != TSS2_RC_SUCCESS, "return error: 0x%08x\n", rc);
	return rc;
}
