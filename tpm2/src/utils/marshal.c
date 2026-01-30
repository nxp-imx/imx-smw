// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <tss2/tss2_mu.h>

#include "common.h"
#include "session.h"
#include "crypto.h"
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

uint32_t create_primary_unmarshal(const uint8_t *cmd, size_t cmd_size,
				  createprimary_input_t *input,
				  TPM2B_NONCE *nonce_caller,
				  uint32_t *session_handle)
{
	TSS2_RC rc = TSS2_TCTI_RC_GENERAL_FAILURE;
	size_t offset = TPM_HEADER_SIZE;
	size_t auth_start = 0;
	uint32_t auth_size = 0;

	/* Unmarshal primary handle */
	rc = Tss2_MU_UINT32_Unmarshal(cmd, cmd_size, &offset,
				      &input->primary_handle);
	if (rc != TSS2_RC_SUCCESS)
		goto end;

	DBG_TRACE("Hierarchy=0x%08x\n", input->primary_handle);

	/* Unmarshal authorization area */
	rc = Tss2_MU_UINT32_Unmarshal(cmd, cmd_size, &offset, &auth_size);
	if (rc != TSS2_RC_SUCCESS)
		goto end;

	auth_start = offset;

	if (auth_size == 0) {
		DBG_TRACE("Requires authorization area\n");
		rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	/* Parse session handle */
	rc = Tss2_MU_UINT32_Unmarshal(cmd, cmd_size, &offset, session_handle);
	if (rc != TSS2_RC_SUCCESS)
		goto end;

	/* Parse nonce */
	rc = Tss2_MU_TPM2B_NONCE_Unmarshal(cmd, cmd_size, &offset,
					   nonce_caller);
	if (rc != TSS2_RC_SUCCESS)
		goto end;

	/* Skip to end of auth area */
	offset = auth_start + auth_size;

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
