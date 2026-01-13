// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <tss2/tss2_mu.h>

#include "common.h"
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
