// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include "smw_crypto.h"
#include "utils.h"
#include "crypto.h"
#include "commands.h"
#include "trace.h"

uint32_t handle_hash(tcti_smw_context_t *ctx, uint16_t tag, const uint8_t *cmd,
		     size_t cmd_size)
{
	TPM2_RC rc = TPM2_RC_SUCCESS;
	TSS2_RC tss2_rc = TSS2_TCTI_RC_GENERAL_FAILURE;
	size_t offset = TPM_HEADER_SIZE;
	struct smw_hash_args hash_args = { 0 };
	enum smw_status_code smw_status = SMW_STATUS_OK;

	/* Input parameters */
	TPM2B_MAX_BUFFER data = { 0 };
	TPMI_ALG_HASH hash_alg = TPM2_ALG_NULL;
	TPMI_RH_HIERARCHY hierarchy;

	/* Output parameters */
	TPM2B_DIGEST out_hash = { 0 };
	TPMT_TK_HASHCHECK validation = {
		.tag = TPM2_ST_HASHCHECK,
		.hierarchy = TPM2_RH_OWNER,
		.digest = { .size = 0 } /* No HMAC proof (ticket NULL) */
	};
	size_t resp_offset = TPM_HEADER_SIZE, ticket_size = 0,
	       resp_params_size = 0;
	uint32_t total_size = 0;

	/* 1. Unmarshal input parameters */
	tss2_rc = Tss2_MU_TPM2B_MAX_BUFFER_Unmarshal(cmd, cmd_size, &offset,
						     &data);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	tss2_rc = Tss2_MU_UINT16_Unmarshal(cmd, cmd_size, &offset, &hash_alg);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	tss2_rc = Tss2_MU_UINT32_Unmarshal(cmd, cmd_size, &offset, &hierarchy);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	/* 2. Configure algorithm */
	tss2_rc = map_hash_info(hash_alg, &out_hash.size, &hash_args.algo_name);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	/* 3. Prepare SMW args */
	hash_args.input = data.buffer;
	hash_args.input_length = data.size;
	hash_args.output = out_hash.buffer;
	hash_args.output_length = out_hash.size;

	/* 4. Call SMW API */
	smw_status = smw_hash(&hash_args);

	if (smw_status != SMW_STATUS_OK) {
		DBG_TRACE("SMW Hash failed with status: %d\n", smw_status);
		tss2_rc = smw_rc_to_tcti_rc(smw_status);
		goto end;
	}

	DBG_TRACE("%s: Hashing %u bytes with alg 0x%04x\n", __func__, data.size,
		  hash_alg);

	/*
	 * 5. Compute response size
	 * Header(10) + outHash(2 + N) + validation(2 + 4 + 2 + 0)
	 */
	tss2_rc = Tss2_MU_TPM2B_DIGEST_Marshal(&out_hash, NULL, 0,
					       &resp_params_size);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	tss2_rc = Tss2_MU_TPMT_TK_HASHCHECK_Marshal(&validation, NULL, 0,
						    &ticket_size);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	total_size = TPM_HEADER_SIZE + resp_params_size + ticket_size;

	/* 6. Building response */
	tss2_rc = build_rc_response(ctx, total_size, tag, TPM2_RC_SUCCESS);
	if (tss2_rc != TSS2_RC_SUCCESS)
		return tss2_rc;

	tss2_rc = Tss2_MU_TPM2B_DIGEST_Marshal(&out_hash, ctx->resp_buf,
					       ctx->resp_size, &resp_offset);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	tss2_rc =
		Tss2_MU_TPMT_TK_HASHCHECK_Marshal(&validation, ctx->resp_buf,
						  ctx->resp_size, &resp_offset);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

end:
	if (tss2_rc != TSS2_RC_SUCCESS) {
		rc = tcti_rc_to_tpm2_rc(tss2_rc);
		return build_rc_response(ctx, TPM_HEADER_SIZE, tag, rc);
	}

	return tss2_rc;
}
