// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <string.h>

#include <tss2/tss2_mu.h>

#include "utils.h"
#include "commands.h"
#include "trace.h"

static pcr_bank_t *find_pcr_bank(tcti_smw_context_t *ctx,
				 TPMI_ALG_HASH hash_alg)
{
	uint8_t i = 0;

	for (; i < ctx->pcr_bank_count; i++) {
		if (ctx->pcr_banks[i].hash_alg == hash_alg)
			return &ctx->pcr_banks[i];
	}
	return NULL;
}

uint32_t handle_pcrread(tcti_smw_context_t *ctx, uint16_t tag,
			const uint8_t *cmd, size_t cmd_size)
{
	TPM2_RC rc = TPM2_RC_SUCCESS;
	TSS2_RC tss2_rc = TSS2_TCTI_RC_GENERAL_FAILURE;
	size_t offset = TPM_HEADER_SIZE;
	uint16_t digest_size = 0;
	uint8_t i = 0, j = 0;
	uint8_t pcr_idx = 0, byte_idx = 0, bit_idx = 0;
	TPM2B_DIGEST *digest = NULL;
	pcr_bank_t *bank = NULL;
	uint8_t *params_buffer = NULL;
	uint8_t *params_marshal_scratch = NULL;
	size_t marshaled_param_size = 0;

	/* Input parameters */
	TPML_PCR_SELECTION pcr_selection_in = { 0 };
	TPMS_PCR_SELECTION *sel_in = NULL;

	/* Output parameters */
	uint32_t pcr_update_counter = 0;
	TPML_PCR_SELECTION pcr_selection_out = { 0 };
	TPML_DIGEST pcr_values = { 0 };
	TPMS_PCR_SELECTION *sel_out = NULL;

	/* Session handling */
	tcti_smw_session_t *sess = NULL;
	uint32_t session_handle = 0;
	TPM2B_NONCE nonce_caller = { 0 };

	/* 1. Check initialization */
	if (!ctx->initialized) {
		tss2_rc = TSS2_TCTI_RC_BAD_SEQUENCE;
		goto end;
	}

	if (tag == TPM2_ST_SESSIONS) {
		tss2_rc = unmarshal_auth_area(cmd, cmd_size, &offset,
					      &nonce_caller, &session_handle);
		if (tss2_rc != TSS2_RC_SUCCESS)
			goto end;

		if (session_handle != TPM2_RH_PW) {
			sess = find_session_by_handle(ctx, session_handle);
			if (!sess || !sess->active) {
				tss2_rc = TSS2_TCTI_RC_IO_ERROR;
				goto end;
			}
		}
	}

	/* 2. Unmarshal input parameters */
	tss2_rc = Tss2_MU_TPML_PCR_SELECTION_Unmarshal(cmd, cmd_size, &offset,
						       &pcr_selection_in);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	DBG_TRACE("PCR_Read: %u selection(s) requested\n",
		  pcr_selection_in.count);

	/* 3. Process PCR selections and build response */
	pcr_update_counter = ctx->pcr_update_counter;
	pcr_selection_out.count = 0;
	pcr_values.count = 0;

	/* Iterate through requested PCR selections */
	for (i = 0; i < pcr_selection_in.count; i++) {
		sel_in = &pcr_selection_in.pcrSelections[i];

		DBG_TRACE("Selection %u: hash=0x%04x, sizeofSelect=%u\n", i,
			  sel_in->hash, sel_in->sizeofSelect);

		/* Find the PCR bank for this hash algorithm */
		bank = find_pcr_bank(ctx, sel_in->hash);
		if (!bank) {
			DBG_TRACE("PCR bank not found for hash alg: 0x%04x\n",
				  sel_in->hash);
			tss2_rc = TSS2_TCTI_RC_BAD_VALUE;
			goto end;
		}

		/* Add this selection to output */
		if (pcr_selection_out.count < TPM2_NUM_PCR_BANKS) {
			sel_out = &pcr_selection_out.pcrSelections
					   [pcr_selection_out.count++];
			sel_out->hash = sel_in->hash;
			sel_out->sizeofSelect = sel_in->sizeofSelect;

			/* Copy PCR bitmap */
			for (j = 0;
			     j < MIN(sel_in->sizeofSelect, TPM2_PCR_SELECT_MAX);
			     j++) {
				sel_out->pcrSelect[j] = sel_in->pcrSelect[j];
			}
		}

		/* Read PCR values for selected PCRs */
		for (pcr_idx = 0; pcr_idx < TPM2_MAX_PCRS; pcr_idx++) {
			byte_idx = pcr_idx / 8;
			bit_idx = pcr_idx % 8;

			/* Check if this PCR is selected */
			if (byte_idx >= sel_in->sizeofSelect)
				continue;

			if (!(sel_in->pcrSelect[byte_idx] & (1 << bit_idx)))
				continue;

			if (pcr_values.count >=
			    TPM2_NUM_PCR_BANKS * TPM2_MAX_PCRS)
				goto pcr_read_done;

			digest = &pcr_values.digests[pcr_values.count++];
			digest_size = bank->digest_size;
			digest->size = digest_size;

			if (digest_size > 0)
				memcpy(digest->buffer, bank->pcr[pcr_idx],
				       digest_size);

			DBG_TRACE("PCR[%u]: digest_size=%u\n", pcr_idx,
				  digest_size);
		}
	}

pcr_read_done:
	/* 4. Calculate params_size for all output parameters */
	params_marshal_scratch = calloc(1, TPM2_MAX_CAP_BUFFER);
	if (!params_marshal_scratch) {
		tss2_rc = TSS2_TCTI_RC_MEMORY;
		goto end;
	}

	tss2_rc = Tss2_MU_UINT32_Marshal(pcr_update_counter,
					 params_marshal_scratch,
					 TPM2_MAX_CAP_BUFFER,
					 &marshaled_param_size);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	tss2_rc = Tss2_MU_TPML_PCR_SELECTION_Marshal(&pcr_selection_out,
						     params_marshal_scratch,
						     TPM2_MAX_CAP_BUFFER,
						     &marshaled_param_size);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	tss2_rc =
		Tss2_MU_TPML_DIGEST_Marshal(&pcr_values, params_marshal_scratch,
					    TPM2_MAX_CAP_BUFFER,
					    &marshaled_param_size);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	params_buffer = malloc(marshaled_param_size);
	if (!params_buffer) {
		tss2_rc = TSS2_TCTI_RC_MEMORY;
		goto end;
	}

	if (marshaled_param_size > 0 && params_marshal_scratch)
		memcpy(params_buffer, params_marshal_scratch,
		       marshaled_param_size);

	/* 9. Build response */
	if (tag == TPM2_ST_SESSIONS) {
		/* Use build_auth_response for session response */
		tss2_rc =
			build_auth_response(ctx, sess, TPM2_RC_SUCCESS,
					    TPM2_CC_PCR_Read, tag,
					    params_buffer, marshaled_param_size,
					    &nonce_caller, NULL);
	} else {
		/* Build simple response without auth */
		tss2_rc = build_auth_response(ctx, NULL, TPM2_RC_SUCCESS,
					      TPM2_CC_PCR_Read, tag,
					      params_buffer,
					      marshaled_param_size, NULL, NULL);
	}

	DBG_TRACE("PCR_Read successful\n");

end:
	/* Free allocated memory */
	if (params_buffer)
		free(params_buffer);

	if (params_marshal_scratch)
		free(params_marshal_scratch);

	if (tss2_rc != TSS2_RC_SUCCESS) {
		rc = tcti_rc_to_tpm2_rc(tss2_rc);
		tss2_rc = build_rc_response(ctx, TPM_HEADER_SIZE, tag, rc);
	}

	return tss2_rc;
}
