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

static TSS2_RC pcr_extend_single(tcti_smw_context_t *ctx, uint8_t pcr_index,
				 TPMI_ALG_HASH hash_alg, const uint8_t *digest,
				 uint16_t digest_size)
{
	TSS2_RC rc = TSS2_RC_SUCCESS;
	enum smw_status_code smw_status = SMW_STATUS_OK;

	pcr_bank_t *bank = NULL;
	uint8_t concat_buffer[TPM2_SHA512_DIGEST_SIZE * 2];
	TPM2B_DIGEST new_pcr = { 0 };
	struct smw_hash_args hash_args = { 0 };

	if (!digest) {
		rc = TSS2_TCTI_RC_BAD_REFERENCE;
		goto end;
	}

	/* Check PCR index */
	if (pcr_index >= TPM2_MAX_PCRS) {
		DBG_TRACE("Invalid PCR index: %d\n", pcr_index);
		rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	/* Find bank */
	bank = find_pcr_bank(ctx, hash_alg);
	if (!bank) {
		DBG_TRACE("PCR bank not found for hash alg: 0x%04x\n",
			  hash_alg);
		rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	/* Check digest size */
	if (digest_size != bank->digest_size) {
		DBG_TRACE("Digest size mismatch: got %d, expected %d\n",
			  digest_size, bank->digest_size);
		rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	/* Concatenate PCR_old || digest */
	if (bank->digest_size > 0)
		memcpy(concat_buffer, bank->pcr[pcr_index], bank->digest_size);

	if (digest_size > 0 && digest)
		memcpy(concat_buffer + bank->digest_size, digest, digest_size);

	/* Compute the new PCR : Hash(PCR_old || digest) */
	rc = map_hash_info(hash_alg, &new_pcr.size, &hash_args.algo_name, NULL);
	if (rc != TSS2_RC_SUCCESS)
		goto end;

	hash_args.input = concat_buffer;
	hash_args.input_length = bank->digest_size + digest_size;
	hash_args.output = new_pcr.buffer;
	hash_args.output_length = new_pcr.size;

	smw_status = smw_hash(&hash_args);
	if (smw_status != SMW_STATUS_OK) {
		DBG_TRACE("SMW Hash failed with status: %d\n", smw_status);
		rc = smw_rc_to_tcti_rc(smw_status);
		goto end;
	}

	/* Update PCR */
	if (bank->digest_size > 0)
		memcpy(bank->pcr[pcr_index], new_pcr.buffer, bank->digest_size);

	DBG_TRACE("PCR[%d] extended with hash alg 0x%04x\n", pcr_index,
		  hash_alg);

end:
	DBG_TRACE_COND(rc != TSS2_RC_SUCCESS, "return error: 0x%08x\n", rc);
	return rc;
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

uint32_t handle_pcrextend(tcti_smw_context_t *ctx, uint16_t tag,
			  const uint8_t *cmd, size_t cmd_size)
{
	TSS2_RC tss2_rc = TSS2_TCTI_RC_GENERAL_FAILURE;
	TPM2_RC rc = TPM2_RC_SUCCESS;
	size_t offset = TPM_HEADER_SIZE;
	uint8_t i = 0;
	uint16_t digest_size = 0;
	TPMT_HA *digest = NULL;

	/* Input parameters */
	TPMI_DH_PCR pcr_handle = 0;
	TPML_DIGEST_VALUES digests = { 0 };
	uint8_t pcr_index = 0;

	/* Session handling */
	tcti_smw_session_t *sess = NULL;
	uint32_t session_handle = 0;
	TPM2B_NONCE nonce_caller = { 0 };

	/* 1. Check initialization */
	if (!ctx->initialized) {
		tss2_rc = TSS2_TCTI_RC_BAD_SEQUENCE;
		goto end;
	}

	/* 2. Unmarshal PCR handle */
	tss2_rc = Tss2_MU_UINT32_Unmarshal(cmd, cmd_size, &offset, &pcr_handle);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	/* 3. Unmarshal authorization area */
	tss2_rc = unmarshal_auth_area(cmd, cmd_size, &offset, &nonce_caller,
				      &session_handle);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	/* 4. Unmarshal digests */
	tss2_rc = Tss2_MU_TPML_DIGEST_VALUES_Unmarshal(cmd, cmd_size, &offset,
						       &digests);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	if (session_handle != TPM2_RH_PW) {
		sess = find_session_by_handle(ctx, session_handle);
		if (!sess || !sess->active) {
			tss2_rc = TSS2_TCTI_RC_IO_ERROR;
			goto end;
		}
	}

	/* 5. Validate PCR handle */
	if ((pcr_handle >> TPM2_HR_SHIFT) != TPM2_HT_PCR) {
		DBG_TRACE("Invalid PCR handle type: 0x%08x\n", pcr_handle);
		tss2_rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	pcr_index = pcr_handle & 0xFF;
	if (pcr_index >= TPM2_MAX_PCRS) {
		DBG_TRACE("PCR index out of range: %d\n", pcr_index);
		tss2_rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	DBG_TRACE("PCR_Extend: PCR[%d], %d digest(s)\n", pcr_index,
		  digests.count);

	/* 6. Extend PCR for each digest */
	for (i = 0; i < digests.count; i++) {
		digest = &digests.digests[i];
		digest_size = 0;

		/* Get digest size for this algorithm */
		tss2_rc = map_hash_info(digest->hashAlg, &digest_size, NULL,
					NULL);
		if (tss2_rc != TSS2_RC_SUCCESS) {
			DBG_TRACE("Unknown hash algorithm: 0x%04x\n",
				  digest->hashAlg);
			goto end;
		}

		/* Extend the PCR */
		tss2_rc = pcr_extend_single(ctx, pcr_index, digest->hashAlg,
					    digest->digest.sha512, digest_size);
		if (tss2_rc != TSS2_RC_SUCCESS)
			goto end;
	}

	/* 7. Update counter */
	ctx->pcr_update_counter++;

	/* 8. Build response */
	tss2_rc = build_auth_response(ctx, sess, TPM2_RC_SUCCESS,
				      TPM2_CC_PCR_Extend, tag, NULL, 0,
				      &nonce_caller, NULL);

	DBG_TRACE("PCR_Extend successful\n");

end:
	if (tss2_rc != TSS2_RC_SUCCESS) {
		rc = tcti_rc_to_tpm2_rc(tss2_rc);
		tss2_rc = build_rc_response(ctx, TPM_HEADER_SIZE, tag, rc);
	}

	return tss2_rc;
}

uint32_t handle_pcrevent(tcti_smw_context_t *ctx, uint16_t tag,
			 const uint8_t *cmd, size_t cmd_size)
{
	TSS2_RC tss2_rc = TSS2_TCTI_RC_GENERAL_FAILURE;
	TPM2_RC rc = TPM2_RC_SUCCESS;
	enum smw_status_code smw_status = SMW_STATUS_OK;

	size_t offset = TPM_HEADER_SIZE;
	uint8_t i = 0;
	pcr_bank_t *bank = NULL;
	TPM2B_DIGEST hash_result = { 0 };
	struct smw_hash_args hash_args = { 0 };
	uint8_t *params_buffer = NULL;
	uint8_t *params_marshal_scratch = NULL;
	size_t marshaled_param_size = 0;

	/* Input parameters */
	TPMI_DH_PCR pcr_handle = 0;
	TPM2B_EVENT event_data = { 0 };
	uint8_t pcr_index = 0;

	/* Output parameters */
	TPML_DIGEST_VALUES digests = { 0 };

	/* Session handling */
	tcti_smw_session_t *sess = NULL;
	uint32_t session_handle = 0;
	TPM2B_NONCE nonce_caller = { 0 };

	/* 1. Check initialization */
	if (!ctx->initialized) {
		tss2_rc = TSS2_TCTI_RC_BAD_SEQUENCE;
		goto end;
	}

	/* 2. Unmarshal PCR handle */
	tss2_rc = Tss2_MU_UINT32_Unmarshal(cmd, cmd_size, &offset, &pcr_handle);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	/* 3. Unmarshal authorization area */
	tss2_rc = unmarshal_auth_area(cmd, cmd_size, &offset, &nonce_caller,
				      &session_handle);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	/* 4. Unmarshal event data */
	tss2_rc = Tss2_MU_TPM2B_EVENT_Unmarshal(cmd, cmd_size, &offset,
						&event_data);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	if (session_handle != TPM2_RH_PW) {
		sess = find_session_by_handle(ctx, session_handle);
		if (!sess || !sess->active) {
			tss2_rc = TSS2_TCTI_RC_IO_ERROR;
			goto end;
		}
	}

	/* 5. Validate PCR handle */
	if ((pcr_handle >> TPM2_HR_SHIFT) != TPM2_HT_PCR) {
		DBG_TRACE("Invalid PCR handle type: 0x%08x\n", pcr_handle);
		tss2_rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	pcr_index = pcr_handle & 0xFF;
	if (pcr_index >= TPM2_MAX_PCRS) {
		DBG_TRACE("PCR index out of range: %d\n", pcr_index);
		tss2_rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	DBG_TRACE("PCR_Event: PCR[%d], event_size=%d\n", pcr_index,
		  event_data.size);

	/* 6. Hash event data and extend PCR for each bank */
	digests.count = ctx->pcr_bank_count;

	for (i = 0; i < ctx->pcr_bank_count; i++) {
		bank = &ctx->pcr_banks[i];

		/* Hash the event data */
		tss2_rc = map_hash_info(bank->hash_alg, &hash_result.size,
					&hash_args.algo_name, NULL);
		if (tss2_rc != TSS2_RC_SUCCESS)
			goto end;
		hash_args.input = event_data.buffer;
		hash_args.input_length = event_data.size;
		hash_args.output = hash_result.buffer;
		hash_args.output_length = hash_result.size;

		smw_status = smw_hash(&hash_args);
		if (smw_status != SMW_STATUS_OK) {
			DBG_TRACE("SMW Hash failed with status: %d\n",
				  smw_status);
			tss2_rc = smw_rc_to_tcti_rc(smw_status);
			goto end;
		}

		/* Store the digest in response */
		digests.digests[i].hashAlg = bank->hash_alg;
		if (bank->digest_size > 0)
			memcpy(digests.digests[i].digest.sha512,
			       hash_result.buffer, bank->digest_size);

		/* Extend the PCR */
		tss2_rc = pcr_extend_single(ctx, pcr_index, bank->hash_alg,
					    hash_result.buffer,
					    bank->digest_size);
		if (tss2_rc != TSS2_RC_SUCCESS)
			goto end;

		DBG_TRACE("  Bank %d (alg 0x%04x): extended\n", i,
			  bank->hash_alg);
	}

	/* 7. Update counter */
	ctx->pcr_update_counter++;

	/* 8. Calculate params_size for all output parameters */
	params_marshal_scratch = calloc(1, TPM2_MAX_CAP_BUFFER);
	if (!params_marshal_scratch) {
		tss2_rc = TSS2_TCTI_RC_MEMORY;
		goto end;
	}

	tss2_rc = Tss2_MU_TPML_DIGEST_VALUES_Marshal(&digests,
						     params_marshal_scratch,
						     TPM2_MAX_CAP_BUFFER,
						     &marshaled_param_size);

	params_buffer = malloc(marshaled_param_size);
	if (!params_buffer) {
		tss2_rc = TSS2_TCTI_RC_MEMORY;
		goto end;
	}

	if (marshaled_param_size > 0 && params_marshal_scratch)
		memcpy(params_buffer, params_marshal_scratch,
		       marshaled_param_size);

	/* 9. Build response */
	tss2_rc =
		build_auth_response(ctx, sess, TPM2_RC_SUCCESS,
				    TPM2_CC_PCR_Event, tag, params_buffer,
				    marshaled_param_size, &nonce_caller, NULL);

	DBG_TRACE("PCR_Event successful\n");

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
