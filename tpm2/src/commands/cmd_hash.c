// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <string.h>
#include <byteswap.h>

#include "smw_crypto.h"
#include "utils.h"
#include "crypto.h"
#include "commands.h"
#include "smw_keymgr.h"
#include "builtin_macros.h"
#include "trace.h"

static bool starts_with_tpm_generated(const uint8_t *data)
{
	uint32_t value;

	/* Check if data starts with TPM2_GENERATED_VALUE (big-endian) */
	value = bswap_32(*(uint32_t *)data);

	return (value == TPM2_GENERATED_VALUE);
}

uint32_t handle_hash(tcti_smw_context_t *ctx, uint16_t tag, const uint8_t *cmd,
		     size_t cmd_size)
{
	TPM2_RC rc = TPM2_RC_SUCCESS;
	TSS2_RC tss2_rc = TSS2_TCTI_RC_GENERAL_FAILURE;
	size_t offset = TPM_HEADER_SIZE;
	struct smw_hash_args hash_args = { 0 };
	enum smw_status_code smw_status = SMW_STATUS_OK;
	size_t resp_params_size = 0;

	/* Input parameters */
	TPM2B_MAX_BUFFER data = { 0 };
	TPMI_ALG_HASH hash_alg = TPM2_ALG_NULL;
	TPMI_RH_HIERARCHY hierarchy = TPM2_RH_NULL;

	/* Output parameters */
	TPM2B_DIGEST out_hash = { 0 };
	TPMT_TK_HASHCHECK validation = { 0 };

	/* Session handling */
	uint32_t session_handle = 0;
	TPM2B_NONCE nonce_caller = { 0 };
	tcti_smw_session_t *sess = NULL;

	uint8_t *params_buffer = NULL;

	if (tag == TPM2_ST_SESSIONS) {
		tss2_rc = unmarshal_auth_area(cmd, cmd_size, &offset,
					      &nonce_caller, &session_handle);
		if (tss2_rc != TSS2_RC_SUCCESS)
			goto end;

		/* Find session */
		if (session_handle != TPM2_RH_PW) {
			sess = find_session_by_handle(ctx, session_handle);
			if (!sess || !sess->active) {
				tss2_rc = TSS2_TCTI_RC_IO_ERROR;
				goto end;
			}
		}
	}

	/* 1. Unmarshal input parameters */
	tss2_rc = Tss2_MU_TPM2B_MAX_BUFFER_Unmarshal(cmd, cmd_size, &offset,
						     &data);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	if (!data.size) {
		tss2_rc = TSS2_TCTI_RC_GENERAL_FAILURE;
		goto end;
	}

	tss2_rc = Tss2_MU_UINT16_Unmarshal(cmd, cmd_size, &offset, &hash_alg);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	tss2_rc = Tss2_MU_UINT32_Unmarshal(cmd, cmd_size, &offset, &hierarchy);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	if (hierarchy != TPM2_RH_NULL && hierarchy != TPM2_RH_OWNER &&
	    hierarchy != TPM2_RH_PLATFORM && hierarchy != TPM2_RH_ENDORSEMENT) {
		DBG_TRACE("Invalid hierarchy: 0x%08x\n", hierarchy);
		tss2_rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	/* 2. Configure algorithm */
	tss2_rc = map_hash_info(hash_alg, &out_hash.size, &hash_args.algo_name,
				NULL);
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

	/* 5. Marshal output parameters */
	params_buffer = calloc(1, TPM2_MAX_CAP_BUFFER);
	if (!params_buffer) {
		tss2_rc = TSS2_TCTI_RC_MEMORY;
		goto end;
	}

	tss2_rc = Tss2_MU_TPM2B_DIGEST_Marshal(&out_hash, params_buffer,
					       TPM2_MAX_CAP_BUFFER,
					       &resp_params_size);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	validation.tag = TPM2_ST_HASHCHECK;
	if (!starts_with_tpm_generated(data.buffer) ||
	    hierarchy == TPM2_RH_NULL) {
		/* NULL ticket - data is not safe to sign */
		validation.hierarchy = TPM2_RH_NULL;
		validation.digest.size = 0;

		DBG_TRACE("Returning NULL ticket\n"
			  "(hierarchy=0x%08x, TPM_GEN=%s)\n",
			  hierarchy,
			  starts_with_tpm_generated(data.buffer) ? "yes" :
								   "no");
	} else {
		/* Valid ticket - Data starts with TPM2_GENERATED_VALUE */
		validation.hierarchy = hierarchy;
		validation.digest.size = TPM2_SHA256_DIGEST_SIZE;
		tss2_rc = compute_hashcheck_hmac(hierarchy, out_hash.buffer,
						 out_hash.size,
						 validation.digest.buffer);
		if (tss2_rc == TSS2_RC_SUCCESS) {
			DBG_TRACE("Valid ticket with HMAC (%u bytes)\n",
				  validation.digest.size);
		} else {
			/* Fallback to empty digest if HMAC fails */
			validation.digest.size = 0;
			DBG_TRACE("Valid ticket but HMAC failed\n"
				  "using empty digest\n");
		}
	}

	tss2_rc = Tss2_MU_TPMT_TK_HASHCHECK_Marshal(&validation, params_buffer,
						    TPM2_MAX_CAP_BUFFER,
						    &resp_params_size);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	/* 6. Building response */
	tss2_rc = build_auth_response(ctx, sess, TPM2_RC_SUCCESS, TPM2_CC_Hash,
				      tag, params_buffer, resp_params_size,
				      &nonce_caller, NULL);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	DBG_TRACE("Hash computed successfully\n");

end:
	/* Free allocated memory */
	if (params_buffer)
		free(params_buffer);

	if (tss2_rc != TSS2_RC_SUCCESS) {
		rc = tcti_rc_to_tpm2_rc(tss2_rc);
		return build_rc_response(ctx, TPM_HEADER_SIZE, tag, rc);
	}

	return tss2_rc;
}

uint32_t handle_hmac(tcti_smw_context_t *ctx, uint16_t tag, const uint8_t *cmd,
		     size_t cmd_size)
{
	TPM2_RC rc = TPM2_RC_SUCCESS;
	TSS2_RC tss2_rc = TSS2_TCTI_RC_GENERAL_FAILURE;
	enum smw_status_code smw_status = SMW_STATUS_OK;
	size_t resp_params_size = 0;

	/* Input parameters */
	uint32_t object_handle = 0;
	TPM2B_MAX_BUFFER data = { 0 };
	TPMI_ALG_HASH hmac_hash_alg = TPM2_ALG_ERROR;

	/* Output parameters */
	TPM2B_DIGEST hmac_result = { 0 };
	uint16_t hmac_size = 0;
	smw_hash_algo_t smw_hash_name = SMW_HASH_ALGO_NAME_NONE;

	/* Session handling */
	uint32_t session_handle = 0;
	TPM2B_NONCE nonce_caller = { 0 };
	tcti_smw_session_t *sess = NULL;

	struct smw_mac_args mac_args = { 0 };
	struct smw_key_descriptor key_desc = { 0 };

	tcti_smw_object_t *obj = NULL;
	size_t offset = TPM_HEADER_SIZE;
	uint8_t *params_buffer = NULL;

	if (!ctx->initialized) {
		tss2_rc = TSS2_TCTI_RC_BAD_SEQUENCE;
		goto end;
	}

	/* 1. Unmarshal command (inputs) */
	tss2_rc = Tss2_MU_UINT32_Unmarshal(cmd, cmd_size, &offset,
					   &object_handle);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	/* 2. Get the object referenced by handle */
	obj = find_object_by_handle(ctx, object_handle);
	if (!obj) {
		DBG_TRACE("Object handle 0x%08x not found\n", object_handle);
		tss2_rc = TSS2_TCTI_RC_IO_ERROR;
		goto end;
	}

	tss2_rc = unmarshal_auth_area(cmd, cmd_size, &offset, &nonce_caller,
				      &session_handle);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	if (session_handle != TPM2_RH_PW) {
		sess = find_session_by_handle(ctx, session_handle);
		if (!sess || !sess->active) {
			tss2_rc = TSS2_TCTI_RC_IO_ERROR;
			goto end;
		}
	}

	tss2_rc = Tss2_MU_TPM2B_MAX_BUFFER_Unmarshal(cmd, cmd_size, &offset,
						     &data);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	tss2_rc = Tss2_MU_UINT16_Unmarshal(cmd, cmd_size, &offset,
					   &hmac_hash_alg);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	/* 3. Computing HMAC via SMW using the object's key*/
	tss2_rc =
		map_hash_info(hmac_hash_alg, &hmac_size, &smw_hash_name, NULL);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	key_desc.id = obj->smw_key_id;

	mac_args.algo_name = SMW_MAC_ALGO_NAME_HMAC;
	mac_args.hash_name = smw_hash_name;
	mac_args.input = data.buffer;
	mac_args.input_length = data.size;
	mac_args.key_descriptor = &key_desc;

	/* Prepare output buffer */
	hmac_result.size = hmac_size;
	mac_args.mac = hmac_result.buffer;
	mac_args.mac_length = hmac_result.size;

	smw_status = smw_mac(&mac_args);
	if (smw_status != SMW_STATUS_OK) {
		DBG_TRACE("SMW MAC operation failed: %d\n", smw_status);
		tss2_rc = smw_rc_to_tcti_rc(smw_status);
		goto end;
	}

	/* 4. Marshal output parameter */
	params_buffer = calloc(1, TPM2_MAX_CAP_BUFFER);
	if (!params_buffer) {
		tss2_rc = TSS2_TCTI_RC_MEMORY;
		goto end;
	}

	tss2_rc = Tss2_MU_TPM2B_DIGEST_Marshal(&hmac_result, params_buffer,
					       TPM2_MAX_CAP_BUFFER,
					       &resp_params_size);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	/* 5. Build response */
	tss2_rc = build_auth_response(ctx, sess, TPM2_RC_SUCCESS, TPM2_CC_HMAC,
				      tag, params_buffer, resp_params_size,
				      &nonce_caller, NULL);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	DBG_TRACE("HMAC computed successfully, result:\n");
	DBG_BUF_HEX(hmac_result.buffer, hmac_result.size);

end:
	/* Free allocated memory */
	if (params_buffer)
		free(params_buffer);

	if (tss2_rc != TSS2_RC_SUCCESS) {
		rc = tcti_rc_to_tpm2_rc(tss2_rc);
		tss2_rc = build_rc_response(ctx, TPM_HEADER_SIZE, tag, rc);
	}

	return tss2_rc;
}

uint32_t handle_getrandom(tcti_smw_context_t *ctx, uint16_t tag,
			  const uint8_t *cmd, size_t cmd_size)
{
	TSS2_RC tss2_rc = TSS2_TCTI_RC_GENERAL_FAILURE;
	TPM2_RC rc = TPM2_RC_SUCCESS;
	size_t offset = TPM_HEADER_SIZE;
	uint16_t bytes_to_generate = 0;
	enum smw_status_code smw_status = SMW_STATUS_OK;
	struct smw_rng_args rng_args = { 0 };
	size_t resp_params_size = 0;

	/* Input parameter */
	uint16_t bytes_requested = 0;

	/* Output parameter */
	TPM2B_DIGEST random_bytes = { 0 };

	/* Session handling */
	uint32_t session_handle = 0;
	TPM2B_NONCE nonce_caller = { 0 };
	tcti_smw_session_t *sess = NULL;

	uint8_t *params_buffer = NULL;

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

	/* 1. Unmarshal input parameter */
	tss2_rc = Tss2_MU_UINT16_Unmarshal(cmd, cmd_size, &offset,
					   &bytes_requested);
	if (tss2_rc != TSS2_RC_SUCCESS) {
		DBG_TRACE("Failed to unmarshal bytes_requested\n");
		goto end;
	}

	DBG_TRACE("GetRandom: %u bytes requested\n", bytes_requested);

	/* 2. Limit to maximum TPM capacity */
	DBG_TRACE_COND(bytes_to_generate > sizeof(random_bytes.buffer),
		       "Requested %u bytes exceeds max %zu, truncating\n",
		       bytes_requested, sizeof(random_bytes.buffer));
	bytes_to_generate = MIN(bytes_requested, sizeof(random_bytes.buffer));

	/* 3. Generate bytes randomly through SMW */
	rng_args.subsystem_name = SMW_SUBSYSTEM_NAME_ELE;
	rng_args.output = random_bytes.buffer;
	rng_args.output_length = bytes_to_generate;

	smw_status = smw_rng(&rng_args);
	if (smw_status != SMW_STATUS_OK) {
		DBG_TRACE("SMW RNG generation failed\n");
		tss2_rc = smw_rc_to_tcti_rc(smw_status);
		goto end;
	}

	random_bytes.size = bytes_to_generate;

	DBG_TRACE("Generated %u random bytes (requested: %u)\n",
		  random_bytes.size, bytes_requested);

	DBG_TRACE_COND(bytes_requested > bytes_to_generate,
		       "Note: Returned %u bytes instead of %u (TPM limit)\n",
		       bytes_to_generate, bytes_requested);

	/* 4. Compute response size */
	params_buffer = calloc(1, TPM2_MAX_CAP_BUFFER);
	if (!params_buffer) {
		tss2_rc = TSS2_TCTI_RC_MEMORY;
		goto end;
	}

	tss2_rc = Tss2_MU_TPM2B_DIGEST_Marshal(&random_bytes, params_buffer,
					       TPM2_MAX_CAP_BUFFER,
					       &resp_params_size);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	/* 5. Build response */
	tss2_rc = build_auth_response(ctx, sess, TPM2_RC_SUCCESS,
				      TPM2_CC_GetRandom, tag, params_buffer,
				      resp_params_size, &nonce_caller, NULL);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	DBG_TRACE("GetRandom success\n");

end:
	/* Free allocated memory */
	if (params_buffer)
		free(params_buffer);

	if (tss2_rc != TSS2_RC_SUCCESS) {
		rc = tcti_rc_to_tpm2_rc(tss2_rc);
		tss2_rc = build_rc_response(ctx, TPM_HEADER_SIZE, tag, rc);
	}

	return tss2_rc;
}
