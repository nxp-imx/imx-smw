// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <string.h>

#include "smw_crypto.h"
#include "smw_keymgr.h"
#include "utils.h"
#include "commands.h"
#include "crypto.h"
#include "trace.h"

static uint32_t
configure_smw_key_descriptor(TPMT_PUBLIC *pub,
			     struct smw_key_descriptor *key_desc,
			     struct smw_keypair_buffer *key_buffer)
{
	TSS2_RC rc = TSS2_RC_SUCCESS;
	TPMA_OBJECT attrs = pub->objectAttributes;
	size_t public_data_size = 0;
	smw_hash_algo_t smw_hash_attr = SMW_HASH_ALGO_NAME_NONE;

	/* Configure usage flags */
	if (attrs & TPMA_OBJECT_RESTRICTED) {
		DBG_TRACE("  - TPMA_OBJECT_RESTRICTED\n");
		key_desc->attributes.usage_flags |= SMW_ATTR_USAGE_DERIVE;
	}
	if (attrs & TPMA_OBJECT_SIGN_ENCRYPT) {
		DBG_TRACE("  - TPMA_OBJECT_SIGN_ENCRYPT\n");
		if (pub->type != TPM2_ALG_ECC)
			key_desc->attributes.usage_flags |=
				SMW_ATTR_USAGE_SIGN_HASH;
	}
	if (attrs & TPMA_OBJECT_DECRYPT) {
		DBG_TRACE("  - TPMA_OBJECT_DECRYPT\n");
		if (pub->type != TPM2_ALG_ECC)
			key_desc->attributes.usage_flags |=
				SMW_ATTR_USAGE_DECRYPT;
	}

	/* Configure according to key type */
	if (pub->type == TPM2_ALG_ECC) {
		key_desc->type_name = SMW_KEY_TYPE_NAME_SECP_R1;

		switch (pub->parameters.eccDetail.curveID) {
		case TPM2_ECC_NIST_P224:
			key_desc->security_size = 224;
			public_data_size = 56;
			break;
		case TPM2_ECC_NIST_P256:
			key_desc->security_size = 256;
			public_data_size = 64;
			break;
		case TPM2_ECC_NIST_P384:
			key_desc->security_size = 384;
			public_data_size = 96;
			break;
		case TPM2_ECC_NIST_P521:
			key_desc->security_size = 521;
			public_data_size = 132;
			break;
		default:
			DBG_TRACE("Unsupported ECC curve: 0x%04x\n",
				  pub->parameters.eccDetail.curveID);
			rc = TSS2_TCTI_RC_IO_ERROR;
			goto end;
		}

		rc = map_hash_info(pub->nameAlg, NULL, &smw_hash_attr);

		key_buffer->format_name = SMW_KEY_FORMAT_NAME_NONE;
		key_buffer->gen.public_length = public_data_size;

		key_desc->attributes.permitted_algo =
			SMW_ATTR_ALGO_KEY_AGREEMENT(ECDH, SMW_ATTR_ALGO_HKDF,
						    smw_hash_attr);

		DBG_TRACE("Configuring ECC key: size=%u bits\n",
			  key_desc->security_size);
	} else {
		DBG_TRACE("Unsupported key type: 0x%04x\n", pub->type);
		rc = TSS2_TCTI_RC_IO_ERROR;
		goto end;
	}

	/* Common attributes */
	key_desc->buffer = key_buffer;
	if (!(attrs & TPMA_OBJECT_STCLEAR) && (attrs & TPMA_OBJECT_FIXEDTPM)) {
		key_desc->attributes.attributes =
			SMW_ATTR_SET_PERSISTENCE(/*Without this comment clang-format*/
						 /*does not meet the checkpatch requirement. */
						 0,
						 SMW_ATTR_PERSISTENCE_PERSISTENT);
	} else {
		DBG_TRACE("Key cannot be persistent ");
		DBG_TRACE("because of attributes given\n");
		rc = TSS2_TCTI_RC_BAD_REFERENCE;
	}

end:
	DBG_TRACE_COND(rc != TSS2_RC_SUCCESS, "return error: 0x%08x\n", rc);
	return rc;
}

uint32_t handle_createprimary(tcti_smw_context_t *ctx, uint16_t tag,
			      const uint8_t *cmd, size_t cmd_size)
{
	TPM2_RC rc = TPM2_RC_SUCCESS;
	TSS2_RC tss2_rc = TSS2_TCTI_RC_GENERAL_FAILURE;
	enum smw_status_code smw_status = SMW_STATUS_OK;
	size_t resp_offset = TPM_HEADER_SIZE;
	uint32_t total_resp_size = 0;
	uint8_t *response_hmac = NULL;

	/*
	 * creation_data, creation_hash and creation_pcr
	 * set to 0 because PCR not supported
	 */

	/* Input parameters */
	createprimary_input_t input = { 0 };

	/* Output parameters */
	createprimary_output_t output = { 0 };
	TPMT_PUBLIC *pub = NULL;
	TPMA_OBJECT attrs = { 0 };
	TPM2_HANDLE object_handle = 0;
	size_t ecc_coord_size = 0;
	unsigned char public_data_buf[TPM2_MAX_ECC_KEY_BYTES] = { 0 };

	/* Session handling */
	uint32_t session_handle = 0;
	TPM2B_NONCE nonce_caller = { 0 };
	uint16_t response_hmac_size = 0;
	uint8_t tpma_attrs = TPMA_SESSION_CONTINUESESSION;
	uint8_t *params_buffer = NULL;
	size_t params_offset = 0;
	tcti_smw_session_t *sess = NULL;

	struct smw_key_descriptor key_desc = { 0 };
	struct smw_keypair_buffer key_buffer = { 0 };
	struct smw_generate_key_args gen_args = { 0 };

	/*
	 * Workaround: Some TSS2 Marshal functions don't handle NULL buffer correctly
	 * for size calculation.
	 */
	uint8_t *params_marshal_scratch = NULL;
	size_t params_marshal_scratch_size = 1024;
	size_t marshaled_param_size = 0;

	/* 1. Check initialization */
	if (!ctx->initialized) {
		tss2_rc = TSS2_TCTI_RC_BAD_SEQUENCE;
		goto end;
	}

	params_marshal_scratch = calloc(1, params_marshal_scratch_size);
	if (!params_marshal_scratch) {
		tss2_rc = TSS2_TCTI_RC_MEMORY;
		goto end;
	}

	/* 2. Unmarshal primary handle */
	tss2_rc = create_primary_unmarshal(cmd, cmd_size, &input, &nonce_caller,
					   &session_handle);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	/* Find session */
	sess = find_session_by_handle(ctx, session_handle);
	if (!sess || !sess->active) {
		tss2_rc = TSS2_TCTI_RC_IO_ERROR;
		goto end;
	}

	DBG_TRACE("Session found: handle=0x%08x\n", session_handle);

	/* 3. Validate key type and prepare SMW structures */
	pub = &input.in_public.publicArea;
	attrs = pub->objectAttributes;

	key_buffer.gen.public_data = public_data_buf;
	tss2_rc = configure_smw_key_descriptor(pub, &key_desc, &key_buffer);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	/* 4. Call SMW to generate key */
	gen_args.subsystem_name = SMW_SUBSYSTEM_NAME_ELE;
	gen_args.key_descriptor = &key_desc;

	smw_status = smw_generate_key(&gen_args);
	if (!(smw_status == SMW_STATUS_OK ||
	      smw_status == SMW_STATUS_KEY_POLICY_WARNING_IGNORED)) {
		DBG_TRACE("SMW key generation failed: %d\n", smw_status);
		tss2_rc = smw_rc_to_tcti_rc(smw_status);
		goto end;
	}

	DBG_TRACE("Key generated successfully, SMW ID: %d\n", key_desc.id);

	/* 5. Prepare output structures */
	output.out_public = input.in_public;

	if (pub->type == TPM2_ALG_ECC) {
		/*
		 * For ECC, public_data contains: X || Y coordinates
		 * Format:
		 * - P-256: 32 bytes X + 32 bytes Y = 64 bytes total
		 * - P-384: 48 bytes X + 48 bytes Y = 96 bytes total
		 * - P-521: 66 bytes X + 66 bytes Y = 132 bytes total
		 */
		ecc_coord_size = key_buffer.gen.public_length / 2;

		/* Extract X coordinate (first half) */
		output.out_public.publicArea.unique.ecc.x.size = ecc_coord_size;

		memcpy(output.out_public.publicArea.unique.ecc.x.buffer,
		       key_buffer.gen.public_data, ecc_coord_size);

		/* Extract Y coordinate (second half) */
		output.out_public.publicArea.unique.ecc.y.size = ecc_coord_size;

		memcpy(output.out_public.publicArea.unique.ecc.y.buffer,
		       key_buffer.gen.public_data + ecc_coord_size,
		       ecc_coord_size);
	}

	/* 6. Create and setup object */
	tss2_rc = smw_object_alloc(ctx, &object_handle, attrs, key_desc.id,
				   input.primary_handle, &output.out_public);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	tss2_rc =
		calculate_object_name(&output.out_public, &output.object_name);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	/* Set creation structures to empty (minimal implementation) */
	output.creation_ticket.tag = TPM2_ST_CREATION;
	output.creation_ticket.hierarchy = input.primary_handle;
	output.creation_ticket.digest.size = 0;

	tss2_rc = Tss2_MU_TPM2B_PUBLIC_Marshal(&output.out_public,
					       params_marshal_scratch,
					       params_marshal_scratch_size,
					       &marshaled_param_size);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	tss2_rc =
		Tss2_MU_TPM2B_CREATION_DATA_Marshal(/* Without this comment */
						    /*clang-format does not meet the checkpatch */
						    /* requirement. */
						    &output.creation_data,
						    params_marshal_scratch,
						    params_marshal_scratch_size,
						    &marshaled_param_size);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	tss2_rc = Tss2_MU_TPM2B_DIGEST_Marshal(&output.creation_hash,
					       params_marshal_scratch,
					       params_marshal_scratch_size,
					       &marshaled_param_size);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	tss2_rc = Tss2_MU_TPMT_TK_CREATION_Marshal(&output.creation_ticket,
						   params_marshal_scratch,
						   params_marshal_scratch_size,
						   &marshaled_param_size);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	tss2_rc = Tss2_MU_TPM2B_NAME_Marshal(&output.object_name,
					     params_marshal_scratch,
					     params_marshal_scratch_size,
					     &marshaled_param_size);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	/* 7. Prepare parameters buffer for HMAC calculation */
	params_buffer = malloc(marshaled_param_size);
	if (!params_buffer) {
		tss2_rc = TSS2_TCTI_RC_MEMORY;
		goto end;
	}

	tss2_rc =
		Tss2_MU_TPM2B_PUBLIC_Marshal(&output.out_public, params_buffer,
					     marshaled_param_size,
					     &params_offset);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	tss2_rc = Tss2_MU_TPM2B_CREATION_DATA_Marshal(&output.creation_data,
						      params_buffer,
						      marshaled_param_size,
						      &params_offset);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	tss2_rc = Tss2_MU_TPM2B_DIGEST_Marshal(&output.creation_hash,
					       params_buffer,
					       marshaled_param_size,
					       &params_offset);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	tss2_rc = Tss2_MU_TPMT_TK_CREATION_Marshal(&output.creation_ticket,
						   params_buffer,
						   marshaled_param_size,
						   &params_offset);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	tss2_rc = Tss2_MU_TPM2B_NAME_Marshal(&output.object_name, params_buffer,
					     marshaled_param_size,
					     &params_offset);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	/* 8. Calculate response HMAC if session present */
	tss2_rc = calculate_response_hmac(sess, TPM2_RC_SUCCESS,
					  TPM2_CC_CreatePrimary, params_buffer,
					  params_offset, nonce_caller.buffer,
					  nonce_caller.size, &response_hmac,
					  &response_hmac_size);
	if (tss2_rc != TSS2_RC_SUCCESS) {
		DBG_TRACE("Failed to calculate response HMAC\n");
		response_hmac_size = 0;
	}

	/* 9. Calculate total response size */
	total_resp_size = TPM_HEADER_SIZE;
	total_resp_size += sizeof(TPM2_HANDLE); /* object handle */

	total_resp_size += sizeof(uint32_t); /* parameterSize */
	total_resp_size += params_offset;    /* parameters */
	/* Auth response area */
	total_resp_size += sizeof(uint16_t) + sess->nonce.size;
	total_resp_size += sizeof(uint8_t); /* attributes */
	total_resp_size += sizeof(uint16_t) + response_hmac_size;

	/* 10. Build response */
	tss2_rc = build_rc_response(ctx, total_resp_size, tag, TPM2_RC_SUCCESS);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	/*
	 * 11. Marshal response
	 * Object handle
	 */
	tss2_rc = Tss2_MU_UINT32_Marshal(object_handle, ctx->resp_buf,
					 ctx->resp_size, &resp_offset);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	/* Parameter size if sessions */
	tss2_rc = Tss2_MU_UINT32_Marshal((uint32_t)params_offset, ctx->resp_buf,
					 ctx->resp_size, &resp_offset);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	/* Response parameters */
	memcpy(&ctx->resp_buf[resp_offset], params_buffer, params_offset);

	resp_offset += params_offset;

	/* Auth response area if session */
	/* nonceTPM */
	tss2_rc = Tss2_MU_TPM2B_NONCE_Marshal(&sess->nonce, ctx->resp_buf,
					      ctx->resp_size, &resp_offset);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	/* attributes */
	tss2_rc = Tss2_MU_UINT8_Marshal(tpma_attrs, ctx->resp_buf,
					ctx->resp_size, &resp_offset);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	/* Response HMAC */
	tss2_rc = Tss2_MU_UINT16_Marshal(response_hmac_size, ctx->resp_buf,
					 ctx->resp_size, &resp_offset);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	if (response_hmac_size > 0) {
		memcpy(&ctx->resp_buf[resp_offset], response_hmac,
		       response_hmac_size);

		resp_offset += response_hmac_size;
	}

	DBG_TRACE("CreatePrimary success: handle=0x%08x, SMW ID=%d\n",
		  object_handle, key_desc.id);

end:
	/* Free allocated memory */
	free(params_buffer);
	free(response_hmac);
	free(params_marshal_scratch);

	if (tss2_rc != TSS2_RC_SUCCESS) {
		rc = tcti_rc_to_tpm2_rc(tss2_rc);
		return build_rc_response(ctx, TPM_HEADER_SIZE, tag, rc);
	}

	return tss2_rc;
}
