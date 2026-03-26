// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <string.h>

#include <tss2/tss2_mu.h>

#include "utils.h"
#include "commands.h"
#include "trace.h"

#include "smw_keymgr.h"
#include "crypto.h"

static uint32_t verify_creation_ticket(TPMI_RH_HIERARCHY hierarchy,
				       const tcti_smw_object_t *object,
				       const TPM2B_DIGEST creation_hash,
				       TPMT_TK_CREATION ticket)
{
	TSS2_RC rc = TSS2_TCTI_RC_BAD_VALUE;
	size_t digest_size = ticket.digest.size;

	/* 1. Validate creation ticket */
	if (ticket.tag != TPM2_ST_CREATION) {
		DBG_TRACE("Invalid creation ticket tag:\n"
			  "0x%04x (expected 0x%04x)\n",
			  ticket.tag, TPM2_ST_CREATION);
		goto end;
	}

	/* 2. Validate hierarchy matches */
	if (ticket.hierarchy != hierarchy) {
		DBG_TRACE("Hierarchy mismatch:\n"
			  "  ticket.hierarchy: 0x%08x\n"
			  "  expected: 0x%08x\n",
			  ticket.hierarchy, hierarchy);
		goto end;
	}

	/* 3. Handle NULL ticket (empty digest) */
	if (!ticket.digest.size) {
		DBG_TRACE("NULL ticket (empty digest)\n"
			  "- skipping verification\n");
		rc = TSS2_RC_SUCCESS;
		goto end;
	}

	/* 4. Validate ticket digest size */
	if (ticket.digest.size != TPM2_SHA256_DIGEST_SIZE) {
		DBG_TRACE("Invalid ticket digest size: %u (expected %u)\n",
			  ticket.digest.size, TPM2_SHA256_DIGEST_SIZE);
		goto end;
	}

	/* 5. Compute expected HMAC using common function */
	rc = compute_creation_ticket_hmac(hierarchy, &object->object_name,
					  &creation_hash, ticket.digest.buffer,
					  &digest_size, true);
	if (rc != TSS2_RC_SUCCESS) {
		DBG_TRACE("Failed to compute HMAC for verification\n");
		goto end;
	}

	DBG_TRACE("Ticket verification SUCCESS!\n"
		  "Ticket is authentic and valid\n");

end:
	DBG_TRACE_COND(rc != TSS2_RC_SUCCESS, "return error: 0x%08x\n", rc);
	return rc;
}

static uint32_t build_tpms_attest_creation(TPMS_ATTEST *attest,
					   tcti_smw_object_t *object,
					   tcti_smw_object_t *signer,
					   const uint8_t *qualifying_data,
					   uint16_t qualifying_data_size,
					   const uint8_t *creation_hash,
					   uint16_t creation_hash_size)
{
	TSS2_RC rc = TSS2_TCTI_RC_BAD_VALUE;

	if (!attest || !creation_hash)
		goto end;

	memset(attest, 0, sizeof(*attest));

	/* 1. Magic value - indicates TPM generated */
	attest->magic = TPM2_GENERATED_VALUE;

	/* 2. Type - ATTEST_CREATION */
	attest->type = TPM2_ST_ATTEST_CREATION;

	/* 3. Qualified signer Name */
	if (signer) {
		/* Compute Name of signing key */
		rc = calculate_object_name(&signer->public_area,
					   &attest->qualifiedSigner);
		if (rc != TSS2_RC_SUCCESS) {
			DBG_TRACE("Failed to compute signer Name\n");
			goto end;
		}
	} else {
		/* NULL signer - empty qualifiedSigner */
		attest->qualifiedSigner.size = 0;
	}

	/* 4. Extra data (user-provided qualifying data) */
	attest->extraData.size = qualifying_data_size;
	if (qualifying_data && qualifying_data_size > 0) {
		if (qualifying_data_size > sizeof(attest->extraData.buffer)) {
			DBG_TRACE("qualifyingData too large: %u > %zu\n",
				  qualifying_data_size,
				  sizeof(attest->extraData.buffer));
			rc = TSS2_TCTI_RC_BAD_VALUE;
			goto end;
		}

		memcpy(attest->extraData.buffer, qualifying_data,
		       qualifying_data_size);
	}

	/* 5. Clock info (simulated) */
	attest->clockInfo.clock = 0;
	attest->clockInfo.resetCount = 0;
	attest->clockInfo.restartCount = 0;
	attest->clockInfo.safe = TPM2_YES;

	/* 6. Firmware version (simulated) */
	attest->firmwareVersion = 0;

	/* 7. Creation-specific fields */

	/* objectName - Name of the created object */
	rc = calculate_object_name(&object->public_area,
				   &attest->attested.creation.objectName);
	if (rc != TSS2_RC_SUCCESS) {
		DBG_TRACE("Failed to compute object Name\n");
		goto end;
	}

	/* creationHash */
	if (creation_hash_size >
	    sizeof(attest->attested.creation.creationHash.buffer)) {
		DBG_TRACE("creationHash too large: %u > %zu\n",
			  creation_hash_size,
			  sizeof(attest->attested.creation.creationHash.buffer));
		rc = TSS2_TCTI_RC_INSUFFICIENT_BUFFER;
		goto end;
	}

	attest->attested.creation.creationHash.size = creation_hash_size;

	memcpy(attest->attested.creation.creationHash.buffer, creation_hash,
	       creation_hash_size);

end:
	DBG_TRACE_COND(rc != TSS2_RC_SUCCESS, "return error: 0x%08x\n", rc);
	return rc;
}

static uint32_t sign_attest_structure(tcti_smw_object_t *signer,
				      uint8_t *attest_data, size_t attest_size,
				      const TPMT_SIG_SCHEME *in_scheme,
				      TPMT_SIGNATURE *signature)
{
	TSS2_RC rc = TSS2_TCTI_RC_BAD_VALUE;
	enum smw_status_code smw_status = SMW_STATUS_OK;
	struct smw_sign_verify_args sign_args = { 0 };
	struct smw_key_descriptor key_desc = { 0 };

	/* SMW hash attributes algorithm */
	smw_attr_algo_t smw_hash_attr = SMW_ATTR_HASH_NONE;
	smw_attr_algo_t curve_hash_attr = SMW_ATTR_HASH_NONE;

	/* Curve security size */
	unsigned int security_size = 0;
	TPMI_ECC_CURVE curve_id = 0;

	/* Signature buffer */
	unsigned char signature_buffer[TPM2_MAX_ECC_KEY_BYTES * 2] = { 0 };
	unsigned int signature_length = sizeof(signature_buffer);

	if (!signer || !attest_data || !in_scheme || !signature)
		goto end;

	/* 1. Validate key type (only ECC supported) */

	if (signer->public_area.publicArea.type != TPM2_ALG_ECC) {
		DBG_TRACE("Unsupported key type: 0x%04x\n",
			  signer->public_area.publicArea.type);
		rc = TSS2_TCTI_RC_IO_ERROR;
		goto end;
	}

	if (in_scheme->scheme != TPM2_ALG_ECDSA) {
		DBG_TRACE("Unsupported signing scheme: 0x%04x\n",
			  in_scheme->scheme);
		rc = TSS2_TCTI_RC_IO_ERROR;
		goto end;
	}

	curve_id = signer->public_area.publicArea.parameters.eccDetail.curveID;

	/* 2. Get curve information and validate */
	rc = map_curve_info(curve_id, &security_size, NULL, &curve_hash_attr);
	if (rc != TSS2_RC_SUCCESS)
		goto end;

	/* 3. Map TPM hash algorithm to SMW hash algorithm */
	rc = map_hash_info(in_scheme->details.ecdsa.hashAlg, NULL, NULL,
			   &smw_hash_attr);
	if (rc != TSS2_RC_SUCCESS)
		goto end;

	/* 4. Validate hash algorithm consistency */
	if (smw_hash_attr != curve_hash_attr) {
		DBG_TRACE("Hash algorithm mismatch: curve=0x%lx, scheme=0x%lx\n",
			  curve_hash_attr, smw_hash_attr);
		rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	if (attest_size > UINT32_MAX) {
		DBG_TRACE("Attest data size too large: %zu\n", attest_size);
		rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	/* 6. Hash and sign the attest data */
	key_desc.id = signer->smw_key_id;
	key_desc.type_name = SMW_KEY_TYPE_NAME_SECP_R1;
	key_desc.security_size = security_size;

	sign_args.key_descriptor = &key_desc;
	sign_args.sign_algo =
		SMW_ATTR_ALGO_ASYMMETRIC_SIGNATURE_ECDSA(SMW_ATTR_CURVE_SECP_R1,
							 smw_hash_attr);
	sign_args.message = attest_data;
	sign_args.message_length = attest_size;
	sign_args.signature = signature_buffer;
	sign_args.signature_length = signature_length;

	smw_status = smw_sign(&sign_args);
	if (smw_status != SMW_STATUS_OK) {
		DBG_TRACE("SMW sign failed: %d\n", smw_status);
		rc = smw_rc_to_tcti_rc(smw_status);
		goto end;
	}

	DBG_TRACE("SMW sign success: signature_length=%u\n",
		  sign_args.signature_length);

	/* 7. Build TPMT_SIGNATURE structure */
	signature->sigAlg = TPM2_ALG_ECDSA;
	signature->signature.ecdsa.hash = in_scheme->details.ecdsa.hashAlg;

	rc = extract_ecdsa_signature(signature_buffer,
				     sign_args.signature_length, signature);
	if (rc != TSS2_RC_SUCCESS)
		goto end;

end:
	DBG_TRACE_COND(rc != TSS2_RC_SUCCESS, "return error: 0x%08x\n", rc);
	return rc;
}

uint32_t handle_certifycreation(tcti_smw_context_t *ctx, uint16_t tag,
				const uint8_t *cmd, size_t cmd_size)
{
	TPM2_RC rc = TPM2_RC_SUCCESS;
	TSS2_RC tss2_rc = TSS2_TCTI_RC_GENERAL_FAILURE;
	size_t offset = TPM_HEADER_SIZE;
	TPMT_SIG_SCHEME effective_scheme = { 0 };
	TPMT_SIG_SCHEME key_scheme = { 0 };

	/* Input parameters */
	TPM2_HANDLE sign_handle = 0;
	TPM2_HANDLE object_handle = 0;
	TPM2B_DATA qualifying_data = { 0 };
	TPM2B_DIGEST creation_hash = { 0 };
	TPMT_SIG_SCHEME in_scheme = { 0 };
	TPMT_TK_CREATION creation_ticket = { 0 };

	/* Session handling */
	uint32_t session_handle = 0;
	TPM2B_NONCE nonce_caller = { 0 };
	tcti_smw_session_t *sess = NULL;

	/* Objects */
	tcti_smw_object_t *signer = NULL;
	tcti_smw_object_t *object = NULL;

	/* Output parameters */
	TPM2B_ATTEST certify_info = { 0 };
	TPMT_SIGNATURE signature = { 0 };
	TPMS_ATTEST attest = { 0 };
	size_t attest_offset = 0;
	size_t attest_buf_size = sizeof(certify_info.attestationData);

	/* Buffers */
	uint8_t *params_buffer = NULL;
	size_t marshaled_param_size = 0;

	if (!ctx) {
		tss2_rc = TSS2_TCTI_RC_BAD_REFERENCE;
		goto end;
	}

	/* 1. Unmarshal handles */
	tss2_rc =
		Tss2_MU_UINT32_Unmarshal(cmd, cmd_size, &offset, &sign_handle);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	tss2_rc = Tss2_MU_UINT32_Unmarshal(cmd, cmd_size, &offset,
					   &object_handle);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	/* 2. Get signing key */
	signer = find_object_by_handle(ctx, sign_handle);
	if (!signer) {
		tss2_rc = TSS2_TCTI_RC_IO_ERROR;
		goto end;
	}

	/* Verify signing key has sign attribute */
	if (!(signer->attributes & TPMA_OBJECT_SIGN_ENCRYPT)) {
		DBG_TRACE("Key 0x%08x cannot sign\n", sign_handle);
		tss2_rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	/* 3. Get the object associated with the creation data */
	object = find_object_by_handle(ctx, object_handle);
	if (!object) {
		tss2_rc = TSS2_TCTI_RC_IO_ERROR;
		goto end;
	}

	/* 4. Unmarshal authorization area */
	tss2_rc = unmarshal_auth_area(cmd, cmd_size, &offset, &nonce_caller,
				      &session_handle);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	if (session_handle != TPM2_RH_PW) {
		sess = find_session_by_handle(ctx, session_handle);
		if (!sess || !sess->active) {
			DBG_TRACE("Session 0x%08x not found or inactive\n",
				  session_handle);
			tss2_rc = TSS2_TCTI_RC_IO_ERROR;
			goto end;
		}
	}

	/* 5. Unmarshal parameters */

	/* qualifyingData */
	tss2_rc = Tss2_MU_TPM2B_DATA_Unmarshal(cmd, cmd_size, &offset,
					       &qualifying_data);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	/* creationHash */
	tss2_rc = Tss2_MU_TPM2B_DIGEST_Unmarshal(cmd, cmd_size, &offset,
						 &creation_hash);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	/* inScheme */
	tss2_rc = Tss2_MU_TPMT_SIG_SCHEME_Unmarshal(cmd, cmd_size, &offset,
						    &in_scheme);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	/* creationTicket */
	tss2_rc = Tss2_MU_TPMT_TK_CREATION_Unmarshal(cmd, cmd_size, &offset,
						     &creation_ticket);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	/* 6. Validate creation ticket */
	tss2_rc = verify_creation_ticket(object->hierarchy, object,
					 creation_hash, creation_ticket);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	/* Extract key's signature scheme */
	tss2_rc = extract_key_sig_scheme(&signer->public_area, &key_scheme);
	if (tss2_rc != TSS2_RC_SUCCESS) {
		DBG_TRACE("Failed to extract key signature scheme\n");
		goto end;
	}

	/* Determine effective scheme according to TPM 2.0 spec */
	tss2_rc = get_effective_scheme(&signer->public_area.publicArea,
				       &key_scheme, &in_scheme,
				       &effective_scheme);
	if (tss2_rc != TSS2_RC_SUCCESS) {
		DBG_TRACE("Failed to determine effective scheme\n");
		goto end;
	}

	/* 7. Build TPMS_ATTEST structure using existing function */
	tss2_rc = build_tpms_attest_creation(&attest, object, signer,
					     qualifying_data.buffer,
					     qualifying_data.size,
					     creation_hash.buffer,
					     creation_hash.size);
	if (tss2_rc != TSS2_RC_SUCCESS) {
		DBG_TRACE("Failed to build TPMS_ATTEST\n");
		goto end;
	}

	/* 8. Marshal TPMS_ATTEST */
	tss2_rc = Tss2_MU_TPMS_ATTEST_Marshal(&attest,
					      certify_info.attestationData,
					      attest_buf_size, &attest_offset);
	if (tss2_rc != TSS2_RC_SUCCESS) {
		DBG_TRACE("Failed to marshal TPMS_ATTEST\n");
		goto end;
	}

	certify_info.size = attest_offset;

	/* 9. Sign the attestation structure */
	tss2_rc = sign_attest_structure(signer, certify_info.attestationData,
					certify_info.size, &effective_scheme,
					&signature);
	if (tss2_rc != TSS2_RC_SUCCESS) {
		DBG_TRACE("Failed to sign attest structure\n");
		goto end;
	}

	/* 10. Marshal output parameters */
	params_buffer = calloc(1, TPM2_MAX_CAP_BUFFER);
	if (!params_buffer) {
		tss2_rc = TSS2_TCTI_RC_MEMORY;
		goto end;
	}

	/* Marshal certifyInfo */
	tss2_rc = Tss2_MU_TPM2B_ATTEST_Marshal(&certify_info, params_buffer,
					       TPM2_MAX_CAP_BUFFER,
					       &marshaled_param_size);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	/* Marshal signature */
	tss2_rc = Tss2_MU_TPMT_SIGNATURE_Marshal(&signature, params_buffer,
						 TPM2_MAX_CAP_BUFFER,
						 &marshaled_param_size);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	/* 11. Build response */
	tss2_rc =
		build_auth_response(ctx, sess, TPM2_RC_SUCCESS,
				    TPM2_CC_CertifyCreation, tag, params_buffer,
				    marshaled_param_size, &nonce_caller, NULL);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	DBG_TRACE("CertifyCreation successful:\n"
		  "  signHandle: 0x%08x\n"
		  "  objectHandle: 0x%08x\n"
		  "  certifyInfo size: %u bytes\n",
		  sign_handle, object_handle, certify_info.size);

end:
	if (params_buffer)
		free(params_buffer);

	if (tss2_rc != TSS2_RC_SUCCESS) {
		rc = tcti_rc_to_tpm2_rc(tss2_rc);
		tss2_rc = build_rc_response(ctx, TPM_HEADER_SIZE, tag, rc);
	}

	return tss2_rc;
}
