// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <string.h>
#include <stdlib.h>

#include "smw_crypto.h"
#include "smw_keymgr.h"
#include "utils.h"
#include "commands.h"
#include "crypto.h"
#include "trace.h"

static uint32_t extract_ecdsa_signature(unsigned char *signature_buffer,
					unsigned int signature_length,
					TPMT_SIGNATURE *tpm_signature)
{
	TSS2_RC rc = TSS2_RC_SUCCESS;
	size_t coord_size = 0;

	/* Validate input parameters */
	if (!signature_buffer || !tpm_signature) {
		DBG_TRACE("Invalid parameters\n");
		rc = TSS2_TCTI_RC_BAD_REFERENCE;
		goto end;
	}

	/* Validate signature length (must be even and non-zero) */
	if (signature_length == 0 || signature_length % 2 != 0) {
		DBG_TRACE("Invalid length: %u must be even and non-zero\n",
			  signature_length);
		rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	/* Calculate coordinate size (R and S are equal length) */
	coord_size = signature_length / 2;

	/* Validate coordinate size against TPM2 buffer limits */
	if (coord_size > TPM2_MAX_ECC_KEY_BYTES) {
		DBG_TRACE("Signature coordinate size too large: %zu bytes\n",
			  coord_size);
		rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	/* Additional validation for specific curve sizes */
	switch (coord_size) {
	case 28: /* P-224: 28 bytes per coordinate */
	case 32: /* P-256: 32 bytes per coordinate */
	case 48: /* P-384: 48 bytes per coordinate */
	case 66: /* P-521: 66 bytes per coordinate */
		/* Valid ECC signature sizes */
		break;
	default:
		DBG_TRACE("Unexpected signature coordinate size: %zu bytes\n",
			  coord_size);
		rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	/* Extract R coordinate (first half of signature buffer) */
	tpm_signature->signature.ecdsa.signatureR.size = coord_size;
	memcpy(tpm_signature->signature.ecdsa.signatureR.buffer,
	       signature_buffer, coord_size);

	/* Extract S coordinate (second half of signature buffer) */
	tpm_signature->signature.ecdsa.signatureS.size = coord_size;
	memcpy(tpm_signature->signature.ecdsa.signatureS.buffer,
	       &signature_buffer[coord_size], coord_size);

	DBG_TRACE("ECDSA signature extracted successfully:\n");
	DBG_TRACE("  Total length: %u bytes\n", signature_length);
	DBG_TRACE("  R component: %zu bytes\n", coord_size);
	DBG_TRACE("  S component: %zu bytes\n", coord_size);

end:
	DBG_TRACE_COND(rc != TSS2_RC_SUCCESS, "return error: 0x%08x\n", rc);
	return rc;
}

uint32_t handle_sign(tcti_smw_context_t *ctx, uint16_t tag, const uint8_t *cmd,
		     size_t cmd_size)
{
	TPM2_RC rc = TPM2_RC_SUCCESS;
	TSS2_RC tss2_rc = TSS2_TCTI_RC_GENERAL_FAILURE;
	enum smw_status_code smw_status = SMW_STATUS_OK;

	/* Input parameters */
	sign_input_t input = { 0 };

	/* Output parameters */
	TPMT_SIGNATURE signature = { 0 };

	/* Session handling */
	uint32_t session_handle = 0;
	TPM2B_NONCE nonce_caller = { 0 };
	tcti_smw_session_t *sess = NULL;

	/* Object and key handling */
	tcti_smw_object_t *obj = NULL;
	struct smw_key_descriptor key_desc = { 0 };
	struct smw_sign_verify_args sign_args = { 0 };

	/* Signature buffer */
	unsigned char signature_buffer[TPM2_MAX_ECC_KEY_BYTES * 2] = { 0 };
	unsigned int signature_length = sizeof(signature_buffer);

	/* SMW hash attributes algorithm */
	smw_attr_algo_t smw_hash_attr = SMW_ATTR_HASH_NONE;
	smw_attr_algo_t curve_hash_attr = SMW_ATTR_HASH_NONE;

	/* Curve parameters */
	unsigned int security_size = 0;
	TPMI_ECC_CURVE curveID = TPM2_ECC_NONE;

	/* Response marshaling */
	uint8_t *params_marshal_scratch = NULL;
	size_t marshaled_param_size = 0;
	uint8_t *params_buffer = NULL;

	if (!ctx || !cmd) {
		tss2_rc = TSS2_TCTI_RC_BAD_REFERENCE;
		goto end;
	}

	/* 1. Check initialization */
	if (!ctx->initialized) {
		tss2_rc = TSS2_TCTI_RC_BAD_SEQUENCE;
		goto end;
	}

	/* 2. Unmarshal command parameters */
	tss2_rc = sign_unmarshal(cmd, cmd_size, &input, &nonce_caller,
				 &session_handle);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	/* 3. Find session */
	sess = find_session_by_handle(ctx, session_handle);
	if (!sess || !sess->active) {
		tss2_rc = TSS2_TCTI_RC_IO_ERROR;
		goto end;
	}

	DBG_TRACE("Session found: handle=0x%08x\n", session_handle);

	/* 4. Find the key object */
	obj = find_object_by_handle(ctx, input.key_handle);
	if (!obj) {
		DBG_TRACE("Key handle 0x%08x not found\n", input.key_handle);
		tss2_rc = TSS2_TCTI_RC_IO_ERROR;
		goto end;
	}

	/* 5. Validate key type (only ECC supported) */
	if (obj->public_area.publicArea.type != TPM2_ALG_ECC) {
		DBG_TRACE("Unsupported key type: 0x%04x\n",
			  obj->public_area.publicArea.type);
		tss2_rc = TSS2_TCTI_RC_IO_ERROR;
		goto end;
	}

	/* 6. Validate signing scheme (only ECDSA supported) */
	if (input.in_scheme.scheme != TPM2_ALG_ECDSA) {
		DBG_TRACE("Unsupported signing scheme: 0x%04x\n",
			  input.in_scheme.scheme);
		tss2_rc = TSS2_TCTI_RC_IO_ERROR;
		goto end;
	}

	/* 7. Get curve information and validate */
	curveID = obj->public_area.publicArea.parameters.eccDetail.curveID;
	tss2_rc =
		map_curve_info(curveID, &security_size, NULL, &curve_hash_attr);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	/* 8. Map TPM hash algorithm to SMW hash algorithm */
	tss2_rc = map_hash_info(input.in_scheme.details.ecdsa.hashAlg, NULL,
				NULL, &smw_hash_attr);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	/* 9. Validate hash algorithm consistency */
	if (smw_hash_attr != curve_hash_attr) {
		DBG_TRACE("Hash algorithm mismatch: curve=0x%lx, scheme=0x%lx\n",
			  curve_hash_attr, smw_hash_attr);
		tss2_rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	/* 10. Setup SMW key descriptor */
	key_desc.id = obj->smw_key_id;
	key_desc.type_name = SMW_KEY_TYPE_NAME_SECP_R1;
	key_desc.security_size = security_size;

	/* 11. Setup SMW sign arguments */
	sign_args.subsystem_name = SMW_SUBSYSTEM_NAME_ELE;
	sign_args.key_descriptor = &key_desc;
	sign_args.sign_algo =
		SMW_ATTR_ALGO_ASYMMETRIC_SIGNATURE_ECDSA(SMW_ATTR_CURVE_SECP_R1,
							 smw_hash_attr);
	sign_args.sign_algo = SMW_ATTR_SET_MSG_HASHED(sign_args.sign_algo);
	sign_args.message = input.digest.buffer;
	sign_args.message_length = input.digest.size;
	sign_args.signature = signature_buffer;
	sign_args.signature_length = signature_length;

	/* 12. Call SMW to perform signature */
	smw_status = smw_sign(&sign_args);
	if (smw_status != SMW_STATUS_OK) {
		DBG_TRACE("SMW sign failed: %d\n", smw_status);
		tss2_rc = smw_rc_to_tcti_rc(smw_status);
		goto end;
	}

	DBG_TRACE("SMW sign success: signature_length=%u\n",
		  sign_args.signature_length);

	/* 13. Prepare TPM signature structure */
	signature.sigAlg = TPM2_ALG_ECDSA;
	signature.signature.ecdsa.hash = input.in_scheme.details.ecdsa.hashAlg;

	/* 14. Extract ECDSA signature components (R, S) */
	tss2_rc =
		extract_ecdsa_signature(signature_buffer,
					sign_args.signature_length, &signature);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	/* 15. Marshal signature for response */
	params_marshal_scratch = calloc(1, TPM2_MAX_CAP_BUFFER);
	if (!params_marshal_scratch) {
		tss2_rc = TSS2_TCTI_RC_MEMORY;
		goto end;
	}

	tss2_rc = Tss2_MU_TPMT_SIGNATURE_Marshal(&signature,
						 params_marshal_scratch,
						 TPM2_MAX_CAP_BUFFER,
						 &marshaled_param_size);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	/* 16. Prepare parameters buffer for HMAC calculation */
	params_buffer = malloc(marshaled_param_size);
	if (!params_buffer) {
		tss2_rc = TSS2_TCTI_RC_MEMORY;
		goto end;
	}

	memcpy(params_buffer, params_marshal_scratch, marshaled_param_size);

	/* 17. Build auth response */
	tss2_rc = build_auth_response(ctx, sess, TPM2_RC_SUCCESS, TPM2_CC_Sign,
				      tag, params_buffer, marshaled_param_size,
				      &nonce_caller, NULL);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	DBG_TRACE("Sign success: handle=0x%08x, signature_length=%u\n",
		  input.key_handle, sign_args.signature_length);

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
