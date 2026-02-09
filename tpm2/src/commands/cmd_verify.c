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

static uint32_t prepare_ecdsa_signature(TPMT_SIGNATURE *tpm_signature,
					unsigned char *signature_buffer,
					unsigned int *signature_length)
{
	TSS2_RC rc = TSS2_RC_SUCCESS;
	size_t r_size = 0;
	size_t s_size = 0;

	/* Validate input parameters */
	if (!tpm_signature || !signature_buffer || !signature_length) {
		DBG_TRACE("Invalid parameter\n");
		rc = TSS2_TCTI_RC_BAD_REFERENCE;
		goto end;
	}

	/* Validate signature algorithm */
	if (tpm_signature->sigAlg != TPM2_ALG_ECDSA) {
		DBG_TRACE("Invalid signature algorithm: 0x%04x\n",
			  tpm_signature->sigAlg);
		rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	/* Get R and S component sizes */
	r_size = tpm_signature->signature.ecdsa.signatureR.size;
	s_size = tpm_signature->signature.ecdsa.signatureS.size;

	/* Validate that R and S have the same size */
	if (r_size != s_size) {
		DBG_TRACE("Components have different sizes: R=%zu, S=%zu\n",
			  r_size, s_size);
		rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	/* Validate component sizes */
	if (r_size == 0 || r_size > TPM2_MAX_ECC_KEY_BYTES) {
		DBG_TRACE("Invalid ECDSA component size: %zu bytes\n", r_size);
		rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	/* Additional validation for specific curve sizes */
	switch (r_size) {
	case 28: /* P-224: 28 bytes per coordinate */
	case 32: /* P-256: 32 bytes per coordinate */
	case 48: /* P-384: 48 bytes per coordinate */
	case 66: /* P-521: 66 bytes per coordinate */
		/* Valid ECC signature sizes */
		break;
	default:
		DBG_TRACE("Unexpected signature component size: %zu bytes\n",
			  r_size);
		rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	/* Check buffer capacity */
	if (*signature_length < (r_size + s_size)) {
		DBG_TRACE("Signature buffer too small\n");
		rc = TSS2_TCTI_RC_INSUFFICIENT_BUFFER;
		goto end;
	}

	/* Copy R component (first half) */
	memcpy(signature_buffer,
	       tpm_signature->signature.ecdsa.signatureR.buffer, r_size);

	/* Copy S component (second half) */
	memcpy(&signature_buffer[r_size],
	       tpm_signature->signature.ecdsa.signatureS.buffer, s_size);

	/* Set total signature length */
	*signature_length = r_size + s_size;

	DBG_TRACE("ECDSA signature prepared successfully:\n");
	DBG_TRACE("  R component: %zu bytes\n", r_size);
	DBG_TRACE("  S component: %zu bytes\n", s_size);
	DBG_TRACE("  Total length: %u bytes\n", *signature_length);

end:
	DBG_TRACE_COND(rc != TSS2_RC_SUCCESS, "return error: 0x%08x\n", rc);
	return rc;
}

uint32_t handle_verifysignature(tcti_smw_context_t *ctx, uint16_t tag,
				const uint8_t *cmd, size_t cmd_size)
{
	TPM2_RC rc = TPM2_RC_SUCCESS;
	TSS2_RC tss2_rc = TSS2_TCTI_RC_GENERAL_FAILURE;
	enum smw_status_code smw_status = SMW_STATUS_OK;

	/* Input parameters */
	verifysignature_input_t input = { 0 };

	/* Output parameters */
	TPMT_TK_VERIFIED validation = { 0 };

	/* Object and key handling */
	tcti_smw_object_t *obj = NULL;
	struct smw_key_descriptor key_desc = { 0 };
	struct smw_sign_verify_args verify_args = { 0 };

	/* Signature buffer */
	unsigned char signature_buffer[TPM2_MAX_ECC_KEY_BYTES * 2] = { 0 };
	unsigned int signature_length = sizeof(signature_buffer);

	/* SMW hash algorithm */
	smw_attr_algo_t smw_hash_attr = SMW_ATTR_HASH_NONE;
	smw_attr_algo_t curve_hash_attr = SMW_ATTR_HASH_NONE;

	/* Curve security size */
	unsigned int security_size = 0;

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
	tss2_rc = verifysignature_unmarshal(cmd, cmd_size, &input);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

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

	/* 6. Validate signature scheme (only ECDSA supported) */
	if (input.signature.sigAlg != TPM2_ALG_ECDSA) {
		DBG_TRACE("Unsupported signature scheme: 0x%04x\n",
			  input.signature.sigAlg);
		tss2_rc = TSS2_TCTI_RC_IO_ERROR;
		goto end;
	}

	/* 7. Get curve information and validate */
	tss2_rc =
		map_curve_info(/* Without this comment clang-format does not */
			       /* meet the checkpatch requirement. */
			       obj->public_area.publicArea.parameters.eccDetail
				       .curveID,
			       &security_size, NULL, &curve_hash_attr);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	/* 8. Map TPM hash algorithm to SMW hash algorithm */
	tss2_rc = map_hash_info(input.signature.signature.ecdsa.hash, NULL,
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

	/* 10. Prepare ECDSA signature buffer (R || S) */
	tss2_rc = prepare_ecdsa_signature(&input.signature, signature_buffer,
					  &signature_length);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	/* 11. Setup SMW key descriptor */
	key_desc.id = obj->smw_key_id;
	key_desc.type_name = SMW_KEY_TYPE_NAME_SECP_R1;
	key_desc.security_size = security_size;

	/* 12. Setup SMW verify arguments */
	verify_args.subsystem_name = SMW_SUBSYSTEM_NAME_ELE;
	verify_args.key_descriptor = &key_desc;
	verify_args.sign_algo =
		SMW_ATTR_ALGO_ASYMMETRIC_SIGNATURE_ECDSA(SMW_ATTR_CURVE_SECP_R1,
							 smw_hash_attr);
	verify_args.message = input.digest.buffer;
	verify_args.message_length = input.digest.size;
	verify_args.signature = signature_buffer;
	verify_args.signature_length = signature_length;

	/* 13. Call SMW to perform verification */
	smw_status = smw_verify(&verify_args);
	if (smw_status != SMW_STATUS_OK) {
		DBG_TRACE("SMW verify failed: %d\n", smw_status);
		if (smw_status == SMW_STATUS_SIGNATURE_INVALID) {
			rc = TPM2_RC_SIGNATURE;
			tss2_rc = build_rc_response(ctx, TPM_HEADER_SIZE, tag,
						    rc);
			goto end;
		}
		tss2_rc = smw_rc_to_tcti_rc(smw_status);
		goto end;
	}

	DBG_TRACE("SMW verify success\n");

	/* 14. Prepare validation ticket */
	validation.tag = TPM2_ST_VERIFIED;
	validation.hierarchy = TPM2_RH_NULL;
	validation.digest.size = 0; /* Empty digest for NULL hierarchy */

	/* 15. Marshal validation ticket for response */
	params_marshal_scratch = calloc(1, TPM2_MAX_CAP_BUFFER);
	if (!params_marshal_scratch) {
		tss2_rc = TSS2_TCTI_RC_MEMORY;
		goto end;
	}

	tss2_rc = Tss2_MU_TPMT_TK_VERIFIED_Marshal(&validation,
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
	tss2_rc =
		build_auth_response(ctx, NULL, TPM2_RC_SUCCESS,
				    TPM2_CC_VerifySignature, tag, params_buffer,
				    marshaled_param_size, NULL, NULL);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	DBG_TRACE("VerifySignature success: handle=0x%08x\n", input.key_handle);

end:
	/* Free allocated memory */
	if (params_buffer)
		free(params_buffer);

	if (params_marshal_scratch)
		free(params_marshal_scratch);

	if (tss2_rc != TSS2_RC_SUCCESS && rc == TPM2_RC_SUCCESS) {
		rc = tcti_rc_to_tpm2_rc(tss2_rc);
		tss2_rc = build_rc_response(ctx, TPM_HEADER_SIZE, tag, rc);
	}

	return tss2_rc;
}
