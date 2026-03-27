// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <string.h>

#include "crypto.h"
#include "trace.h"

uint32_t map_curve_info(TPM2_ECC_CURVE curve, uint32_t *security_size,
			uint32_t *public_data_size, smw_attr_algo_t *hash_attr)
{
	TSS2_RC rc = TSS2_TCTI_RC_BAD_VALUE;
	uint32_t size = 0, data_size = 0;
	smw_attr_algo_t hash = SMW_ATTR_ALGO_NONE;

	switch (curve) {
	case TPM2_ECC_NIST_P224:
		size = ECC_P224_SECURITY_BITS;
		data_size = ECC_P224_PUBLIC_SIZE;
		hash = SMW_ATTR_HASH_SHA224;
		break;
	case TPM2_ECC_NIST_P256:
		size = ECC_P256_SECURITY_BITS;
		data_size = ECC_P256_PUBLIC_SIZE;
		hash = SMW_ATTR_HASH_SHA256;
		break;
	case TPM2_ECC_NIST_P384:
		size = ECC_P384_SECURITY_BITS;
		data_size = ECC_P384_PUBLIC_SIZE;
		hash = SMW_ATTR_HASH_SHA384;
		break;
	case TPM2_ECC_NIST_P521:
		size = ECC_P521_SECURITY_BITS;
		data_size = ECC_P521_PUBLIC_SIZE;
		hash = SMW_ATTR_HASH_SHA512;
		break;
	default:
		DBG_TRACE("Unknown ECC curve: 0x%04x\n", curve);
		rc = TSS2_TCTI_RC_IO_ERROR;
		goto end;
	}

	if (security_size)
		*security_size = size;

	if (public_data_size)
		*public_data_size = data_size;

	if (hash_attr)
		*hash_attr = hash;

	rc = TSS2_RC_SUCCESS;

end:
	DBG_TRACE_COND(rc != TSS2_RC_SUCCESS, "return error: 0x%08x\n", rc);
	return rc;
}

uint32_t extract_ecdsa_signature(unsigned char *signature_buffer,
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
	if (!signature_length || signature_length % 2) {
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
	case ECC_P224_COORD_SIZE:
	case ECC_P256_COORD_SIZE:
	case ECC_P384_COORD_SIZE:
	case ECC_P521_COORD_SIZE:
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
