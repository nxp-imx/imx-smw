// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

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
		size = 224;
		data_size = 56;
		hash = SMW_ATTR_HASH_SHA224;
		break;
	case TPM2_ECC_NIST_P256:
		size = 256;
		data_size = 64;
		hash = SMW_ATTR_HASH_SHA256;
		break;
	case TPM2_ECC_NIST_P384:
		size = 384;
		data_size = 96;
		hash = SMW_ATTR_HASH_SHA384;
		break;
	case TPM2_ECC_NIST_P521:
		size = 521;
		data_size = 132;
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
