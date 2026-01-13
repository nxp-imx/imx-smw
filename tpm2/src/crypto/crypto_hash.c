// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include "crypto.h"
#include "trace.h"

uint32_t map_hash_info(TPMI_ALG_HASH hash_alg, uint16_t *digest_size,
		       smw_hash_algo_t *smw_name)
{
	TSS2_RC rc = TSS2_TCTI_RC_BAD_VALUE;
	uint16_t size = 0;
	smw_hash_algo_t name = SMW_HASH_ALGO_NAME_NONE;

	switch (hash_alg) {
	case TPM2_ALG_SHA1:
		size = TPM2_SHA1_DIGEST_SIZE;
		name = SMW_HASH_ALGO_NAME_SHA1;
		break;
	case TPM2_ALG_SHA256:
		size = TPM2_SHA256_DIGEST_SIZE;
		name = SMW_HASH_ALGO_NAME_SHA256;
		break;
	case TPM2_ALG_SHA384:
		size = TPM2_SHA384_DIGEST_SIZE;
		name = SMW_HASH_ALGO_NAME_SHA384;
		break;
	case TPM2_ALG_SHA512:
		size = TPM2_SHA512_DIGEST_SIZE;
		name = SMW_HASH_ALGO_NAME_SHA512;
		break;
	default:
		DBG_TRACE("Unknown hash algorithm 0x%04x\n", hash_alg);
		goto end;
	}

	if (digest_size)
		*digest_size = size;

	if (smw_name)
		*smw_name = name;

	rc = TSS2_RC_SUCCESS;

end:
	DBG_TRACE_COND(rc != TSS2_RC_SUCCESS, "return error: 0x%08x\n", rc);
	return rc;
}
