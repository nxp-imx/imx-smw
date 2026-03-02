// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <stdint.h>
#include <string.h>

#include <tss2/tss2_mu.h>

#include "smw_crypto.h"
#include "common.h"
#include "crypto.h"
#include "builtin_macros.h"
#include "trace.h"

uint8_t proof_owner[TPM2_SHA384_DIGEST_SIZE] = {
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
	0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
	0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24,
	0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30
};

uint8_t proof_platform[TPM2_SHA384_DIGEST_SIZE] = {
	0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c,
	0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
	0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44,
	0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50
};

uint8_t proof_endorsement[TPM2_SHA384_DIGEST_SIZE] = {
	0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c,
	0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
	0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64,
	0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70
};

tcti_smw_object_t *find_object_by_handle(tcti_smw_context_t *ctx,
					 uint32_t handle)
{
	uint8_t i = 0;

	if (handle == 0)
		goto end;

	for (; i < SMW_MAX_OBJECTS; i++) {
		if (ctx->objects[i].active &&
		    ctx->objects[i].handle == handle) {
			return &ctx->objects[i];
		}
	}

end:
	DBG_TRACE("Object handle 0x%08X not found!\n", handle);
	return NULL;
}

uint32_t smw_object_alloc(tcti_smw_context_t *ctx, uint32_t *handle,
			  TPMA_OBJECT attributes, unsigned int key_id,
			  TPMI_RH_HIERARCHY hierarchy,
			  TPM2B_PUBLIC *public_area)
{
	TSS2_RC rc = TSS2_RC_SUCCESS;
	uint8_t i = 0;
	TPM2_HANDLE h = 0;

	for (; i < SMW_MAX_OBJECTS; i++) {
		if (!ctx->objects[i].active) {
			/* Find an unused handle */
			do {
				h = TPM2_TRANSIENT_FIRST +
				    ctx->next_transient_id++;
			} while (find_object_by_handle(ctx, h));

			ctx->objects[i].active = true;
			ctx->objects[i].handle = h;
			ctx->objects[i].smw_key_id = key_id;
			ctx->objects[i].attributes = attributes;
			ctx->objects[i].is_persistent =
				!(attributes & TPMA_OBJECT_STCLEAR) &&
				(attributes & TPMA_OBJECT_FIXEDTPM);
			ctx->objects[i].hierarchy = hierarchy;
			ctx->objects[i].public_area = *public_area;
			*handle = h;

			DBG_TRACE("Object registered:\n");
			DBG_TRACE("  Handle: 0x%08x\n", ctx->objects[i].handle);
			DBG_TRACE("  SMW ID: %u\n", ctx->objects[i].smw_key_id);
			DBG_TRACE("  Is persistent: %s\n",
				  ctx->objects[i].is_persistent ? "YES" : "NO");
			goto end;
		}
	}
	rc = TSS2_TCTI_RC_MEMORY;

end:
	return rc;
}

uint32_t calculate_object_name(const TPM2B_PUBLIC *public, TPM2B_NAME *name)
{
	TSS2_RC rc = TSS2_TCTI_RC_MEMORY;
	enum smw_status_code smw_status = SMW_STATUS_OK;
	struct smw_hash_args hash_args = { 0 };
	smw_hash_algo_t hash_name = SMW_HASH_ALGO_NAME_NONE;
	uint8_t *marshal_buffer = NULL;
	size_t marshal_size = 0;
	size_t offset = 0;
	uint16_t digest_size = 0;

	if (!public || !name)
		goto end;

	/* Get hash algorithm info */
	rc = map_hash_info(public->publicArea.nameAlg, &digest_size, &hash_name,
			   NULL);
	if (rc != TSS2_RC_SUCCESS)
		goto end;

	/* Marshal TPMT_PUBLIC */
	rc = Tss2_MU_TPMT_PUBLIC_Marshal(&public->publicArea, NULL, 0,
					 &marshal_size);
	if (rc != TSS2_RC_SUCCESS)
		goto end;

	marshal_buffer = malloc(marshal_size);
	if (!marshal_buffer) {
		rc = TSS2_TCTI_RC_MEMORY;
		goto end;
	}

	rc = Tss2_MU_TPMT_PUBLIC_Marshal(&public->publicArea, marshal_buffer,
					 marshal_size, &offset);
	if (rc != TSS2_RC_SUCCESS)
		goto end;

	/* Name = hashAlg || Hash(TPMT_PUBLIC) */
	if ((sizeof(TPMI_ALG_HASH) + digest_size) > UINT16_MAX) {
		DBG_TRACE("Name size too large: %lu\n",
			  sizeof(TPMI_ALG_HASH) + digest_size);
		rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	if (ADD_OVERFLOW(sizeof(TPMI_ALG_HASH), digest_size, &name->size)) {
		rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	/* Store hash algorithm ID */
	offset = 0;
	rc = Tss2_MU_UINT16_Marshal(public->publicArea.nameAlg, name->name,
				    sizeof(name->name), &offset);
	if (rc != TSS2_RC_SUCCESS)
		goto end;

	/* Compute hash of marshaled public area */
	hash_args.algo_name = hash_name;
	hash_args.input = marshal_buffer;
	hash_args.input_length = (uint32_t)marshal_size;
	hash_args.output = &name->name[offset];
	hash_args.output_length = digest_size;

	smw_status = smw_hash(&hash_args);
	if (smw_status != SMW_STATUS_OK) {
		DBG_TRACE("Failed to compute object name hash: %d\n",
			  smw_status);
		rc = smw_rc_to_tcti_rc(smw_status);
		goto end;
	}

	rc = TSS2_RC_SUCCESS;

end:
	free(marshal_buffer);

	DBG_TRACE_COND(rc != TSS2_RC_SUCCESS, "return error: 0x%08x\n", rc);
	return rc;
}

uint32_t get_hierarchy_proof_key(TPMI_RH_HIERARCHY hierarchy, uint8_t *proof)
{
	TSS2_RC rc = TSS2_RC_SUCCESS;

	if (!proof) {
		rc = TSS2_TCTI_RC_BAD_REFERENCE;
		goto end;
	}

	/* Select proof based on hierarchy */
	switch (hierarchy) {
	case TPM2_RH_OWNER:
		memcpy(proof, proof_owner, TPM2_SHA256_DIGEST_SIZE);
		break;
	case TPM2_RH_PLATFORM:
		memcpy(proof, proof_platform, TPM2_SHA256_DIGEST_SIZE);
		break;
	case TPM2_RH_ENDORSEMENT:
		memcpy(proof, proof_endorsement, TPM2_SHA256_DIGEST_SIZE);
		break;
	case TPM2_RH_NULL:
		/* No key for NULL hierarchy */
		break;
	default:
		DBG_TRACE("Unknown hierarchy: 0x%08x\n", hierarchy);
		rc = TSS2_TCTI_RC_BAD_VALUE;
		break;
	}

end:
	DBG_TRACE_COND(rc != TSS2_RC_SUCCESS, "return error: 0x%08x\n", rc);
	return rc;
}
