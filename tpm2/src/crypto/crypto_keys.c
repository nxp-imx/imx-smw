// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <stdint.h>

#include "common.h"
#include "trace.h"

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
			  TPMI_RH_HIERARCHY hierarchy)
{
	TSS2_RC rc = TSS2_RC_SUCCESS;
	uint8_t i = 0;

	for (; i < SMW_MAX_OBJECTS; i++) {
		if (!ctx->objects[i].active) {
			TPM2_HANDLE h =
				TPM2_TRANSIENT_FIRST + ctx->next_transient_id++;

			ctx->objects[i].active = true;
			ctx->objects[i].handle = h;
			ctx->objects[i].smw_key_id = key_id;
			ctx->objects[i].attributes = attributes;
			ctx->objects[i].is_persistent =
				!(attributes & TPMA_OBJECT_STCLEAR) &&
				(attributes & TPMA_OBJECT_FIXEDTPM);
			;
			ctx->objects[i].hierarchy = hierarchy;
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
