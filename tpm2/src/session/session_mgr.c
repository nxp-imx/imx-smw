// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <string.h>

#include "session.h"
#include "crypto.h"
#include "trace.h"

tcti_smw_session_t *find_session_by_handle(tcti_smw_context_t *ctx,
					   uint32_t handle)
{
	uint8_t i = 0;

	if (!handle)
		goto end;

	for (; i < SMW_MAX_SESSIONS; i++) {
		if (ctx->sessions[i].active &&
		    ctx->sessions[i].handle == handle) {
			return &ctx->sessions[i];
		}
	}

end:
	DBG_TRACE("Session handle 0x%08X not found!\n", handle);
	return NULL;
}

uint32_t smw_session_alloc(tcti_smw_context_t *ctx, uint32_t *handle,
			   TPM2B_NONCE nonce,
			   start_auth_session_params_t *params)
{
	TSS2_RC rc = TSS2_TCTI_RC_MEMORY;
	uint8_t i = 0;
	uint16_t key_size = 0;

	for (; i < SMW_MAX_SESSIONS; i++) {
		if (!ctx->sessions[i].active) {
			uint32_t h = SMW_SESSION_HANDLE_BASE +
				     ctx->next_session_id++;
			ctx->sessions[i].active = true;
			ctx->sessions[i].handle = h;
			ctx->sessions[i].type = params->session_type;
			ctx->sessions[i].auth_hash = params->auth_hash;
			ctx->sessions[i].nonce = nonce;

			DBG_TRACE("ctx->sessions[%d].type: %d\n"
				  "ctx->sessions[%d].auth_hash: %d\n"
				  "ctx->sessions[%d].active: %d\n"
				  "ctx->next_session_id: %d\n",
				  i, ctx->sessions[i].type, i,
				  ctx->sessions[i].auth_hash, i,
				  ctx->sessions[i].active,
				  ctx->next_session_id);

			*handle = h;
			if (params->tpmKey == TPM2_RH_NULL &&
			    params->bind == TPM2_RH_NULL) {
				/* Simple case : empty session_key */

				rc = map_hash_info(params->auth_hash, &key_size,
						   NULL);

				if (rc != TSS2_RC_SUCCESS)
					goto end;

				ctx->sessions[i].session_key_size = key_size;

				memset(ctx->sessions[i].session_key, 0,
				       ctx->sessions[i].session_key_size);

				DBG_TRACE("Session created with empty key");
				DBG_TRACE(" (tpmKey=NULL, bind=NULL)\n");
			} else {
				/*
				 * Complex case: use KDFa
				 * authValue = authValue of entity bind (or empty)
				 * salt = decrypted encryptedSalt (or empty)
				 */
				DBG_TRACE("Session with bind/salt");
				DBG_TRACE(" NOT IMPLEMENTED YET\n");

				rc = TSS2_TCTI_RC_NOT_IMPLEMENTED;
				goto end;
			}
			goto end;
		}
	}

end:
	return rc;
}
