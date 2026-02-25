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
	TPM2_HANDLE session_handle = 0;

	if (params->session_type == TPM2_SE_HMAC) {
		if (ctx->next_hmac_session_id == UINT8_MAX) {
			rc = TSS2_TCTI_RC_BAD_VALUE;
			goto end;
		}

		session_handle =
			TPM2_HMAC_SESSION_FIRST + ctx->next_hmac_session_id++;
	} else if (params->session_type == TPM2_SE_POLICY) {
		if (ctx->next_policy_session_id == UINT8_MAX) {
			rc = TSS2_TCTI_RC_BAD_VALUE;
			goto end;
		}

		session_handle = TPM2_POLICY_SESSION_FIRST +
				 ctx->next_policy_session_id++;
	} else {
		rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	for (; i < SMW_MAX_SESSIONS; i++) {
		if (!ctx->sessions[i].active) {
			ctx->sessions[i].handle = session_handle;
			ctx->sessions[i].active = true;
			ctx->sessions[i].saved = false;
			ctx->sessions[i].type = params->session_type;
			ctx->sessions[i].auth_hash = params->auth_hash;
			ctx->sessions[i].nonce = nonce;

			DBG_TRACE("ctx->sessions[%d].type: %d\n"
				  "ctx->sessions[%d].auth_hash: %d\n"
				  "ctx->sessions[%d].active: %d\n"
				  "ctx->sessions[%d].handle: 0x%08x\n",
				  i, ctx->sessions[i].type, i,
				  ctx->sessions[i].auth_hash, i,
				  ctx->sessions[i].active, i, session_handle);

			*handle = session_handle;
			if (params->tpmKey == TPM2_RH_NULL &&
			    params->bind == TPM2_RH_NULL) {
				/* Simple case : empty session_key */

				rc = map_hash_info(params->auth_hash, &key_size,
						   NULL, NULL);

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
