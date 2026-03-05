// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <string.h>

#include "smw_crypto.h"
#include "smw_osal.h"
#include "tcti_smw.h"

#include "compiler.h"

#include "common.h"
#include "trace.h"
#include "commands.h"
#include "utils.h"

static void init_pcr_bank(tcti_smw_context_t *ctx)
{
	/* Automotive-Thin, only 1 bank SHA-256
	 * Initialize PCR bank supported
	 */
	ctx->pcr_bank_count = 1;

	/* Bank SHA256 */
	ctx->pcr_banks[0].hash_alg = TPM2_ALG_SHA256;
	ctx->pcr_banks[0].digest_size = TPM2_SHA256_DIGEST_SIZE;

	/* Initialize PCR0 to 0 */
	memset(ctx->pcr_banks[0].pcr[0], 0, TPM2_SHA256_DIGEST_SIZE);

	ctx->pcr_update_counter = 0;

	DBG_TRACE("PCR banks initialized (Automotive-Thin Profile):\n");
	DBG_TRACE("  - 1 bank (SHA-256)\n");
	DBG_TRACE("  - PCR 0 supported\n");
}

/* tcti_smw_down_cast() - Down-cast SMW TCTI context to common context.
 * @tcti_smw: Pointer to the SMW TCTI context structure.
 *
 * This function performs a down-cast operation from the SMW-specific TCTI
 * context to the common TCTI context structure defined in the tcti-common
 * module.
 *
 * Return:
 * Pointer to the TSS2_TCTI_COMMON_CONTEXT structure.
 */
static tcti_context_t *tcti_smw_down_cast(tcti_smw_context_t *tcti_smw)
{
	if (!tcti_smw)
		return NULL;

	return &tcti_smw->common;
}

/**
 * tcti_smw_context_cast() - Up-cast opaque TCTI context to SMW TCTI context.
 * @tcti_ctx: Pointer to the opaque TSS2_TCTI_CONTEXT structure.
 *
 * This function performs an up-cast operation from the opaque TSS2_TCTI_CONTEXT
 * type to the SMW-specific TCTI context structure. It allows access to the
 * SMW-specific fields and functionality.
 *
 * Return:
 * Pointer to the tcti_smw_context_t structure, or NULL if tcti_ctx is NULL.
 */
static tcti_smw_context_t *tcti_smw_context_cast(TSS2_TCTI_CONTEXT *tcti_ctx)
{
	if (!tcti_ctx)
		return NULL;

	return (tcti_smw_context_t *)tcti_ctx;
}

static TSS2_RC tcti_smw_transmit(TSS2_TCTI_CONTEXT *tcti_ctx, size_t size,
				 const uint8_t *cmd)
{
	TSS2_RC rc = TSS2_TCTI_RC_GENERAL_FAILURE;
	tpm_smw_header_t header = { 0 };
	tcti_smw_context_t *tcti_smwtpm = tcti_smw_context_cast(tcti_ctx);
	tcti_context_t *tcti_common = tcti_smw_down_cast(tcti_smwtpm);

	rc = tcti_common_transmit_checks(tcti_common, cmd, SMW_TCTI_MAGIC);
	if (rc != TSS2_RC_SUCCESS)
		goto end;

	rc = header_unmarshal(cmd, &header);
	if (rc != TSS2_RC_SUCCESS)
		goto end;

	if (header.size != size) {
		DBG_TRACE("Buffer size parameter: %zu\n", size);
		DBG_TRACE("TPM2 command header size field: %d\n", header.size);
		rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	DBG_TRACE("Sending command with TPM_CC 0x%x and size %d\n", header.code,
		  header.size);

	DBG_TRACE("Command\n");
	DBG_BUF_HEX(cmd, size);

	tcti_common->state = TCTI_SMW_STATE_RECEIVE;
	switch (header.code) {
	case TPM2_CC_Startup:
		rc = handle_startup(tcti_smwtpm, header.tag, cmd, header.size);
		break;
	case TPM2_CC_Shutdown:
		rc = handle_shutdown(tcti_smwtpm, header.tag, cmd, header.size);
		break;
	case TPM2_CC_Hash:
		rc = handle_hash(tcti_smwtpm, header.tag, cmd, header.size);
		break;
	case TPM2_CC_StartAuthSession:
		rc = handle_startauthsession(tcti_smwtpm, header.tag, cmd,
					     header.size);
		break;
	case TPM2_CC_ContextSave:
		rc = handle_contextsave(tcti_smwtpm, header.tag, cmd,
					header.size);
		break;
	case TPM2_CC_HMAC:
		rc = handle_hmac(tcti_smwtpm, header.tag, cmd, header.size);
		break;
	case TPM2_CC_FlushContext:
		rc = handle_flushcontext(tcti_smwtpm, header.tag, cmd,
					 header.size);
		break;
	case TPM2_CC_GetCapability:
		rc = handle_getcapability(tcti_smwtpm, header.tag, cmd,
					  header.size);
		break;
	case TPM2_CC_CreatePrimary:
		rc = handle_createprimary(tcti_smwtpm, header.tag, cmd,
					  header.size);
		break;
	case TPM2_CC_ContextLoad:
		rc = handle_contextload(tcti_smwtpm, header.tag, cmd,
					header.size);
		break;
	case TPM2_CC_GetRandom:
		rc = handle_getrandom(tcti_smwtpm, header.tag, cmd,
				      header.size);
		break;
	case TPM2_CC_ReadPublic:
		rc = handle_readpublic(tcti_smwtpm, header.tag, cmd,
				       header.size);
		break;
	case TPM2_CC_Create:
		rc = handle_create(tcti_smwtpm, header.tag, cmd, header.size);
		break;
	case TPM2_CC_Load:
		rc = handle_load(tcti_smwtpm, header.tag, cmd, header.size);
		break;
	case TPM2_CC_Sign:
		rc = handle_sign(tcti_smwtpm, header.tag, cmd, header.size);
		break;
	case TPM2_CC_VerifySignature:
		rc = handle_verifysignature(tcti_smwtpm, header.tag, cmd,
					    header.size);
		break;
	case TPM2_CC_PCR_Read:
		rc = handle_pcrread(tcti_smwtpm, header.tag, cmd, header.size);
		break;
	case TPM2_CC_PCR_Extend:
		rc = handle_pcrextend(tcti_smwtpm, header.tag, cmd,
				      header.size);
		break;
	case TPM2_CC_PCR_Event:
		rc = handle_pcrevent(tcti_smwtpm, header.tag, cmd, header.size);
		break;
	case TPM2_CC_PCR_Reset:
		rc = handle_pcrreset(tcti_smwtpm, header.tag, cmd, header.size);
		break;
	case TPM2_CC_PCR_Allocate:
		rc = handle_pcrallocate(tcti_smwtpm, header.tag, cmd,
					header.size);
		break;
	default:
		/* Unsupported command */
		DBG_TRACE("Unsupported TPM command: 0x%x", header.code);
		rc = build_rc_response(tcti_smwtpm, TPM_HEADER_SIZE, header.tag,
				       TPM2_RC_COMMAND_CODE);
		goto end;
	}

end:
	return rc;
}

static uint32_t tcti_smw_receive(TSS2_TCTI_CONTEXT *tcti_ctx, size_t *size,
				 uint8_t *response, int32_t timeout)
{
	(void)timeout;
	TSS2_RC rc = TSS2_TCTI_RC_GENERAL_FAILURE;
	tcti_smw_context_t *tcti_smwtpm = tcti_smw_context_cast(tcti_ctx);
	tcti_context_t *tcti_common = tcti_smw_down_cast(tcti_smwtpm);

	rc = tcti_common_receive_checks(tcti_common, size, SMW_TCTI_MAGIC);
	if (rc != TSS2_RC_SUCCESS)
		goto end;

	if (!response) {
		*size = tcti_smwtpm->resp_size;
		goto end;
	}

	if (!tcti_smwtpm->resp_buf) {
		DBG_TRACE("Response buffer is NULL\n");
		rc = TSS2_TCTI_RC_NO_CONNECTION;
		goto end;
	}

	if (*size < tcti_smwtpm->resp_size) {
		*size = tcti_smwtpm->resp_size;
		rc = TSS2_TCTI_RC_INSUFFICIENT_BUFFER;
		goto end;
	}

	memcpy(response, tcti_smwtpm->resp_buf, tcti_smwtpm->resp_size);

	*size = tcti_smwtpm->resp_size;

	/* after read, free response */
	free_resp(tcti_smwtpm);

	DBG_TRACE("Response\n");
	DBG_BUF_HEX(response, *size);
	tcti_common->state = TCTI_SMW_STATE_TRANSMIT;

end:
	return rc;
}

static void tcti_smw_finalize(TSS2_TCTI_CONTEXT *tcti_ctx)
{
	/* no-op */
	(void)tcti_ctx;
}

static uint32_t tcti_smw_cancel(TSS2_TCTI_CONTEXT *tcti_ctx)
{
	/* Linux driver doesn't expose a mechanism to cancel commands. */
	(void)tcti_ctx;
	return TSS2_TCTI_RC_NOT_IMPLEMENTED;
}

static uint32_t tcti_smw_get_poll_handles(TSS2_TCTI_CONTEXT *tcti_ctx,
					  TSS2_TCTI_POLL_HANDLE *handles,
					  size_t *num_handles)
{
	(void)tcti_ctx;
	(void)handles;
	(void)num_handles;
	return TSS2_TCTI_RC_NOT_IMPLEMENTED;
}

static uint32_t tcti_smw_set_locality(TSS2_TCTI_CONTEXT *tcti_ctx,
				      uint8_t locality)
{
	(void)tcti_ctx;
	(void)locality;
	return TSS2_TCTI_RC_NOT_IMPLEMENTED;
}

static uint32_t tcti_make_sticky_not_implemented(TSS2_TCTI_CONTEXT *tctiContext,
						 TPM2_HANDLE *handle,
						 uint8_t sticky)
{
	(void)tctiContext;
	(void)handle;
	(void)sticky;
	return TSS2_TCTI_RC_NOT_IMPLEMENTED;
}

static void tcti_smw_init_context_data(tcti_context_t *tcti_common)
{
	TSS2_TCTI_MAGIC(tcti_common) = SMW_TCTI_MAGIC;
	TSS2_TCTI_VERSION(tcti_common) = TCTI_VERSION;
	TSS2_TCTI_TRANSMIT(tcti_common) = tcti_smw_transmit;
	TSS2_TCTI_RECEIVE(tcti_common) = tcti_smw_receive;
	TSS2_TCTI_FINALIZE(tcti_common) = tcti_smw_finalize;
	TSS2_TCTI_CANCEL(tcti_common) = tcti_smw_cancel;
	TSS2_TCTI_GET_POLL_HANDLES(tcti_common) = tcti_smw_get_poll_handles;
	TSS2_TCTI_SET_LOCALITY(tcti_common) = tcti_smw_set_locality;
	TSS2_TCTI_MAKE_STICKY(tcti_common) = tcti_make_sticky_not_implemented;
	tcti_common->state = TCTI_SMW_STATE_TRANSMIT;
	memset(&tcti_common->header, 0, sizeof(tcti_common->header));
}

__export TSS2_RC Tss2_Tcti_Smw_Init(TSS2_TCTI_CONTEXT *tcti_ctx, size_t *size,
				    const char *conf)
{
	(void)conf;
	enum smw_status_code status = SMW_STATUS_OK;
	tcti_smw_context_t *smw = (tcti_smw_context_t *)tcti_ctx;
	tcti_context_t *tcti_common = tcti_smw_down_cast(smw);

	if (!tcti_ctx) {
		*size = sizeof(tcti_smw_context_t);
		return TSS2_RC_SUCCESS;
	}

	memset(tcti_ctx, 0, sizeof(tcti_smw_context_t));

	tcti_smw_init_context_data(tcti_common);

	/*
	 * 1. Init SMW middleware
	 * This function will read /etc/opt/smw.conf and load ELE
	 */
	status = smw_osal_lib_init();
	if (status != SMW_STATUS_OK) {
		DBG_TRACE("Error: Impossible to initialize SMW: %d\n", status);
		return smw_rc_to_tcti_rc(status);
	}

	init_pcr_bank(smw);

	smw->initialized = 1;

	DBG_TRACE("TCTI SMW loaded.\n");

	return TSS2_RC_SUCCESS;
}

/* public info structure */
const TSS2_TCTI_INFO tss2_tcti_smw_info = {
	.version = TCTI_VERSION,
	.name = "smw",
	.description =
		"TCTI module for communication with the SMW API from NXP.",
	.config_help = "Usage: --tcti=smw. No config needed.",
	.init = Tss2_Tcti_Smw_Init,
};

__export const TSS2_TCTI_INFO *Tss2_Tcti_Info(void)
{
	return &tss2_tcti_smw_info;
}
