// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <string.h>

#include "tcti_smw.h"

#include "compiler.h"

#include "common.h"
#include "trace.h"

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

static uint32_t tcti_smw_transmit(TSS2_TCTI_CONTEXT *tcti_ctx, size_t size,
				  const uint8_t *cmd)
{
	(void)tcti_ctx;
	(void)size;
	(void)cmd;
	return TSS2_TCTI_RC_NOT_IMPLEMENTED;
}

static uint32_t tcti_smw_receive(TSS2_TCTI_CONTEXT *tcti_ctx, size_t *size,
				 uint8_t *response, int32_t timeout)
{
	(void)tcti_ctx;
	(void)size;
	(void)response;
	(void)timeout;
	return TSS2_TCTI_RC_NOT_IMPLEMENTED;
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
	if (!tcti_ctx) {
		*size = sizeof(tcti_smw_context_t);
		return TSS2_RC_SUCCESS;
	}

	memset(tcti_ctx, 0, sizeof(tcti_smw_context_t));
	tcti_smw_context_t *smw = (tcti_smw_context_t *)tcti_ctx;
	tcti_context_t *tcti_common = tcti_smw_down_cast(smw);

	tcti_smw_init_context_data(tcti_common);

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
