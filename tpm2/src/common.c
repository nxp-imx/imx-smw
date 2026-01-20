// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#include <tss2/tss2_mu.h>

#include "smw_status.h"

#include "common.h"

uint32_t tcti_common_transmit_checks(tcti_context_t *tcti_common,
				     const uint8_t *command_buffer,
				     uint64_t magic)
{
	if (!command_buffer || !tcti_common)
		return TSS2_TCTI_RC_BAD_REFERENCE;

	if (TSS2_TCTI_MAGIC(tcti_common) != magic)
		return TSS2_TCTI_RC_BAD_CONTEXT;

	if (tcti_common->state != TCTI_SMW_STATE_TRANSMIT)
		return TSS2_TCTI_RC_BAD_SEQUENCE;

	return TSS2_RC_SUCCESS;
}

uint32_t tcti_common_receive_checks(tcti_context_t *tcti_common,
				    size_t *response_size, uint64_t magic)
{
	if (!response_size || !tcti_common)
		return TSS2_TCTI_RC_BAD_REFERENCE;

	if (TSS2_TCTI_MAGIC(tcti_common) != magic)
		return TSS2_TCTI_RC_BAD_CONTEXT;

	if (tcti_common->state != TCTI_SMW_STATE_RECEIVE)
		return TSS2_TCTI_RC_BAD_SEQUENCE;

	return TSS2_RC_SUCCESS;
}

TSS2_RC smw_rc_to_tcti_rc(int smw_rc)
{
	switch (smw_rc) {
	case SMW_STATUS_OK:
		return TSS2_RC_SUCCESS;
	case SMW_STATUS_INVALID_PARAM:
		return TSS2_TCTI_RC_BAD_VALUE;
	case SMW_STATUS_ALLOC_FAILURE:
		return TSS2_TCTI_RC_MEMORY;
	case SMW_STATUS_OPERATION_NOT_SUPPORTED:
	case SMW_STATUS_OPERATION_NOT_CONFIGURED:
		return TSS2_TCTI_RC_NOT_IMPLEMENTED;
	case SMW_STATUS_SUBSYSTEM_NOT_CONFIGURED:
	case SMW_STATUS_SUBSYSTEM_FAILURE:
		return TSS2_TCTI_RC_IO_ERROR;
	case SMW_STATUS_LIBRARY_ALREADY_INIT:
	case SMW_STATUS_SIGNATURE_INVALID:
		return TSS2_TCTI_RC_BAD_SEQUENCE;
	case SMW_STATUS_OUTPUT_TOO_SHORT:
		return TSS2_TCTI_RC_INSUFFICIENT_BUFFER;
	default:
		return TSS2_TCTI_RC_GENERAL_FAILURE;
	}
}
