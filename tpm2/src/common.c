// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#include <tss2/tss2_mu.h>

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
