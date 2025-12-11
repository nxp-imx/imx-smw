/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2026 NXP
 */

#ifndef __TCTI_SMW_H__
#define __TCTI_SMW_H__

#include <tss2/tss2_tcti.h>

/**
 * Tss2_Tcti_Smw_Init() - Initialize a TCTI context for the SMW backend.
 *
 * @tcti_ctx: Pointer to the TCTI context structure to initialize. If NULL,
 *            the function only calculates the size required for the context.
 * @size:     Pointer to a size_t variable. On input, the allocated size of
 *            tcti_ctx. On output, the required size if tcti_ctx is NULL.
 * @conf:     Optional configuration string. May contain SMW-specific settings
 *            such as choice of ELE backend or software fallback.
 *
 * This function prepares the TCTI context for use by the TPM2-TSS stack
 * to communicate with the SMW (Secure Middleware for NXP ELE) backend.
 * It sets up internal state and optionally parses the configuration string.
 *
 * If tcti_ctx is NULL, the function returns the size of memory required to
 * allocate a context. Otherwise, it initializes the context in place.
 *
 * Return:
 * TSS2_RC code:
 * - TSS2_RC_SUCCESS: Context initialized successfully.
 * - TSS2_TCTI_RC_BAD_CONTEXT: Provided tcti_ctx is invalid.
 * - TSS2_TCTI_RC_NOT_IMPLEMENTED: A required feature is not supported.
 */
TSS2_RC
Tss2_Tcti_Smw_Init(TSS2_TCTI_CONTEXT * /* Without this comment clang-format */
			   /*does not meet the checkpatch requirement. */
			   tcti_ctx,
		   size_t *size, const char *conf);

/**
 * Tss2_Tcti_Info() - Return static information about the SMW TCTI.
 *
 * This function provides a pointer to a constant TSS2_TCTI_INFO structure
 * describing the SMW TCTI. The information includes the supported TCTI
 * API version, a helper, the TCTI name, the description and a pointer to
 * the TCTI Init function to use.
 *
 * This function does not modify any state and can be called at any time
 * to query the SMW TCTI information.
 *
 * Return:
 * Pointer to a constant TSS2_TCTI_INFO structure.
 */
const TSS2_TCTI_INFO *Tss2_Tcti_Info(void);

#endif /* __TCTI_SMW_H__ */
