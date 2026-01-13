/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2026 NXP
 */

#ifndef __COMMANDS_H__
#define __COMMANDS_H__

#include "common.h"

/**
 * handle_startup() - Process TPM2_Startup command.
 * @ctx:      Pointer to the SMW TCTI context structure.
 * @tag:      TPM structure tag from the command header.
 * @cmd:      Pointer to the command buffer containing the full TPM command.
 * @cmd_size: Size of the command buffer in bytes.
 *
 * This function handles the TPM2_Startup command which initializes the TPM.
 * It verifies that the TPM has not already been initialized, validates the
 * startup type parameter (must be TPM2_SU_CLEAR), and sets the initialized
 * flag in the context upon success.
 *
 * Return:
 * uint32_t value indicating success or the corresponding error code.
 */
uint32_t handle_startup(tcti_smw_context_t *ctx, uint16_t tag,
			const uint8_t *cmd, size_t cmd_size);

/**
 * handle_shutdown() - Process TPM2_Shutdown command.
 * @ctx:      Pointer to the SMW TCTI context structure.
 * @tag:      TPM structure tag from the command header.
 * @cmd:      Pointer to the command buffer containing the full TPM command.
 * @cmd_size: Size of the command buffer in bytes.
 *
 * This function handles the TPM2_Shutdown command which prepares the TPM
 * for shutdown. It validates the shutdown type parameter (must be TPM2_SU_CLEAR)
 * and clears the initialized flag in the context upon success.
 *
 * Return:
 * uint32_t value indicating success or the corresponding error code.
 */
uint32_t handle_shutdown(tcti_smw_context_t *ctx, uint16_t tag,
			 const uint8_t *cmd, size_t cmd_size);
#endif /* __COMMANDS_H__ */
