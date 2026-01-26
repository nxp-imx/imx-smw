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

/**
 * handle_hash() - Process TPM2_Hash command.
 * @ctx:      Pointer to the SMW TCTI context structure.
 * @tag:      TPM structure tag from the command header.
 * @cmd:      Pointer to the command buffer containing the full TPM command.
 * @cmd_size: Size of the command buffer in bytes.
 *
 * This function handles the TPM2_Hash command which computes a hash digest
 * of the provided data. It unmarshals the input parameters (data buffer,
 * hash algorithm, and hierarchy), calls the SMW hash API to perform the
 * actual hash computation, and builds a TPM response containing the hash
 * digest and a validation ticket. Supports SHA1, SHA256, and SHA384 algorithms.
 *
 * Return:
 * uint32_t value indicating success or the corresponding error code.
 */
uint32_t handle_hash(tcti_smw_context_t *ctx, uint16_t tag, const uint8_t *cmd,
		     size_t cmd_size);

/**
 * handle_startauthsession() - Process TPM2_StartAuthSession command.
 * @ctx:      Pointer to the SMW TCTI context structure.
 * @tag:      TPM structure tag from the command header.
 * @cmd:      Pointer to the command buffer containing the full TPM command.
 * @cmd_size: Size of the command buffer in bytes.
 *
 * This function handles the TPM2_StartAuthSession command which establishes
 * an authorization session with the TPM. It unmarshals the session parameters,
 * generates a TPM nonce based on the specified hash algorithm size, allocates
 * a new session with a unique handle, and builds the response containing the
 * session handle and TPM nonce. The function ensures the TPM is initialized
 * before creating sessions.
 *
 * Return:
 * TSS2_RC_SUCCESS on successful session creation, or the corresponding error code.
 */
uint32_t handle_startauthsession(tcti_smw_context_t *ctx, uint16_t tag,
				 const uint8_t *cmd, size_t cmd_size);

/**
 * handle_contextsave() - Process TPM2_ContextSave command.
 * @ctx:      Pointer to the SMW TCTI context structure.
 * @tag:      TPM structure tag from the command header.
 * @cmd:      Pointer to the command buffer containing the full TPM command.
 * @cmd_size: Size of the command buffer in bytes.
 *
 * This function handles the TPM2_ContextSave command which saves the context
 * of a session or transient object for later restoration. It validates that
 * the handle can be saved (sessions or transient objects only), creates a
 * TPMS_CONTEXT structure with appropriate hierarchy and sequence number, and
 * builds a context blob containing the necessary information to restore the
 * context later. The function returns a marshaled TPMS_CONTEXT structure
 * in the response.
 *
 * Return:
 * TSS2_RC_SUCCESS on successful context save, or the corresponding error code.
 */
uint32_t handle_contextsave(tcti_smw_context_t *ctx, uint16_t tag,
			    const uint8_t *cmd, size_t cmd_size);

/**
 * handle_hmac - Process TPM2_CC_HMAC command
 *
 * @ctx:      TCTI SMW context containing response buffer
 * @tag:      TPM2 command tag (TPM2_ST_NO_SESSIONS or TPM2_ST_SESSIONS)
 * @cmd:      Command buffer containing marshaled TPM2_CC_HMAC parameters
 * @cmd_size: Size of command buffer in bytes
 *
 * This function implements the TPM2_CC_HMAC command handler which computes
 * an HMAC of the provided data using a loaded HMAC key or session key.
 *
 * Return: TSS2_RC_SUCCESS on success
 *         TPM2_RC_SIZE for marshaling errors
 *         TPM2_RC_HANDLE for invalid session handle
 *         TPM2_RC_MEMORY for allocation failures
 *         TPM2_RC_FAILURE for SMW operation failures
 */
uint32_t handle_hmac(tcti_smw_context_t *ctx, uint16_t tag, const uint8_t *cmd,
		     size_t cmd_size);

/**
 * handle_flushcontext() - Process TPM2_FlushContext command.
 * @ctx:      Pointer to the SMW TCTI context structure.
 * @tag:      TPM structure tag from the command header.
 * @cmd:      Pointer to the command buffer containing the full TPM command.
 * @cmd_size: Size of the command buffer in bytes.
 *
 * This function handles the TPM2_FlushContext command which removes a loaded
 * context (session or transient object) from TPM memory. It extracts the handle
 * to flush, determines if it's a session or transient object, and performs the
 * appropriate cleanup. For sessions, it clears the session data and marks it
 * as inactive. The command always returns success per TPM2 specification, even
 * if the handle doesn't exist or was already flushed.
 *
 * Return:
 * TSS2_RC_SUCCESS always (per TPM2 specification), with appropriate error code
 * only for command parsing failures.
 */
uint32_t handle_flushcontext(tcti_smw_context_t *ctx, uint16_t tag,
			     const uint8_t *cmd, size_t cmd_size);

/**
 * handle_getcapability - Process TPM2_CC_GetCapability command
 *
 * @ctx:      TCTI SMW context
 * @tag:      TPM2 command tag
 * @cmd:      Command buffer containing marshaled parameters
 * @cmd_size: Size of command buffer
 *
 * This function implements a minimal TPM2_CC_GetCapability handler.
 * Currently returns empty capability data for all requests.
 *
 * Command format:
 *   - capability:     TPM2_CAP (capability group to query)
 *   - property:       UINT32 (first property in group)
 *   - propertyCount:  UINT32 (number of properties to return)
 *
 * Response format:
 *   - moreData:       TPMI_YES_NO (more data available)
 *   - capabilityData: TPMS_CAPABILITY_DATA (requested capability data)
 *
 * Return: TSS2_RC_SUCCESS on success, error code otherwise
 */
uint32_t handle_getcapability(tcti_smw_context_t *ctx, uint16_t tag,
			      const uint8_t *cmd, size_t cmd_size);

/**
 * handle_createprimary() - Process TPM2_CreatePrimary command.
 * @ctx:      Pointer to the SMW TCTI context structure.
 * @tag:      TPM structure tag from the command header.
 * @cmd:      Pointer to the command buffer containing the full TPM command.
 * @cmd_size: Size of the command buffer in bytes.
 *
 * This function handles the TPM2_CreatePrimary command which creates a new
 * primary key in a specified hierarchy. It unmarshals the command parameters
 * including hierarchy handle, authorization session, sensitive
 * creation data, public template, outside info, and PCR selection. The function
 * validates the key type, configures appropriate SMW key generation
 * parameters, and calls the SMW API to generate the key. It builds a response
 * containing the object handle, public area, creation data, creation hash,
 * creation ticket, and object name.
 *
 * Return:
 * TSS2_RC_SUCCESS on successful key creation, or the corresponding error code
 */
uint32_t handle_createprimary(tcti_smw_context_t *ctx, uint16_t tag,
			      const uint8_t *cmd, size_t cmd_size);
#endif /* __COMMANDS_H__ */
