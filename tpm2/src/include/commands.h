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

/**
 * handle_contextload() - Handle TPM2_ContextLoad command
 * @ctx:      Pointer to the SMW TCTI context structure.
 * @tag:      TPM structure tag from the command header.
 * @cmd:      Pointer to the command buffer containing the full TPM command.
 * @cmd_size: Size of the command buffer in bytes.
 *
 * Restores a previously saved TPM context (session or transient object) from
 * a TPMS_CONTEXT structure. The context must have been saved earlier using
 * TPM2_ContextSave.
 *
 * Context Blob Format:
 * - Session: smw_session_blob_t (handle, type, auth_hash, metadata)
 * - Object:  smw_object_blob_t (handle, smw_key_id, hierarchy, attributes)
 *
 * Handle Allocation:
 * - Sessions: Restored to original handle (0x02000000-0x03FFFFFF)
 * - Objects:  Restored to original handle (0x80000000-0x80000002)
 *
 * TPM2 Spec Reference:
 * - Part 3, Section 28.2: TPM2_ContextLoad
 * - Part 2, Section 14.6: Context Management
 *
 * Return:
 * - TSS2_RC_SUCCESS: Context successfully loaded
 * - TPM2_RC_SIZE: Invalid TPMS_CONTEXT structure
 * - TPM2_RC_VALUE: Invalid context blob size or content
 */
uint32_t handle_contextload(tcti_smw_context_t *ctx, uint16_t tag,
			    const uint8_t *cmd, size_t cmd_size);

/**
 * handle_getrandom() - Process TPM2_GetRandom command.
 * @ctx:      Pointer to the SMW TCTI context structure.
 * @tag:      TPM structure tag from the command header.
 * @cmd:      Pointer to the command buffer containing the full TPM command.
 * @cmd_size: Size of the command buffer in bytes.
 *
 * This function handles the TPM2_GetRandom command which generates random
 * bytes using the TPM's random number generator. It unmarshals the number
 * of bytes requested, validates and limits the request to the maximum TPM
 * capacity (TPM2B_DIGEST buffer size), generates random data through the
 * SMW RNG API backed by the ELE subsystem, and builds a response containing
 * the generated random bytes.
 *
 * Return:
 * TSS2_RC_SUCCESS on successful random generation, or the corresponding error
 * code
 */
uint32_t handle_getrandom(tcti_smw_context_t *ctx, uint16_t tag,
			  const uint8_t *cmd, size_t cmd_size);

/**
 * handle_readpublic() - Process TPM2_ReadPublic command.
 * @ctx:      Pointer to the SMW TCTI context structure.
 * @tag:      TPM structure tag from the command header.
 * @cmd:      Pointer to the command buffer containing the full TPM command.
 * @cmd_size: Size of the command buffer in bytes.
 *
 * This function handles the TPM2_ReadPublic command which retrieves the public
 * area of a loaded object. It unmarshals the object handle, locates the
 * corresponding object in the context, retrieves its stored public area, and
 * calculates the object name by hashing the public area. The qualified name
 * is set equal to the name since ELE does not support hierarchy-based name
 * qualification. The function builds a response containing the public area,
 * name, and qualified name.
 *
 * Return:
 * TSS2_RC_SUCCESS on successful public area retrieval, or the corresponding
 * error code.
 */
uint32_t handle_readpublic(tcti_smw_context_t *ctx, uint16_t tag,
			   const uint8_t *cmd, size_t cmd_size);

/**
 * handle_create() - Process TPM2_Create command.
 * @ctx:      Pointer to the SMW TCTI context structure.
 * @tag:      TPM structure tag from the command header.
 * @cmd:      Pointer to the command buffer containing the full TPM command.
 * @cmd_size: Size of the command buffer in bytes.
 *
 * This function handles the TPM2_Create command which creates a new object
 * under a parent key. It unmarshals command parameters, generates the key
 * using SMW/ELE, and returns the public portion and a private blob. Since ELE
 * does not export private keys or support parent-child hierarchy, the private
 * blob contains a magic string "SMWKEYID" followed by the SMW key identifier
 * which references the key stored in ELE's NVM Secure Storage for later use
 * with TPM2_Load.
 *
 * Return:
 * TSS2_RC_SUCCESS on successful object creation, or the corresponding error code.
 */
uint32_t handle_create(tcti_smw_context_t *ctx, uint16_t tag,
		       const uint8_t *cmd, size_t cmd_size);

/**
 * handle_load() - Process TPM2_Load command.
 * @ctx:      Pointer to the SMW TCTI context structure.
 * @tag:      TPM structure tag from the command header.
 * @cmd:      Pointer to the command buffer containing the full TPM command.
 * @cmd_size: Size of the command buffer in bytes.
 *
 * This function handles the TPM2_Load command which loads a previously created
 * object into TPM memory under a parent key. It unmarshals the command parameters
 * including parent handle, authorization session, private blob, and public area.
 * The function validates the blob format, extracts the SMW key ID, allocates a
 * transient object handle and builds a response containing the object handle.
 *
 * Return:
 * TSS2_RC_SUCCESS on successful object load, or the corresponding error code.
 */
uint32_t handle_load(tcti_smw_context_t *ctx, uint16_t tag, const uint8_t *cmd,
		     size_t cmd_size);

/**
 * handle_sign() - Process TPM2_Sign command.
 * @ctx:      Pointer to the SMW TCTI context structure.
 * @tag:      TPM structure tag from the command header.
 * @cmd:      Pointer to the command buffer containing the full TPM command.
 * @cmd_size: Size of the command buffer in bytes.
 *
 * This function handles the TPM2_Sign command which signs a digest using a
 * loaded signing key. It unmarshals the command parameters including key handle,
 * digest, signing scheme, and validation ticket. The function validates the key
 * exists and has signing capabilities, maps the TPM signing scheme to SMW
 * parameters, calls the SMW sign API to generate the signature, and builds a
 * response containing the signature in TPM format (TPMT_SIGNATURE).
 *
 * Return:
 * TSS2_RC_SUCCESS on successful signature generation, or the corresponding error code.
 */
uint32_t handle_sign(tcti_smw_context_t *ctx, uint16_t tag, const uint8_t *cmd,
		     size_t cmd_size);

/**
 * handle_verifysignature() - Process TPM2_VerifySignature command.
 * @ctx:      Pointer to the SMW TCTI context structure.
 * @tag:      TPM structure tag from the command header.
 * @cmd:      Pointer to the command buffer containing the full TPM command.
 * @cmd_size: Size of the command buffer in bytes.
 *
 * This function handles the TPM2_VerifySignature command which verifies a
 * signature using a loaded verification key. It unmarshals the command parameters
 * including key handle, digest, signature, and validation ticket. The function
 * validates the key exists and has verification capabilities, maps the TPM
 * signature scheme to SMW parameters, calls the SMW verify API to validate the
 * signature, and builds a response containing the validation ticket.
 *
 * Return:
 * TSS2_RC_SUCCESS on successful signature verification, or the corresponding error code.
 */
uint32_t handle_verifysignature(tcti_smw_context_t *ctx, uint16_t tag,
				const uint8_t *cmd, size_t cmd_size);

/**
 * handle_pcrread() - Process TPM2_PCR_Read command.
 * @ctx:      Pointer to the SMW TCTI context structure.
 * @tag:      TPM structure tag from the command header.
 * @cmd:      Pointer to the command buffer containing the full TPM command.
 * @cmd_size: Size of the command buffer in bytes.
 *
 * This function handles the TPM2_PCR_Read command which reads Platform
 * Configuration Register (PCR) values. It unmarshals the requested PCR
 * selections (hash algorithm and PCR indices), generates PCR values for
 * each selected register, and builds a response containing the PCR update
 * counter, selection list, and digest values. In this implementation, all
 * PCRs return zero-filled values representing uninitialized state, as PCR
 * extend operations are not yet supported. The function supports multiple
 * hash algorithms (SHA1, SHA256, SHA384, SHA512) and returns appropriately
 * sized digests for each.
 *
 * Return:
 * TSS2_RC_SUCCESS on successful PCR read, or the corresponding error code.
 */
uint32_t handle_pcrread(tcti_smw_context_t *ctx, uint16_t tag,
			const uint8_t *cmd, size_t cmd_size);

/**
 * handle_pcrextend() - Process TPM2_PCR_Extend command.
 * @ctx:      Pointer to the SMW TCTI context structure.
 * @tag:      TPM structure tag from the command header.
 * @cmd:      Pointer to the command buffer containing the full TPM command.
 * @cmd_size: Size of the command buffer in bytes.
 *
 * This function handles the TPM2_PCR_Extend command which extends a Platform
 * Configuration Register with one or more digest values. It unmarshals the
 * PCR handle, authorization area, and digest values, validates the PCR index
 * is within range (0 to TPM2_MAX_PCRS-1), then extends the PCR for each
 * provided digest using the corresponding hash algorithm. The PCR extension
 * follows the formula: PCR_new = Hash(PCR_old || digest). Upon successful
 * extension, the global PCR update counter is incremented to track state
 * changes.
 *
 * Return:
 * TSS2_RC_SUCCESS on successful PCR extension, or the corresponding error code.
 */
uint32_t handle_pcrextend(tcti_smw_context_t *ctx, uint16_t tag,
			  const uint8_t *cmd, size_t cmd_size);

/**
 * handle_pcrevent() - Process TPM2_PCR_Event command.
 * @ctx:      Pointer to the SMW TCTI context structure.
 * @tag:      TPM structure tag from the command header.
 * @cmd:      Pointer to the command buffer containing the full TPM command.
 * @cmd_size: Size of the command buffer in bytes.
 *
 * This function handles the TPM2_PCR_Event command which hashes event data
 * and extends a Platform Configuration Register with the resulting digests.
 * Unlike TPM2_PCR_Extend which takes pre-computed digests, this command
 * accepts raw event data and computes the hash internally. The event data
 * is hashed using each active PCR bank's algorithm (SHA1, SHA256, etc.),
 * and the resulting digests are used to extend the specified PCR. The
 * function validates the PCR handle, computes hashes through the SMW hash
 * API, extends the PCR for each bank, increments the PCR update counter,
 * and returns all computed digests in the response.
 *
 * Return:
 * TSS2_RC_SUCCESS on successful PCR event processing, or the corresponding error code.
 */
uint32_t handle_pcrevent(tcti_smw_context_t *ctx, uint16_t tag,
			 const uint8_t *cmd, size_t cmd_size);

/**
 * handle_pcrreset() - Process TPM2_PCR_Reset command.
 * @ctx:      Pointer to the SMW TCTI context structure.
 * @tag:      TPM structure tag from the command header.
 * @cmd:      Pointer to the command buffer containing the full TPM command.
 * @cmd_size: Size of the command buffer in bytes.
 *
 * This function handles the TPM2_PCR_Reset command which resets a Platform
 * Configuration Register to its initial zero-filled state. It unmarshals
 * the PCR handle and authorization area, validates the PCR index, and
 * checks reset permissions. Per TPM 2.0 specification, only PCRs 16-23
 * are resettable at runtime; attempts to reset PCRs 0-15 return
 * TPM2_RC_LOCALITY. Upon successful validation, the PCR is reset to zeros
 * across all active PCR banks, and the global PCR update counter is
 * incremented to reflect the state change.
 *
 * Return:
 * TSS2_RC_SUCCESS on successful PCR reset, or the corresponding error code.
 */
uint32_t handle_pcrreset(tcti_smw_context_t *ctx, uint16_t tag,
			 const uint8_t *cmd, size_t cmd_size);

/**
 * handle_pcrallocate() - Process TPM2_PCR_Allocate command.
 * @ctx:      Pointer to the SMW TCTI context structure.
 * @tag:      TPM structure tag from the command header.
 * @cmd:      Pointer to the command buffer containing the full TPM command.
 * @cmd_size: Size of the command buffer in bytes.
 *
 * This function handles the TPM2_PCR_Allocate command which configures the
 * allocation of PCR banks. In this implementation, the command is processed
 * as a mock operation: the requested PCR allocation is parsed but not applied,
 * and the response reports the current allocation state unchanged. The handler
 * unmarshals the platform authorization handle, authorization area, and PCR
 * selection, then returns success with the current PCR bank configuration
 * including maximum PCR count, size needed, and size available. This allows
 * compatibility with TPM tools while maintaining the existing PCR bank setup.
 *
 * Return:
 * TSS2_RC_SUCCESS on successful command processing, or the corresponding error code.
 */
uint32_t handle_pcrallocate(tcti_smw_context_t *ctx, uint16_t tag,
			    const uint8_t *cmd, size_t cmd_size);
#endif /* __COMMANDS_H__ */
