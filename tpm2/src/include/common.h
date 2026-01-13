/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2026 NXP
 */

#ifndef __COMMON_H__
#define __COMMON_H__

#include <stdbool.h>

#include <tss2/tss2_tcti.h>

#define TCTI_VERSION 0x2

/*
 * TPM_HEADER_SIZE is counting the significant bytes used to encode command's
 * header in the buffer. It's not the size of the struct tpm_smw_header_t. Decoding
 * or encoding the header value in the buffer must be done using
 * encoding/decoding function.
 */
#define TPM_HEADER_SIZE (sizeof(uint16_t) + sizeof(uint32_t) + sizeof(uint32_t))

#define SMW_TCTI_MAGIC 0x534D5754435449ULL /* SMWTCTI */

/**
 * struct tpm_smw_header_t - TPM command/response header structure.
 * @tag:   TPM structure tag identifying the command/response type.
 * @size:  Total size of the TPM frame, including the header.
 * @code:  Command code (for commands) or response code (for responses).
 *
 * This typedef structure represents the standard 10-byte TPM header used in TPM
 * command and response frames. It contains the tag, the overall frame size,
 * and the command or response code associated with the message.
 */
typedef struct {
	TPM2_ST tag;
	UINT32 size;
	UINT32 code;
} tpm_smw_header_t;

/**
 * enum tcti_smw_state_t - TCTI internal state machine enumeration.
 * @TCTI_SMW_STATE_FINAL: Terminal state. All API calls return
 *                    TSS2_TCTI_RC_BAD_SEQUENCE.
 * @TCTI_SMW_STATE_TRANSMIT:
 *                    transmit:    success transitions the state machine to
 *                                 RECEIVE failure leaves the state unchanged
 *                    receive:     produces TSS2_TCTI_RC_BAD_SEQUENCE
 *                    finalize:    transitions state machine to FINAL state
 *                    cancel:      produces TSS2_TCTI_RC_BAD_SEQUENCE
 *                    setLocality: success or failure leaves state unchanged
 * @TCTI_SMW_STATE_RECEIVE:
 *                    transmit:    produces TSS2_TCTI_RC_BAD_SEQUENCE
 *                    receive:     success transitions the state machine to
 *                                 TRANSMIT failure with the following RCs leave
 *                                 the state unchanged:
 *                                   TRY_AGAIN, INSUFFICIENT_BUFFER, BAD_CONTEXT,
 *                                   BAD_REFERENCE, BAD_VALUE, BAD_SEQUENCE
 *                                 all other failures transition state machine to
 *                                   TRANSMIT (not recoverable)
 *                    finalize:    transitions state machine to FINAL state
 *                    cancel:      success transitions state machine to TRANSMIT
 *                                 failure leaves state unchanged
 *                    setLocality: produces TSS2_TCTI_RC_BAD_SEQUENCE
 *
 * This typedef enumeration defines the possible internal states of the TCTI context.
 * The TCTI state machine alternates between TRANSMIT and RECEIVE until it
 * reaches the FINAL state. Each state restricts which TCTI operations are
 * valid and how the state transitions occur based on command success or
 * failure.
 */
typedef enum {
	TCTI_SMW_STATE_FINAL,
	TCTI_SMW_STATE_TRANSMIT,
	TCTI_SMW_STATE_RECEIVE,
} tcti_smw_state_t;

/**
 * struct tcti_context_t - Common context structure for TCTI implementations.
 * @v2:                      TCTI common context header (Version 2).
 * @state:                   Internal TCTI state used to track operation flow.
 * @header:                  Cached TPM command/response header.
 *
 * This typedef structure defines the shared context used by TCTI modules
 * implementing the common logic for command transmission and reception. It embeds
 * the V2 TCTI context header, tracks the internal state of the TCTI instance,
 * and stores information related to TPM header parsing and locality handling.
 */
typedef struct {
	TSS2_TCTI_CONTEXT_COMMON_V2 v2;
	tcti_smw_state_t state;
	tpm_smw_header_t header;
} tcti_context_t;

/**
 * struct tcti_smw_context_t - Context structure for SMW TCTI implementation.
 * @common:         Common TCTI context. Must be the first field.
 * @initialized:    Indicates whether the TCTI context has been initialized.
 *
 * This typedef represents the TCTI context used by the SMW TCTI layer.
 * It embeds the common TCTI context as the first field to maintain
 * compatibility with generic TCTI operations, and it tracks initialization
 * state and the TPM internal state.
 */
typedef struct {
	tcti_context_t common; /* must be first */
	int initialized;

	/* last response buffer (Transmit/Receive) */
	uint8_t *resp_buf;
	size_t resp_size;
} tcti_smw_context_t;

/**
 * tcti_common_transmit_checks() - Perform common checks for TCTI transmit operation.
 * @tcti_common:     Pointer to the &tcti_context_t to validate.
 * @command_buffer:  Pointer to the buffer containing the command to be sent.
 * @magic:           The expected magic value for the specific TCTI implementation.
 *
 * This function validates the TCTI common context and the command buffer
 * provided to a TCTI 'transmit' operation. It ensures that the pointers are
 * valid and that the magic value matches the expected one for the context.
 *
 * Return:
 * uint32_t value indicating success or the type of validation failure.
 */
uint32_t tcti_common_transmit_checks(tcti_context_t *tcti_common,
				     const uint8_t *command_buffer,
				     uint64_t magic);

/**
 * tcti_common_receive_checks() - Perform common checks for TCTI receive operation.
 * @tcti_common:   Pointer to the &tcti_context_t to validate.
 * @response_size: Pointer to a size_t where the response size will be handled.
 * @magic:         The expected magic value for the specific TCTI implementation.
 *
 * This function validates the TCTI common context, the response size pointer,
 * and the associated magic value before a TCTI 'receive' operation. It ensures
 * that all required pointers are valid and that the context has the expected
 * identifier.
 *
 * Return:
 * uint32_t value indicating success or the type of validation failure.
 */
uint32_t tcti_common_receive_checks(tcti_context_t *tcti_common,
				    size_t *response_size, uint64_t magic);

#endif /* __COMMON_H__ */
