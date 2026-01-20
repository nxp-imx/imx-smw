/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2026 NXP
 */

#ifndef __UTILS_H__
#define __UTILS_H__

#include <tss2/tss2_mu.h>

#include "common.h"

/**
 * free_resp() - Free the response buffer in the SMW TCTI context.
 * @ctx: Pointer to the SMW TCTI context structure.
 *
 * This function releases the memory allocated for the response buffer
 * and resets the response size to zero. It safely handles NULL context
 * pointers.
 *
 * Return:
 * None.
 */
void free_resp(tcti_smw_context_t *ctx);

/**
 * build_rc_response() - Build a TPM response with the specified return code.
 * @ctx:       Pointer to the SMW TCTI context structure.
 * @resp_size: Total size of the response including header.
 * @tag:       TPM structure tag for the response.
 * @rc:        TPM return code to include in the response.
 *
 * This function constructs a TPM response buffer with the provided parameters.
 * It allocates memory for the response, builds the TPM header with the given
 * tag and return code, and marshals it into the response buffer. Any previous
 * response buffer is freed before creating the new one.
 *
 * Return:
 * uint32_t value indicating success or the corresponding error.
 */
uint32_t build_rc_response(tcti_smw_context_t *ctx, uint32_t resp_size,
			   uint16_t tag, TPM2_RC rc);

/**
 * header_unmarshal() - Parse the first 10 bytes of a buffer into a header structure.
 * @buf:    Pointer to the source buffer containing the raw TPM header.
 * @header: Pointer to the &tpm_smw_header_t structure to be populated.
 *
 * This function extracts the TPM header fields from the first 10 bytes of the
 * provided buffer and populates the given header structure with the parsed
 * values. The buffer is assumed to contain at least 10 bytes.
 *
 * Return:
 * uint32_t value indicating success or the corresponding parsing error.
 */
uint32_t header_unmarshal(const uint8_t *buf, tpm_smw_header_t *header);

/**
 * header_marshal() - Serialize a header structure into a 10-byte buffer.
 * @header: Pointer to the &tpm_smw_header_t structure to be serialized.
 * @buf:    Pointer to the output buffer where the serialized data will be stored.
 *
 * The buffer must be at least 10 bytes long.
 * This function encodes the fields of the provided header structure into the
 * output buffer. The resulting binary representation occupies exactly 10 bytes,
 * corresponding to the standard TPM header format.
 *
 * Return:
 * uint32_t value indicating success or the corresponding serialization error.
 */
uint32_t header_marshal(const tpm_smw_header_t *header, uint8_t *buf);

/**
 * param_su_unmarshal() - Parse TPM2_SU startup/shutdown type from command buffer.
 * @buf:      Pointer to the source buffer containing the TPM command.
 * @buf_size: Size of the command buffer in bytes.
 * @su_type:  Pointer to the TPM2_SU variable to be populated.
 *
 * This function extracts the TPM2_SU parameter (startup/shutdown type) from
 * the command buffer after the TPM header. It validates the buffer size and
 * unmarshals the 16-bit value into the provided su_type structure.
 *
 * Return:
 * uint32_t value indicating success or the corresponding parsing error.
 */
uint32_t param_su_unmarshal(const uint8_t *buf, size_t buf_size,
			    TPM2_SU *su_type);

/**
 * tcti_rc_to_tpm2_rc() - Convert TSS2 TCTI return code to TPM2 response code.
 * @tcti_rc: TSS2 TCTI return code to convert.
 *
 * This function maps TSS2 TCTI layer return codes to their corresponding TPM2
 * response codes suitable for inclusion in TPM command responses. It provides
 * a conversion mechanism to translate internal TCTI errors into standard TPM2
 * error codes that can be returned to TPM clients. Unmapped or general TCTI
 * errors default to TPM2_RC_FAILURE.
 *
 * Return:
 * uint32_t value corresponding to the input TSS2 TCTI return code.
 */
uint32_t tcti_rc_to_tpm2_rc(TSS2_RC tcti_rc);
#endif /* __UTILS_H__ */
