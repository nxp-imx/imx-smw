/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2026 NXP
 */

#ifndef __UTILS_H__
#define __UTILS_H__

#include <tss2/tss2_mu.h>

#include "common.h"

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
#endif /* __UTILS_H__ */
