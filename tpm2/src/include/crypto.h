/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2026 NXP
 */

#ifndef __CRYPTO_H__
#define __CRYPTO_H__

#include <stdint.h>

#include <tss2/tss2_mu.h>
#include "smw_crypto.h"
#include "common.h"

#define SMW_OBJECT_METADATA_SIZE 20

typedef struct {
	TPMI_RH_HIERARCHY primary_handle;
	TPM2B_SENSITIVE_CREATE in_sensitive;
	TPM2B_PUBLIC in_public;
	TPM2B_DATA outside_info;
	TPML_PCR_SELECTION creation_pcr;
} createprimary_input_t;

typedef struct {
	TPM2B_PUBLIC out_public;
	TPM2B_NAME object_name;
	TPM2B_CREATION_DATA creation_data;
	TPM2B_DIGEST creation_hash;
	TPMT_TK_CREATION creation_ticket;
} createprimary_output_t;

/**
 * struct smw_object_blob_t - Object data structure for SMW storage.
 * @handle:        TPM object handle identifier.
 * @smw_key_id:    SMW key identifier for the underlying cryptographic key.
 * @attributes:    TPM object attributes defining usage and properties.
 * @metadata:      Additional object-specific metadata or context information.
 * @metadata_size: Size of valid data in the metadata buffer.
 *
 * This structure represents the object information that can be stored and
 * retrieved from SMW's secure storage. It contains the essential object
 * parameters needed to maintain object state across operations, including
 * the mapping between TPM handles and SMW key identifiers.
 */
typedef struct {
	uint32_t handle;
	uint32_t smw_key_id;
	TPMA_OBJECT attributes;
	uint8_t metadata[SMW_OBJECT_METADATA_SIZE];
	size_t metadata_size;
} smw_object_blob_t;

/**
 * map_hash_info() - Map hash algorithm information for TPM to SMW mapping.
 * @hash_alg:     TPM2 hash algorithm identifier.
 * @digest_size:  Pointer to store the digest size in bytes (can be NULL).
 * @smw_name:     Pointer to store the SMW hash algorithm name (can be NULL).
 *
 * This function maps a TPM2 hash algorithm identifier to its corresponding
 * digest size and SMW hash algorithm name. It supports SHA1, SHA256, SHA384,
 * and SHA512 algorithms. If an unknown algorithm is provided, it defaults
 * to SHA256 and returns an error code.
 *
 * Return:
 * TSS2_RC_SUCCESS on successful mapping, TSS2_TCTI_RC_BAD_VALUE for unknown algorithm.
 */
uint32_t map_hash_info(TPMI_ALG_HASH hash_alg, uint16_t *digest_size,
		       smw_hash_algo_t *smw_name);

/**
 * calculate_response_hmac - Calculate HMAC for TPM2 response authentication
 *
 * @session:         Active TPM2 session containing session key and nonces
 * @responseCode:    TPM2 response code (RC) from command execution
 * @commandCode:     TPM2 command code (CC) that was executed
 * @parameters:      Response parameters buffer (marshaled)
 * @parameters_size: Size of response parameters in bytes
 * @nonceCaller:     Nonce provided by caller in the request
 * @nonceCaller_size: Size of caller's nonce in bytes
 * @hmac_out:        Output buffer for calculated HMAC (allocated by function)
 * @hmac_size:       Output size of the calculated HMAC
 *
 * This function calculates the response HMAC according to TPM2 specification
 * for authenticated sessions. It performs the following steps:
 *
 * 1. Computes rpHash = Hash(responseCode || commandCode || parameters)
 * 2. Constructs HMAC message = rpHash || nonceTPM || nonceCaller || sessionAttributes
 * 3. Calculates HMAC using the session key over the constructed message
 *
 * The caller is responsible for freeing the allocated @hmac_out buffer.
 *
 * Return: TSS2_RC_SUCCESS on success
 *         TSS2_TCTI_RC_MEMORY if memory allocation fails
 *         TSS2_TCTI_RC_GENERAL_FAILURE if hash or HMAC computation fails
 *         Other TSS2_RC codes for marshaling errors
 *
 * Note: This function follows TPM 2.0 specification Part 1, Section 16
 *       for HMAC session response authentication.
 */
uint32_t calculate_response_hmac(tcti_smw_session_t *session,
				 TPM2_RC responseCode, TPM2_CC commandCode,
				 const uint8_t *parameters,
				 size_t parameters_size,
				 const uint8_t *nonceCaller,
				 size_t nonceCaller_size, uint8_t **hmac_out,
				 uint16_t *hmac_size);

/**
 * smw_object_alloc() - Allocate a transient object slot
 * @ctx:    Pointer to the SMW TCTI context structure.
 * @handle: Pointer to store the allocated session handle.
 * @attributes: TPM2 object attributes (TPMA_OBJECT flags)
 * @key_id: SMW/ELE key identifier from smw_generate_key()
 * @hierarchy: TPM2 object hierarchy
 *
 * Allocates a free slot in the transient object pool and assigns a TPM2
 * handle in the saveable range (0x80000000-0x80000002).
 *
 * Return:
 * - TSS2_RC_SUCCESS: Object allocated, handle written to *handle
 * - TSS2_TCTI_RC_MEMORY: All slots occupied
 */
uint32_t smw_object_alloc(tcti_smw_context_t *ctx, uint32_t *handle,
			  TPMA_OBJECT attributes, unsigned int key_id,
			  TPMI_RH_HIERARCHY hierarchy);

/**
 * find_object_by_handle() - Find object by TPM2 handle
 * @ctx:    TCTI SMW context containing object pool
 * @handle: TPM2 handle to search for (0x80000000-0x80000002)
 *
 * This function searches through the object array in the TCTI context
 * to find an active object matching the specified handle. It iterates
 * through all possible object slots and returns the first active object
 * with a matching handle.
 *
 * Return:
 * Pointer to the matching tcti_smw_object_t structure if found, NULL otherwise.
 */
tcti_smw_object_t *find_object_by_handle(tcti_smw_context_t *ctx,
					 uint32_t handle);
#endif /* __CRYPTO_H__ */
