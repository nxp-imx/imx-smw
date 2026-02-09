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

/**
 * struct createprimary_input_t - Input parameters for TPM2_CreatePrimary command.
 * @primary_handle: Hierarchy handle where the primary object will be created.
 * @in_sensitive:   Sensitive creation data including user auth and seed values.
 * @in_public:      Public template defining the object's type, algorithm, and attributes.
 * @outside_info:   External data to be included in the creation data.
 * @creation_pcr:   PCR selection for binding the object to specific PCR values.
 *
 * This structure encapsulates all input parameters required for creating a
 * primary object in a TPM hierarchy. It is used to organize and validate
 * command parameters during TPM2_CreatePrimary processing.
 */
typedef struct {
	TPM2_HANDLE primary_handle;
	TPM2B_SENSITIVE_CREATE in_sensitive;
	TPM2B_PUBLIC in_public;
	TPM2B_DATA outside_info;
	TPML_PCR_SELECTION creation_pcr;
} createprimary_input_t;

/**
 * struct createprimary_output_t - Output parameters for TPM2_CreatePrimary command.
 * @out_public:      Public area of the created object.
 * @object_name:     Computed name of the object (nameAlg || Hash(public)).
 * @creation_data:   Data associated with the object creation event.
 * @creation_hash:   Hash of the creation data.
 * @creation_ticket: Ticket proving the object was created by the TPM.
 *
 * This structure encapsulates all output parameters returned by the
 * TPM2_CreatePrimary command. It contains the created object's public
 * information, cryptographic proofs, and metadata for verification and
 * future operations.
 */
typedef struct {
	TPM2B_PUBLIC out_public;
	TPM2B_NAME object_name;
	TPM2B_CREATION_DATA creation_data;
	TPM2B_DIGEST creation_hash;
	TPMT_TK_CREATION creation_ticket;
} createprimary_output_t;

typedef createprimary_input_t create_input_t;

/**
 * struct create_output_t - Output parameters for TPM2_Create command.
 * @out_private:     Private area of the created object.
 * @out_public:      Public area of the created object.
 * @creation_data:   Data associated with the object creation event.
 * @creation_hash:   Hash of the creation data.
 * @creation_ticket: Ticket proving the object was created by the TPM.
 *
 * This structure encapsulates all output parameters returned by the
 * TPM2_Create command.
 */
typedef struct {
	TPM2B_PRIVATE out_private;
	TPM2B_PUBLIC out_public;
	TPM2B_CREATION_DATA creation_data;
	TPM2B_DIGEST creation_hash;
	TPMT_TK_CREATION creation_ticket;
} create_output_t;

/**
 * struct load_input_t - Input parameters for TPM2_Load command.
 * @parent_handle: Handle of the parent object under which to load the object.
 * @in_private:    Private area of the object to be loaded.
 * @in_public:     Public area of the object to be loaded.
 *
 * This structure encapsulates all input parameters required for loading
 * a previously created object into the TPM.
 */
typedef struct {
	TPMI_DH_OBJECT parent_handle;
	TPM2B_PRIVATE in_private;
	TPM2B_PUBLIC in_public;
} load_input_t;

/**
 * struct sign_input_t - Input parameters for TPM2_Sign command.
 * @key_handle:  Handle of the key to use for signing.
 * @digest:      Digest to be signed.
 * @in_scheme:   Signing scheme to use.
 * @validation:  Proof that digest was created by the TPM (can be NULL ticket).
 *
 * This structure encapsulates all input parameters required for the
 * TPM2_Sign command. It organizes the signing key handle, the digest
 * to sign, the signature scheme, and an optional validation ticket.
 */
typedef struct {
	TPMI_DH_OBJECT key_handle;
	TPM2B_DIGEST digest;
	TPMT_SIG_SCHEME in_scheme;
	TPMT_TK_HASHCHECK validation;
} sign_input_t;

/**
 * struct smw_object_blob_t - Object data structure for SMW storage.
 * @handle:        TPM object handle identifier.
 * @smw_key_id:    SMW key identifier for the underlying cryptographic key.
 * @attributes:    TPM object attributes defining usage and properties.
 * @public_area:   Complete public area of the object.
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
	TPM2B_PUBLIC public_area;
	uint8_t metadata[SMW_OBJECT_METADATA_SIZE];
	size_t metadata_size;
} smw_object_blob_t;

/**
 * map_hash_info() - Map hash algorithm information for TPM to SMW mapping.
 * @hash_alg:     TPM2 hash algorithm identifier.
 * @digest_size:  Pointer to store the digest size in bytes (can be NULL).
 * @smw_name:     Pointer to store the SMW hash algorithm name (can be NULL).
 * @smw_algo:     Pointer to store the SMW hash algorithm attribute (can be NULL).
 *
 * This function maps a TPM2 hash algorithm identifier to its corresponding
 * digest size, SMW hash algorithm name (smw_hash_algo_t), and SMW hash
 * algorithm attribute (smw_attr_algo_t). It supports SHA1, SHA256, SHA384,
 * and SHA512 algorithms. If an unknown algorithm is provided, it defaults to
 * SHA256 and returns an error code.
 *
 * Return:
 * TSS2_RC_SUCCESS on successful mapping, TSS2_TCTI_RC_BAD_VALUE for unknown algorithm.
 */
uint32_t map_hash_info(TPMI_ALG_HASH hash_alg, uint16_t *digest_size,
		       smw_hash_algo_t *smw_name, smw_attr_algo_t *smw_algo);

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
 * @public_area: Pointer to TPM2 public area structure
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
			  TPMI_RH_HIERARCHY hierarchy,
			  TPM2B_PUBLIC *public_area);

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

/**
 * calculate_object_name() - Calculate TPM object name from public area.
 * @public: Pointer to the TPM2B_PUBLIC structure containing the object's public area.
 * @name:   Pointer to the TPM2B_NAME structure to store the calculated name.
 *
 * This function computes the TPM object name according to TPM 2.0 specification
 * Part 1, Section 14 (Names). The name is calculated as:
 *   Name = nameAlg || Hash(TPMT_PUBLIC)
 * where nameAlg is the hash algorithm identifier and Hash() is the cryptographic
 * hash of the marshaled public area using the specified algorithm. The function
 * marshals the TPMT_PUBLIC structure, computes its hash using the SMW hash API,
 * and constructs the final name by concatenating the algorithm ID and hash digest.
 *
 * Return:
 * TSS2_RC_SUCCESS on successful name calculation, or the corresponding error code
 * (TSS2_TCTI_RC_MEMORY for allocation failures, or converted SMW/TSS2 errors).
 */
uint32_t calculate_object_name(const TPM2B_PUBLIC *public, TPM2B_NAME *name);

/**
 * map_curve_info() - Map ECC curve information for TPM to SMW mapping.
 * @curve:            TPM2 ECC curve identifier
 * @security_size:    Output parameter for security size in bits (can be NULL)
 * @public_data_size: Output parameter for public key data size in bytes (can be NULL)
 * @hash_attr:        Output parameter for SMW hash algorithm attribute (can be NULL)
 *
 * Maps TPM2 ECC curve identifiers to their corresponding security sizes,
 * public key data sizes, and hash algorithm attributes.
 * Supports NIST P-224, P-256, P-384, and P-521 curves.
 *
 * Return: TSS2_RC_SUCCESS on success, error code otherwise
 */
uint32_t map_curve_info(TPM2_ECC_CURVE curve, uint32_t *security_size,
			uint32_t *public_data_size, smw_attr_algo_t *hash_attr);
#endif /* __CRYPTO_H__ */
