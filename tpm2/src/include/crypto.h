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

/*
 * ECC NIST curve security sizes (in bits)
 * These match TPM2_ECC_NIST_P* curve identifiers
 */
#define ECC_P224_SECURITY_BITS 224
#define ECC_P256_SECURITY_BITS 256
#define ECC_P384_SECURITY_BITS 384
#define ECC_P521_SECURITY_BITS 521

/*
 * ECC coordinate sizes (in bytes) for NIST curves
 * Each coordinate (X, Y) or signature component (R, S) has this size
 */
#define ECC_P224_COORD_SIZE 28
#define ECC_P256_COORD_SIZE 32
#define ECC_P384_COORD_SIZE 48
#define ECC_P521_COORD_SIZE 66

/*
 * ECC public key sizes (X || Y coordinates)
 */
#define ECC_P224_PUBLIC_SIZE (ECC_P224_COORD_SIZE * 2) /* 56 */
#define ECC_P256_PUBLIC_SIZE (ECC_P256_COORD_SIZE * 2) /* 64 */
#define ECC_P384_PUBLIC_SIZE (ECC_P384_COORD_SIZE * 2) /* 96 */
#define ECC_P521_PUBLIC_SIZE (ECC_P521_COORD_SIZE * 2) /* 132 */

/* Mocked proof - in production, load from secure storage */
extern uint8_t proof_owner[TPM2_SHA384_DIGEST_SIZE];
extern uint8_t proof_platform[TPM2_SHA384_DIGEST_SIZE];
extern uint8_t proof_endorsement[TPM2_SHA384_DIGEST_SIZE];

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
 * struct verifysignature_input_t - Input parameters for TPM2_VerifySignature command.
 * @key_handle: Handle of the key to use for verification.
 * @digest:     Digest that was signed.
 * @signature:  Signature to be verified.
 *
 * This structure encapsulates all input parameters required for the
 * TPM2_VerifySignature command. It organizes the verification key handle,
 * the digest that was signed, and the signature to verify.
 */
typedef struct {
	TPMI_DH_OBJECT key_handle;
	TPM2B_DIGEST digest;
	TPMT_SIGNATURE signature;
} verifysignature_input_t;

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
	TPM2B_NAME object_name;
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
 * @object_name: Pointer to TPM2 name area structure
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
			  TPM2B_PUBLIC *public_area, TPM2B_NAME *object_name);

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
/**
 * compute_hashcheck_hmac() - Compute HMAC for TPMT_TK_HASHCHECK ticket
 * @hierarchy: Hierarchy for the ticket (TPM_RH_OWNER, etc.)
 * @hash_alg: Hash algorithm used
 * @digest: The computed hash
 * @digest_size: Size of the hash
 * @hmac_out: Output buffer for HMAC
 *
 * Per TPM 2.0 Part 2, Section 10.7.6:
 * HMAC = HMAC_contextAlg(proof, (TPM_ST_HASHCHECK || digest))
 *
 * Where:
 * - proof = hierarchy proof value (secret associated with hierarchy)
 * - TPM_ST_HASHCHECK = 0x8014 (2 bytes, big-endian)
 * - contextAlg = SHA256
 * - digest = the hash result
 * - || = concatenation
 *
 * Return: TSS2_RC_SUCCESS on success, error code otherwise
 */
uint32_t compute_hashcheck_hmac(TPMI_RH_HIERARCHY hierarchy,
				const uint8_t *digest, uint16_t digest_size,
				uint8_t *hmac_out);

/**
 * get_hierarchy_proof_key() - Retrieve and copy the proof key for a TPM hierarchy.
 * @hierarchy:  TPM hierarchy identifier (OWNER, PLATFORM, ENDORSEMENT, or NULL).
 * @proof:      Pointer to the destination buffer where the proof key will be copied.
 *
 * This function retrieves the hierarchy-specific proof key and copies it into
 * the provided buffer. Proof keys are used for generating cryptographic tickets
 * and validating hierarchy-specific operations. Each hierarchy (Owner, Platform,
 * Endorsement) has its own unique proof value. The NULL hierarchy has no
 * associated proof key and results in no data being copied.
 *
 * The caller must ensure the destination buffer is large enough to hold the
 * proof key data.
 *
 * Return:
 * TSS2_RC_SUCCESS if the hierarchy is valid and proof key is copied,
 * error code otherwise.
 */
uint32_t get_hierarchy_proof_key(TPMI_RH_HIERARCHY hierarchy, uint8_t *proof);

/**
 * extract_ecdsa_signature() - Extract ECDSA signature components from raw buffer.
 * @signature_buffer: Pointer to the raw signature buffer containing concatenated R||S.
 * @signature_length: Total length of the signature buffer in bytes (must be even).
 * @tpm_signature:    Pointer to TPMT_SIGNATURE structure to populate with R and S values.
 *
 * This function parses a raw ECDSA signature buffer in the format R||S (concatenated
 * R and S coordinates) and extracts the components into a TPM2 TPMT_SIGNATURE structure.
 * The signature buffer is expected to contain two equal-length big integers representing
 * the ECDSA signature coordinates, with R in the first half and S in the second half.
 *
 * The function validates:
 * - Buffer pointers are non-NULL
 * - Signature length is even and non-zero
 * - Coordinate size does not exceed TPM2_MAX_ECC_KEY_BYTES
 * - Coordinate size matches standard ECC curves (P-224, P-256, P-384, P-521)
 *
 * Supported signature sizes:
 * - 56 bytes (P-224: 28 bytes R + 28 bytes S)
 * - 64 bytes (P-256: 32 bytes R + 32 bytes S)
 * - 96 bytes (P-384: 48 bytes R + 48 bytes S)
 * - 132 bytes (P-521: 66 bytes R + 66 bytes S)
 *
 * Return:
 * TSS2_RC_SUCCESS on successful extraction, error code otherwise.
 */
uint32_t extract_ecdsa_signature(unsigned char *signature_buffer,
				 unsigned int signature_length,
				 TPMT_SIGNATURE *tpm_signature);

/**
 * extract_key_sig_scheme() - Extract signature scheme from TPM public key area.
 * @public_area: Pointer to TPM2B_PUBLIC structure containing the key's public parameters.
 * @sig_scheme:  Pointer to TPMT_SIG_SCHEME structure to populate with extracted scheme.
 *
 * This function extracts the signature scheme configuration from a TPM key's public
 * area and populates a TPMT_SIG_SCHEME structure with the scheme identifier and
 * associated parameters (e.g., hash algorithm for ECDSA). The extracted scheme
 * represents the key's default signing configuration as defined during key creation.
 *
 * For ECC keys, the function supports:
 * - TPM2_ALG_ECDSA: Extracts the hash algorithm used for signature generation
 * - TPM2_ALG_NULL: Indicates no default scheme (scheme must be specified at sign time)
 *
 * Currently supported key types:
 * - TPM2_ALG_ECC: Elliptic Curve keys (ECDSA scheme)
 * Future extensions may include RSA (RSASSA, RSAPSS) and other asymmetric algorithms.
 *
 * Return:
 * TSS2_RC_SUCCESS on successful extraction, error code otherwise.
 */
uint32_t extract_key_sig_scheme(const TPM2B_PUBLIC *public_area,
				TPMT_SIG_SCHEME *sig_scheme);

/**
 * compute_creation_ticket_hmac() - Compute HMAC for TPM creation ticket validation.
 * @hierarchy:        TPM hierarchy (Owner, Platform, or Endorsement) for proof key selection.
 * @object_name:      Pointer to TPM2B_NAME containing the cryptographic name of the created object.
 * @creation_hash:    Pointer to TPM2B_DIGEST containing the hash of creation data.
 * @hmac_output:      Pointer to buffer for HMAC operation. When @is_verify is false, the computed
 *                    HMAC will be stored here. When @is_verify is true, this buffer contains the
 *                    expected HMAC value to verify against.
 * @hmac_output_size: Pointer to size of the output buffer in bytes
 * (must be at least SHA-256 digest size).
 * @is_verify:        Operation mode selector. When false, computes the HMAC and stores the result
 *                    in @hmac_output (used during ticket creation). When true, computes the HMAC
 *                    internally and verifies it against the value provided in @hmac_output (used
 *                    during ticket verification in TPM2_CertifyCreation).
 *
 * This function computes the HMAC used in TPM creation tickets according to TPM 2.0
 * specification Part 2, Section 10.7.3. The HMAC proves that an object was created by
 * the TPM and binds the object's name to its creation data. The computation uses the
 * hierarchy-specific proof key as the HMAC secret.
 *
 * HMAC input structure (concatenated):
 *   TPM_ST_CREATION (2 bytes) || objectName || creationHash
 *
 * The HMAC is computed using:
 * - Algorithm: HMAC-SHA256
 * - Key: Hierarchy proof key (retrieved via get_hierarchy_proof_key())
 * - Message: TPM_ST_CREATION || object name || creation hash
 *
 * This HMAC is stored in the TPMT_TK_CREATION ticket's digest field and later
 * verified during TPM2_CertifyCreation to prove the object's authentic creation.
 *
 * Return:
 * TSS2_RC_SUCCESS on successful HMAC computation, error code otherwise.
 */
uint32_t compute_creation_ticket_hmac(TPMI_RH_HIERARCHY hierarchy,
				      const TPM2B_NAME *object_name,
				      const TPM2B_DIGEST *creation_hash,
				      uint8_t *hmac_output,
				      size_t *hmac_output_size, bool is_verify);

/**
 * build_creation_ticket() - Build a TPM creation ticket structure.
 * @hierarchy:      TPM hierarchy (Owner, Platform, or Endorsement) that authorizes the ticket.
 * @object_name:    TPM2B_NAME containing the cryptographic name of the created object.
 * @creation_hash:  Pointer to TPM2B_DIGEST containing the hash of creation data and parameters.
 * @ticket:         Pointer to TPMT_TK_CREATION structure to populate with the ticket.
 *
 * This function constructs a TPM creation ticket that cryptographically binds an object
 * to its creation data. The ticket is generated during object creation (TPM2_Create,
 * TPM2_CreatePrimary) and later verified during attestation (TPM2_CertifyCreation) to
 * prove that the object was genuinely created by the TPM with specific creation parameters.
 *
 * The ticket contains:
 * - tag: TPM2_ST_CREATION (identifies this as a creation ticket)
 * - hierarchy: The hierarchy that authorizes this ticket
 * - digest: HMAC-SHA256 computed over (TPM_ST_CREATION || objectName || creationHash)
 *           using the hierarchy's proof key as the HMAC secret
 *
 * If the creation hash is empty (size = 0), an empty ticket is generated with no digest,
 * which is valid for objects created without specific creation data.
 *
 * The ticket's HMAC provides cryptographic proof that:
 * 1. The object was created by this TPM (only TPM knows the proof key)
 * 2. The object's name matches the creation parameters
 * 3. The creation data has not been tampered with
 *
 * Return:
 * TSS2_RC_SUCCESS on successful ticket construction, error code otherwise.
 */
uint32_t build_creation_ticket(TPMI_RH_HIERARCHY hierarchy,
			       const TPM2B_NAME object_name,
			       TPM2B_DIGEST *creation_hash,
			       TPMT_TK_CREATION *ticket);

/**
 * get_effective_scheme() - Determine the effective signature scheme for a signing operation.
 * @pub:              Pointer to TPMT_PUBLIC structure containing the key's public parameters.
 * @key_scheme:       Pointer to the key's default signature scheme from its public area.
 * @in_scheme:        Pointer to the caller-provided signature scheme (from command parameter).
 * @effective_scheme: Pointer to TPMT_SIG_SCHEME to populate with the resolved effective scheme.
 *
 * This function implements TPM 2.0 signature scheme selection rules according to the
 * specification Part 3, Section 18.1. The effective scheme is determined by combining
 * the key's default scheme with the caller-provided scheme, following these rules:
 *
 * 1. If key has a defined scheme (not TPM2_ALG_NULL):
 *    a. If in_scheme is NULL → use key's scheme
 *    b. If in_scheme matches key's scheme → use in_scheme (allows hash override)
 *    c. If in_scheme differs → ERROR (scheme conflict)
 *    d. If key is RESTRICTED and in_scheme is not NULL/matching → ERROR
 *
 * 2. If key's scheme is NULL (unrestricted signing key):
 *    a. If in_scheme is NULL → ERROR (no scheme specified)
 *    b. Otherwise → use in_scheme
 *
 * For ECC keys, the function also extracts scheme-specific details (e.g., hash algorithm
 * for ECDSA) from the key's public parameters.
 *
 * The RESTRICTED attribute prevents scheme override: restricted keys must use their
 * predefined scheme to ensure they can only be used for their intended purpose.
 *
 * Currently supported key types:
 * - TPM2_ALG_ECC: Elliptic Curve keys with ECDSA scheme
 *
 * Return:
 * TSS2_RC_SUCCESS if effective scheme is successfully determined, error code otherwise.
 */
uint32_t get_effective_scheme(TPMT_PUBLIC *pub,
			      const TPMT_SIG_SCHEME *key_scheme,
			      const TPMT_SIG_SCHEME *in_scheme,
			      TPMT_SIG_SCHEME *effective_scheme);
#endif /* __CRYPTO_H__ */
