// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <string.h>

#include "smw_crypto.h"
#include "smw_keymgr.h"
#include "utils.h"
#include "commands.h"
#include "crypto.h"
#include "trace.h"

#define SMW_PRIVATE_BLOB_MAGIC	   "SMWKEYID"
#define SMW_PRIVATE_BLOB_MAGIC_LEN 8

static uint32_t encrypt_sealed_data(TPMI_RH_HIERARCHY hierarchy,
				    const uint8_t *plaintext,
				    uint16_t plaintext_size, uint8_t *blob_out,
				    uint16_t *blob_size)
{
	TSS2_RC rc = TSS2_RC_SUCCESS;
	enum smw_status_code smw_status = SMW_STATUS_OK;

	/* AEAD structures */
	struct smw_aead_args aead_args = { 0 };
	struct smw_aead_init_args init_args = { 0 };
	struct smw_aead_aad_args aad_args = { 0 };
	struct smw_aead_final_args final_args = { 0 };
	struct smw_aead_data_args data_args = { 0 };
	struct smw_key_descriptor key_desc = { 0 };
	struct smw_keypair_buffer key_buffer = { 0 };

	uint8_t *ptr = blob_out;
	uint8_t *proof = NULL;
	uint8_t output_iv[SEAL_NONCE_SIZE] = { 0 };
	size_t offset = 0;
	size_t iv_offset = SMW_SEALED_BLOB_MAGIC_LEN + sizeof(uint16_t) +
			   sizeof(TPMI_RH_HIERARCHY);

	if (!plaintext || !blob_out || !blob_size) {
		rc = TSS2_TCTI_RC_BAD_REFERENCE;
		goto end;
	}

	if (plaintext_size == 0 || plaintext_size > SMW_MAX_SEALED_DATA) {
		DBG_TRACE("Invalid data size: %u (max: %u)\n", plaintext_size,
			  SMW_MAX_SEALED_DATA);
		rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	/* Allocate proof buffer */
	proof = calloc(1, TPM2_SHA256_DIGEST_SIZE);
	if (!proof) {
		rc = TSS2_TCTI_RC_MEMORY;
		goto end;
	}

	rc = get_hierarchy_proof_key(hierarchy, proof);
	if (rc != TSS2_RC_SUCCESS)
		goto end;

	/* 3. Build AAD header in blob */
	/* Magic */
	memcpy(ptr + offset, SMW_SEALED_BLOB_MAGIC, SMW_SEALED_BLOB_MAGIC_LEN);
	offset += SMW_SEALED_BLOB_MAGIC_LEN;

	/* Plaintext size */
	memcpy(ptr + offset, &plaintext_size, sizeof(uint16_t));
	offset += sizeof(uint16_t);

	/* Hierarchy */
	memcpy(ptr + offset, &hierarchy, sizeof(TPMI_RH_HIERARCHY));
	offset += sizeof(TPMI_RH_HIERARCHY);

	/* IV will be generated during encryption process */
	offset += SEAL_NONCE_SIZE;

	/* 4. Setup AEAD structures */
	key_buffer.gen.private_data = proof;
	key_buffer.gen.private_length = TPM2_SHA256_DIGEST_SIZE;
	key_desc.type_name = SMW_KEY_TYPE_NAME_AES;
	key_desc.buffer = &key_buffer;
	key_desc.security_size = BYTES_TO_BITS(TPM2_SHA256_DIGEST_SIZE);

	init_args.subsystem_name = SMW_SUBSYSTEM_NAME_ELE;
	init_args.mode_name = SMW_AEAD_MODE_NAME_GCM;
	init_args.op_type_name = SMW_AEAD_OP_TYPE_NAME_ENCRYPT;
	init_args.user_iv = NULL;
	init_args.user_iv_length = 0;
	init_args.iv_length = SEAL_NONCE_SIZE;
	init_args.plaintext_length = plaintext_size;
	init_args.key_desc = &key_desc;

	aad_args.data = ptr;
	aad_args.data_length = SEAL_AAD_SIZE;

	data_args.input = (unsigned char *)plaintext;
	data_args.input_length = plaintext_size;
	data_args.output = ptr + offset;
	data_args.output_length = plaintext_size;

	final_args.data = &data_args;
	final_args.tag = ptr + offset + plaintext_size;
	final_args.tag_length = SEAL_TAG_SIZE;
	final_args.output_iv = output_iv;
	final_args.output_iv_length = SEAL_NONCE_SIZE;

	aead_args.init = &init_args;
	aead_args.aad = &aad_args;
	aead_args.final = &final_args;

	/* 5. Execute AEAD encryption */
	smw_status = smw_aead(&aead_args);
	if (smw_status != SMW_STATUS_OK) {
		DBG_TRACE("AEAD encrypt failed: %d\n", smw_status);
		rc = smw_rc_to_tcti_rc(smw_status);
		goto end;
	}

	/* Store the generated IV in the blob */
	memcpy(ptr + iv_offset, output_iv, SEAL_NONCE_SIZE);

	*blob_size = offset + plaintext_size + SEAL_TAG_SIZE;

	DBG_TRACE("AEAD sealed blob created:\n"
		  "  AAD (%lu bytes):\n"
		  "    - Magic: %s (%u bytes)\n"
		  "    - Plaintext size: %u\n"
		  "    - Hierarchy: 0x%08x\n"
		  "  IV: %u bytes\n"
		  "  Ciphertext: %u bytes\n"
		  "  Tag: %u bytes\n"
		  "  Total: %u bytes\n",
		  SEAL_AAD_SIZE, SMW_SEALED_BLOB_MAGIC,
		  SMW_SEALED_BLOB_MAGIC_LEN, plaintext_size, hierarchy,
		  SEAL_NONCE_SIZE, plaintext_size, SEAL_TAG_SIZE, *blob_size);

end:
	if (proof)
		free(proof);

	DBG_TRACE_COND(rc != TSS2_RC_SUCCESS, "return error: 0x%08x\n", rc);
	return rc;
}

static uint32_t
create_sealed_data_object(tcti_smw_context_t *ctx,
			  const TPM2B_SENSITIVE_CREATE *in_sensitive,
			  const TPM2B_PUBLIC *in_public,
			  TPMI_RH_HIERARCHY hierarchy, create_output_t *output)
{
	TSS2_RC rc = TSS2_RC_SUCCESS;
	uint16_t blob_size = SMW_MAX_SEALED_BLOB_SIZE;

	if (!ctx || !in_sensitive || !in_public) {
		rc = TSS2_TCTI_RC_BAD_REFERENCE;
		goto end;
	}

	/* Validate sensitive data size */
	if (in_sensitive->sensitive.data.size == 0) {
		DBG_TRACE("No data to seal\n");
		rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	if (in_sensitive->sensitive.data.size > SMW_MAX_SEALED_DATA) {
		DBG_TRACE("Sealed data too large: %u > %u\n",
			  in_sensitive->sensitive.data.size,
			  SMW_MAX_SEALED_DATA);
		rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	/* Encrypt with AEAD */
	rc = encrypt_sealed_data(hierarchy, in_sensitive->sensitive.data.buffer,
				 in_sensitive->sensitive.data.size,
				 output->out_private.buffer, &blob_size);
	if (rc != TSS2_RC_SUCCESS) {
		DBG_TRACE("Failed to encrypt sealed data\n");
		goto end;
	}

	output->out_private.size = blob_size;

	/* Copy public area */
	output->out_public = *in_public;

	if (output->out_private.size > sizeof(output->out_private.buffer)) {
		DBG_TRACE("Private blob too large\n");
		rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	DBG_TRACE("Sealed data object created, private blob size: %u\n",
		  output->out_private.size);

end:
	DBG_TRACE_COND(rc != TSS2_RC_SUCCESS, "return error: 0x%08x\n", rc);
	return rc;
}

static uint32_t build_creation_hash(const TPM2B_CREATION_DATA *creation_data,
				    TPM2B_DIGEST *creation_hash,
				    TPMI_ALG_HASH hash_alg)
{
	TSS2_RC rc = TSS2_TCTI_RC_BAD_REFERENCE;
	enum smw_status_code smw_status;
	struct smw_hash_args hash_args = { 0 };
	uint8_t buffer[sizeof(TPM2B_CREATION_DATA)] = { 0 };
	size_t buffer_size = 0;

	uint16_t hmac_size = 0;
	smw_hash_algo_t hash_name = SMW_HASH_ALGO_NAME_NONE;

	if (!creation_data || !creation_hash)
		return rc;

	/* Marshal creation data */
	rc = Tss2_MU_TPM2B_CREATION_DATA_Marshal(creation_data, buffer,
						 sizeof(buffer), &buffer_size);
	if (rc != TSS2_RC_SUCCESS)
		return rc;

	rc = map_hash_info(hash_alg, &hmac_size, &hash_name, NULL);
	if (rc != TSS2_RC_SUCCESS)
		goto end;

	/* Hash with SHA256 */
	hash_args.algo_name = hash_name;
	hash_args.input = buffer;
	hash_args.input_length = buffer_size;
	hash_args.output = creation_hash->buffer;
	hash_args.output_length = hmac_size;

	smw_status = smw_hash(&hash_args);
	if (smw_status != SMW_STATUS_OK) {
		DBG_TRACE("SMW hash failed: %d\n", smw_status);
		rc = smw_rc_to_tcti_rc(smw_status);
		goto end;
	}

	creation_hash->size = TPM2_SHA256_DIGEST_SIZE;

end:
	DBG_TRACE_COND(rc != TSS2_RC_SUCCESS, "return error: 0x%08x\n", rc);
	return rc;
}

static uint32_t build_creation_data(const TPM2B_PUBLIC *public_area,
				    const TPM2B_NAME *parent_name,
				    const TPML_PCR_SELECTION *creation_pcr,
				    const TPM2B_DATA *outside_info,
				    TPM2B_CREATION_DATA *creation_data)
{
	TSS2_RC rc = TSS2_RC_SUCCESS;
	size_t size = 0;
	uint8_t *temp_buffer = NULL;

	if (!public_area || !parent_name || !creation_data) {
		rc = TSS2_TCTI_RC_BAD_REFERENCE;
		goto end;
	}

	temp_buffer = malloc(TPM2_MAX_CAP_BUFFER);
	if (!temp_buffer) {
		rc = TSS2_TCTI_RC_MEMORY;
		goto end;
	}

	memset(creation_data, 0, sizeof(*creation_data));

	/* PCR selection */
	if (creation_pcr)
		creation_data->creationData.pcrSelect = *creation_pcr;

	/* Parent name algorithm */
	creation_data->creationData.parentNameAlg = TPM2_ALG_SHA256;

	/* Parent name */
	creation_data->creationData.parentName = *parent_name;

	/* Parent qualified name */
	creation_data->creationData.parentQualifiedName = *parent_name;

	/* Outside info */
	if (outside_info)
		creation_data->creationData.outsideInfo = *outside_info;

	/* Calculate size */
	rc = Tss2_MU_TPMS_CREATION_DATA_Marshal(&creation_data->creationData,
						temp_buffer,
						TPM2_MAX_CAP_BUFFER, &size);
	if (rc != TSS2_RC_SUCCESS)
		goto end;

	if (SET_OVERFLOW(size, creation_data->size))
		rc = TSS2_TCTI_RC_MEMORY;

end:
	/* Free allocated memory */
	if (temp_buffer)
		free(temp_buffer);

	DBG_TRACE_COND(rc != TSS2_RC_SUCCESS, "return error: 0x%08x\n", rc);
	return rc;
}

static uint32_t configure_hmac_key(TPMT_PUBLIC *pub, uint32_t attrs,
				   struct smw_key_descriptor *key_desc)
{
	TSS2_RC rc = TSS2_RC_SUCCESS;
	uint16_t key_size_bytes = 0;
	smw_attr_algo_t keyed_hash_attr = SMW_ATTR_HASH_NONE;
	TPMS_KEYEDHASH_PARMS *params = &pub->parameters.keyedHashDetail;

	/* Verify HMAC scheme */
	if (params->scheme.scheme != TPM2_ALG_HMAC) {
		DBG_TRACE("Unsupported keyedHash scheme: 0x%04x\n",
			  params->scheme.scheme);
		rc = TSS2_TCTI_RC_IO_ERROR;
		goto end;
	}

	/* Map TPM2 hash algorithm to SMW hash algorithm */
	rc = map_hash_info(params->scheme.details.hmac.hashAlg, &key_size_bytes,
			   NULL, &keyed_hash_attr);
	if (rc != TSS2_RC_SUCCESS) {
		DBG_TRACE("Failed to map hash algorithm: 0x%04x\n",
			  params->scheme.details.hmac.hashAlg);
		goto end;
	}

	/* Configure SMW key descriptor for HMAC */
	key_desc->type_name = SMW_KEY_TYPE_NAME_HMAC;
	key_desc->security_size = BYTES_TO_BITS(key_size_bytes);

	/* Configure usage flags and permitted algorithms based on key attributes */
	if (attrs & TPMA_OBJECT_SIGN_ENCRYPT) {
		DBG_TRACE("  - TPMA_OBJECT_SIGN_ENCRYPT (HMAC sign)\n");
		key_desc->attributes.usage_flags |=
			(SMW_ATTR_USAGE_SIGN_MESSAGE |
			 SMW_ATTR_USAGE_VERIFY_MESSAGE);
	}

	if (attrs & TPMA_OBJECT_DECRYPT) {
		DBG_TRACE("Unsupported HMAC key usage (TPMA_OBJECT_DECRYPT)\n");
		rc = TSS2_TCTI_RC_IO_ERROR;
		goto end;
	}

	key_desc->attributes.permitted_algo =
		SMW_ATTR_ALGO_MAC_HMAC(keyed_hash_attr, 0);

	DBG_TRACE("HMAC key configured: size=%u bits, hash_alg=0x%04x\n",
		  key_desc->security_size, params->scheme.details.hmac.hashAlg);

end:
	DBG_TRACE_COND(rc != TSS2_RC_SUCCESS, "return error: 0x%08x\n", rc);
	return rc;
}

static uint32_t configure_ecc_key(TPMT_PUBLIC *pub, uint32_t attrs,
				  struct smw_key_descriptor *key_desc)
{
	TSS2_RC rc = TSS2_RC_SUCCESS;
	smw_attr_algo_t hash_attr = SMW_ATTR_HASH_NONE;
	smw_attr_algo_t scheme_hash_attr = SMW_ATTR_HASH_NONE;
	smw_attr_algo_t curve_secp_r1 = SMW_ATTR_CURVE_SECP_R1;
	TPMS_ECC_PARMS *params = &pub->parameters.eccDetail;

	if (!key_desc->buffer) {
		rc = TSS2_TCTI_RC_BAD_REFERENCE;
		goto end;
	}

	if (params->scheme.scheme != TPM2_ALG_NULL &&
	    params->scheme.scheme != TPM2_ALG_ECDSA) {
		DBG_TRACE("Unsupported ECC scheme: 0x%04x\n",
			  params->scheme.scheme);
		rc = TSS2_TCTI_RC_IO_ERROR;
		goto end;
	}

	/* Extract curve details and configure SMW key descriptor */
	rc = map_curve_info(params->curveID, &key_desc->security_size,
			    &key_desc->buffer->gen.public_length, &hash_attr);
	if (rc != TSS2_RC_SUCCESS)
		goto end;

	if (params->scheme.scheme == TPM2_ALG_ECDSA) {
		rc = map_hash_info(params->scheme.details.ecdsa.hashAlg, NULL,
				   NULL, &scheme_hash_attr);
		if (rc != TSS2_RC_SUCCESS)
			goto end;

		if (hash_attr != scheme_hash_attr) {
			DBG_TRACE("Hash algorithm mismatch: curve=0x%lx,\n"
				  "scheme=0x%lx\n",
				  hash_attr, scheme_hash_attr);
			rc = TSS2_TCTI_RC_BAD_VALUE;
			goto end;
		}
	}

	key_desc->type_name = SMW_KEY_TYPE_NAME_SECP_R1;

	/* Configure usage flags and permitted algorithms based on key attributes */
	if (attrs & TPMA_OBJECT_RESTRICTED) {
		DBG_TRACE("  - TPMA_OBJECT_RESTRICTED\n");
		if (hash_attr != SMW_ATTR_HASH_SHA256) {
			DBG_TRACE("Unsupported ECC DERIVE algorithm,\n"
				  "only SHA256 is supported\n");
			rc = TSS2_TCTI_RC_IO_ERROR;
			goto end;
		}

		key_desc->attributes.usage_flags |= SMW_ATTR_USAGE_DERIVE;
		key_desc->attributes.permitted_algo =
			SMW_ATTR_ALGO_KEY_AGREEMENT(ECDH, SMW_ATTR_ALGO_HKDF,
						    hash_attr);
	}

	if (attrs & TPMA_OBJECT_SIGN_ENCRYPT) {
		DBG_TRACE("  - TPMA_OBJECT_SIGN_ENCRYPT\n");
		key_desc->attributes.usage_flags |=
			(SMW_ATTR_USAGE_SIGN_HASH |
			 SMW_ATTR_USAGE_SIGN_MESSAGE);
		key_desc->attributes.permitted_algo =
			SMW_ATTR_ALGO_ASYMMETRIC_SIGNATURE_ECDSA(curve_secp_r1,
								 hash_attr);
	}

	if (attrs & TPMA_OBJECT_DECRYPT) {
		DBG_TRACE("Unsupported ECC key usage (TPMA_OBJECT_DECRYPT)\n");
		rc = TSS2_TCTI_RC_IO_ERROR;
		goto end;
	}

	DBG_TRACE("ECC key configured: size=%u bits, curve_id=0x%04x\n",
		  key_desc->security_size, params->curveID);

end:
	DBG_TRACE_COND(rc != TSS2_RC_SUCCESS, "return error: 0x%08x\n", rc);
	return rc;
}

static uint32_t
configure_smw_key_descriptor(TPMT_PUBLIC *pub,
			     struct smw_key_descriptor *key_desc,
			     struct smw_keypair_buffer *key_buffer)
{
	TSS2_RC rc = TSS2_RC_SUCCESS;
	uint32_t attrs = 0;
	smw_attr_algo_t persistent = SMW_ATTR_PERSISTENCE_PERSISTENT;

	if (!pub || !key_desc || !key_buffer) {
		DBG_TRACE("Invalid parameters\n");
		rc = TSS2_TCTI_RC_BAD_REFERENCE;
		goto end;
	}

	attrs = pub->objectAttributes;

	/* Check persistence requirements first */
	if (!(attrs & TPMA_OBJECT_STCLEAR) && (attrs & TPMA_OBJECT_FIXEDTPM)) {
		key_desc->attributes.attributes =
			SMW_ATTR_SET_PERSISTENCE(0, persistent);
	} else {
		DBG_TRACE("Key cannot be persistent\n"
			  "because of attributes given\n");
		rc = TSS2_TCTI_RC_BAD_REFERENCE;
		goto end;
	}

	key_desc->buffer = key_buffer;

	/* Handle different key types */
	switch (pub->type) {
	case TPM2_ALG_KEYEDHASH:
		rc = configure_hmac_key(pub, attrs, key_desc);
		break;

	case TPM2_ALG_ECC:
		rc = configure_ecc_key(pub, attrs, key_desc);
		break;

	default:
		DBG_TRACE("Unsupported key type: 0x%04x\n", pub->type);
		rc = TSS2_TCTI_RC_IO_ERROR;
		goto end;
	}

end:
	DBG_TRACE_COND(rc != TSS2_RC_SUCCESS, "return error: 0x%08x\n", rc);
	return rc;
}

static uint32_t extract_ecc_coordinates(struct smw_keypair_buffer *key_buffer,
					TPM2B_PUBLIC *out_public)
{
	TSS2_RC rc = TSS2_RC_SUCCESS;
	size_t ecc_coord_size = 0;

	if (!key_buffer || !out_public || !key_buffer->gen.public_data) {
		rc = TSS2_TCTI_RC_BAD_REFERENCE;
		goto end;
	}

	/*
	 * For ECC, public_data contains: X || Y coordinates
	 * Format:
	 * - P-256: 32 bytes X + 32 bytes Y = 64 bytes total
	 * - P-384: 48 bytes X + 48 bytes Y = 96 bytes total
	 * - P-521: 66 bytes X + 66 bytes Y = 132 bytes total
	 */
	if (key_buffer->gen.public_length == 0 ||
	    key_buffer->gen.public_length % 2 != 0) {
		DBG_TRACE("Invalid length: %u must be even and non-zero\n",
			  key_buffer->gen.public_length);
		rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	ecc_coord_size = key_buffer->gen.public_length / 2;

	if (ecc_coord_size >
		    sizeof(out_public->publicArea.unique.ecc.x.buffer) ||
	    ecc_coord_size >
		    sizeof(out_public->publicArea.unique.ecc.y.buffer)) {
		DBG_TRACE("ECC coordinate size too large: %zu bytes\n",
			  ecc_coord_size);
		rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	/* Extract X coordinate (first half) */
	out_public->publicArea.unique.ecc.x.size = ecc_coord_size;
	memcpy(out_public->publicArea.unique.ecc.x.buffer,
	       key_buffer->gen.public_data, ecc_coord_size);

	/* Extract Y coordinate (second half) */
	out_public->publicArea.unique.ecc.y.size = ecc_coord_size;
	memcpy(out_public->publicArea.unique.ecc.y.buffer,
	       &key_buffer->gen.public_data[ecc_coord_size], ecc_coord_size);

end:
	DBG_TRACE_COND(rc != TSS2_RC_SUCCESS, "return error: 0x%08x\n", rc);
	return rc;
}

uint32_t handle_createprimary(tcti_smw_context_t *ctx, uint16_t tag,
			      const uint8_t *cmd, size_t cmd_size)
{
	TPM2_RC rc = TPM2_RC_SUCCESS;
	TSS2_RC tss2_rc = TSS2_TCTI_RC_GENERAL_FAILURE;
	enum smw_status_code smw_status = SMW_STATUS_OK;
	uint8_t *response_hmac = NULL;
	size_t resp_params_size = 0;

	/*
	 * creation_data, creation_hash and creation_pcr
	 * set to 0 because PCR not supported
	 */

	/* Input parameters */
	createprimary_input_t input = { 0 };

	/* Output parameters */
	createprimary_output_t output = { 0 };
	TPMT_PUBLIC *pub = NULL;
	TPMA_OBJECT attrs = { 0 };
	TPM2_HANDLE object_handle = 0;
	unsigned char public_data_buf[TPM2_MAX_ECC_KEY_BYTES * 2] = { 0 };

	/* Session handling */
	uint32_t session_handle = 0;
	TPM2B_NONCE nonce_caller = { 0 };
	tcti_smw_session_t *sess = NULL;

	struct smw_key_descriptor key_desc = { 0 };
	struct smw_keypair_buffer key_buffer = { 0 };
	struct smw_generate_key_args gen_args = { 0 };

	uint8_t *params_buffer = NULL;

	/* 1. Check initialization */
	if (!ctx->initialized) {
		tss2_rc = TSS2_TCTI_RC_BAD_SEQUENCE;
		goto end;
	}

	/* 2. Unmarshal primary handle */
	tss2_rc = create_primary_unmarshal(cmd, cmd_size, &input, &nonce_caller,
					   &session_handle);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	/* Find session */
	if (session_handle != TPM2_RH_PW) {
		sess = find_session_by_handle(ctx, session_handle);
		if (!sess || !sess->active) {
			tss2_rc = TSS2_TCTI_RC_IO_ERROR;
			goto end;
		}
	}

	/* 3. Validate key type and prepare SMW structures */
	pub = &input.in_public.publicArea;
	attrs = pub->objectAttributes;

	if (pub->type == TPM2_ALG_ECC)
		key_buffer.gen.public_data = public_data_buf;

	tss2_rc = configure_smw_key_descriptor(pub, &key_desc, &key_buffer);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	/* 4. Call SMW to generate key */
	gen_args.subsystem_name = SMW_SUBSYSTEM_NAME_ELE;
	gen_args.key_descriptor = &key_desc;

	smw_status = smw_generate_key(&gen_args);
	if (smw_status != SMW_STATUS_OK &&
	    smw_status != SMW_STATUS_KEY_POLICY_WARNING_IGNORED) {
		DBG_TRACE("SMW key generation failed: %d\n", smw_status);
		tss2_rc = smw_rc_to_tcti_rc(smw_status);
		goto end;
	}

	DBG_TRACE("Key generated successfully, SMW ID: %d\n", key_desc.id);

	/* 5. Prepare output structures */
	output.out_public = input.in_public;

	if (pub->type == TPM2_ALG_ECC) {
		tss2_rc = extract_ecc_coordinates(&key_buffer,
						  &output.out_public);
		if (tss2_rc != TSS2_RC_SUCCESS)
			goto end;
	}

	/* 6. Create and setup object */
	tss2_rc = smw_object_alloc(ctx, &object_handle, attrs, key_desc.id,
				   input.primary_handle, &output.out_public,
				   &output.object_name);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	/* Set creation structures to empty (minimal implementation) */
	tss2_rc = build_creation_data(&output.out_public, &output.object_name,
				      &input.creation_pcr, &input.outside_info,
				      &output.creation_data);
	if (tss2_rc != TSS2_RC_SUCCESS) {
		DBG_TRACE("Failed to build creation data\n");
		goto end;
	}

	DBG_TRACE("Creation data built: %u bytes\n", output.creation_data.size);

	tss2_rc = build_creation_hash(&output.creation_data,
				      &output.creation_hash,
				      output.out_public.publicArea.nameAlg);
	if (tss2_rc != TSS2_RC_SUCCESS) {
		DBG_TRACE("Failed to compute creation hash\n");
		goto end;
	}

	DBG_TRACE("Creation hash computed: %u bytes\n",
		  output.creation_hash.size);

	tss2_rc =
		build_creation_ticket(input.primary_handle, output.object_name,
				      &output.creation_hash,
				      &output.creation_ticket);
	if (tss2_rc != TSS2_RC_SUCCESS) {
		DBG_TRACE("Failed to create creation ticket\n");
		goto end;
	}

	DBG_TRACE("Creation ticket created: tag=0x%04x, hierarchy=0x%08x\n",
		  output.creation_ticket.tag, output.creation_ticket.hierarchy);

	params_buffer = calloc(1, TPM2_MAX_CAP_BUFFER);
	if (!params_buffer) {
		tss2_rc = TSS2_TCTI_RC_MEMORY;
		goto end;
	}

	tss2_rc =
		Tss2_MU_TPM2B_PUBLIC_Marshal(&output.out_public, params_buffer,
					     TPM2_MAX_CAP_BUFFER,
					     &resp_params_size);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	tss2_rc = Tss2_MU_TPM2B_CREATION_DATA_Marshal(&output.creation_data,
						      params_buffer,
						      TPM2_MAX_CAP_BUFFER,
						      &resp_params_size);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	tss2_rc =
		Tss2_MU_TPM2B_DIGEST_Marshal(&output.creation_hash,
					     params_buffer, TPM2_MAX_CAP_BUFFER,
					     &resp_params_size);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	tss2_rc = Tss2_MU_TPMT_TK_CREATION_Marshal(&output.creation_ticket,
						   params_buffer,
						   TPM2_MAX_CAP_BUFFER,
						   &resp_params_size);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	tss2_rc = Tss2_MU_TPM2B_NAME_Marshal(&output.object_name, params_buffer,
					     TPM2_MAX_CAP_BUFFER,
					     &resp_params_size);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	/* 8. Build response */
	tss2_rc = build_auth_response(ctx, sess, TPM2_RC_SUCCESS,
				      TPM2_CC_CreatePrimary, tag, params_buffer,
				      resp_params_size, &nonce_caller,
				      &object_handle);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	DBG_TRACE("CreatePrimary success: handle=0x%08x, SMW ID=%d\n",
		  object_handle, key_desc.id);

end:
	/* Free allocated memory */
	if (params_buffer)
		free(params_buffer);

	if (response_hmac)
		free(response_hmac);

	if (tss2_rc != TSS2_RC_SUCCESS) {
		rc = tcti_rc_to_tpm2_rc(tss2_rc);
		tss2_rc = build_rc_response(ctx, TPM_HEADER_SIZE, tag, rc);
	}

	return tss2_rc;
}

uint32_t handle_readpublic(tcti_smw_context_t *ctx, uint16_t tag,
			   const uint8_t *cmd, size_t cmd_size)
{
	TPM2_RC rc = TPM2_RC_SUCCESS;
	TSS2_RC tss2_rc = TSS2_TCTI_RC_GENERAL_FAILURE;
	size_t offset = TPM_HEADER_SIZE;
	tcti_smw_object_t *obj = NULL;
	size_t resp_params_size = 0;

	/* Input parameters */
	TPM2_HANDLE object_handle = 0;

	/* Output parameters */
	TPM2B_PUBLIC out_public = { 0 };
	TPM2B_NAME name = { 0 };
	TPM2B_NAME qualified_name = { 0 };

	/* Session handling */
	uint32_t session_handle = 0;
	TPM2B_NONCE nonce_caller = { 0 };
	tcti_smw_session_t *sess = NULL;

	uint8_t *params_buffer = NULL;

	/* 1. Check initialization */
	if (!ctx->initialized) {
		tss2_rc = TSS2_TCTI_RC_BAD_SEQUENCE;
		goto end;
	}

	if (tag == TPM2_ST_SESSIONS) {
		tss2_rc = unmarshal_auth_area(cmd, cmd_size, &offset,
					      &nonce_caller, &session_handle);
		if (tss2_rc != TSS2_RC_SUCCESS)
			goto end;

		/* Find session */
		if (session_handle != TPM2_RH_PW) {
			sess = find_session_by_handle(ctx, session_handle);
			if (!sess || !sess->active) {
				tss2_rc = TSS2_TCTI_RC_IO_ERROR;
				goto end;
			}
		}
	}

	/* 2. Unmarshal input parameters */
	tss2_rc = Tss2_MU_UINT32_Unmarshal(cmd, cmd_size, &offset,
					   &object_handle);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	DBG_TRACE("ReadPublic for handle 0x%08x\n", object_handle);

	/* 3. Find the object in context */
	obj = find_object_by_handle(ctx, object_handle);
	if (!obj) {
		DBG_TRACE("Object handle 0x%08x not found\n", object_handle);
		tss2_rc = TSS2_TCTI_RC_IO_ERROR;
		goto end;
	}

	/* 4. Copy the public area stored during object creation */
	memcpy(&out_public, &obj->public_area, sizeof(TPM2B_PUBLIC));

	/* 5. Calculate object name (hash of public area) */
	tss2_rc = calculate_object_name(&out_public, &name);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	/* 6. As ELE does not handle hierarchy, qualified name = name */
	memcpy(&qualified_name, &name, sizeof(TPM2B_NAME));

	/* 7. Marshal output parameters */
	params_buffer = calloc(1, TPM2_MAX_CAP_BUFFER);
	if (!params_buffer) {
		tss2_rc = TSS2_TCTI_RC_MEMORY;
		goto end;
	}

	tss2_rc = Tss2_MU_TPM2B_PUBLIC_Marshal(&out_public, params_buffer,
					       TPM2_MAX_CAP_BUFFER,
					       &resp_params_size);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	tss2_rc = Tss2_MU_TPM2B_NAME_Marshal(&name, params_buffer,
					     TPM2_MAX_CAP_BUFFER,
					     &resp_params_size);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	tss2_rc = Tss2_MU_TPM2B_NAME_Marshal(&qualified_name, params_buffer,
					     TPM2_MAX_CAP_BUFFER,
					     &resp_params_size);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	/* 8. Build response */
	tss2_rc = build_auth_response(ctx, sess, TPM2_RC_SUCCESS,
				      TPM2_CC_ReadPublic, tag, params_buffer,
				      resp_params_size, &nonce_caller, NULL);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	DBG_TRACE("ReadPublic success\n");

end:
	/* Free allocated memory */
	if (params_buffer)
		free(params_buffer);

	if (tss2_rc != TSS2_RC_SUCCESS) {
		rc = tcti_rc_to_tpm2_rc(tss2_rc);
		tss2_rc = build_rc_response(ctx, TPM_HEADER_SIZE, tag, rc);
	}

	return tss2_rc;
}

uint32_t handle_create(tcti_smw_context_t *ctx, uint16_t tag,
		       const uint8_t *cmd, size_t cmd_size)
{
	TPM2_RC rc = TPM2_RC_SUCCESS;
	TSS2_RC tss2_rc = TSS2_TCTI_RC_GENERAL_FAILURE;
	enum smw_status_code smw_status = SMW_STATUS_OK;
	size_t resp_params_size = 0;

	/* Input parameters */
	create_input_t input = { 0 };

	/* Output parameters */
	create_output_t output = { 0 };
	TPMT_PUBLIC *pub = NULL;
	unsigned char public_data_buf[TPM2_MAX_ECC_KEY_BYTES * 2] = { 0 };
	TPM2B_NAME object_name = { 0 };

	/* Session handling */
	uint32_t session_handle = 0;
	TPM2B_NONCE nonce_caller = { 0 };
	tcti_smw_session_t *sess = NULL;

	struct smw_key_descriptor key_desc = { 0 };
	struct smw_keypair_buffer key_buffer = { 0 };
	struct smw_generate_key_args gen_args = { 0 };

	uint8_t *params_buffer = NULL;
	tcti_smw_object_t *object = NULL;

	if (!ctx || !cmd) {
		tss2_rc = TSS2_TCTI_RC_BAD_REFERENCE;
		goto end;
	}

	/* 1. Check initialization */
	if (!ctx->initialized) {
		tss2_rc = TSS2_TCTI_RC_BAD_SEQUENCE;
		goto end;
	}

	/* 2. Unmarshal command parameters */
	tss2_rc = create_unmarshal(cmd, cmd_size, &input, &nonce_caller,
				   &session_handle);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	/* Find session */
	if (session_handle != TPM2_RH_PW) {
		sess = find_session_by_handle(ctx, session_handle);
		if (!sess || !sess->active) {
			tss2_rc = TSS2_TCTI_RC_IO_ERROR;
			goto end;
		}
	}

	/* Find parent object */
	object = find_object_by_handle(ctx, input.primary_handle);
	if (!object) {
		DBG_TRACE("Object handle 0x%08x not found\n",
			  input.primary_handle);
		tss2_rc = TSS2_TCTI_RC_IO_ERROR;
		goto end;
	}

	/* 3. Validate key type and prepare SMW structures */
	pub = &input.in_public.publicArea;

	if (pub->type == TPM2_ALG_ECC)
		key_buffer.gen.public_data = public_data_buf;

	tss2_rc = configure_smw_key_descriptor(pub, &key_desc, &key_buffer);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	/* 4. Call SMW to generate key */
	gen_args.subsystem_name = SMW_SUBSYSTEM_NAME_ELE;
	gen_args.key_descriptor = &key_desc;

	smw_status = smw_generate_key(&gen_args);
	if (smw_status != SMW_STATUS_OK &&
	    smw_status != SMW_STATUS_KEY_POLICY_WARNING_IGNORED) {
		DBG_TRACE("SMW key generation failed: %d\n", smw_status);
		tss2_rc = smw_rc_to_tcti_rc(smw_status);
		goto end;
	}

	DBG_TRACE("Key generated successfully, SMW ID: %d\n", key_desc.id);

	/* 5. Prepare output structures */
	output.out_private.size = SMW_PRIVATE_BLOB_MAGIC_LEN + sizeof(uint32_t);
	memcpy(output.out_private.buffer, SMW_PRIVATE_BLOB_MAGIC,
	       SMW_PRIVATE_BLOB_MAGIC_LEN);
	memcpy(&output.out_private.buffer[SMW_PRIVATE_BLOB_MAGIC_LEN],
	       &key_desc.id, sizeof(uint32_t));

	output.out_public = input.in_public;

	if (pub->type == TPM2_ALG_ECC) {
		tss2_rc = extract_ecc_coordinates(&key_buffer,
						  &output.out_public);
		if (tss2_rc != TSS2_RC_SUCCESS)
			goto end;
	}

	/* Set creation structures to empty (minimal implementation) */
	tss2_rc = calculate_object_name(&output.out_public, &object_name);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	tss2_rc = build_creation_data(&output.out_public, &object_name,
				      &input.creation_pcr, &input.outside_info,
				      &output.creation_data);
	if (tss2_rc != TSS2_RC_SUCCESS) {
		DBG_TRACE("Failed to build creation data\n");
		goto end;
	}

	DBG_TRACE("Creation data built: %u bytes\n", output.creation_data.size);

	tss2_rc = build_creation_hash(&output.creation_data,
				      &output.creation_hash,
				      output.out_public.publicArea.nameAlg);
	if (tss2_rc != TSS2_RC_SUCCESS) {
		DBG_TRACE("Failed to compute creation hash\n");
		goto end;
	}

	DBG_TRACE("Creation hash computed: %u bytes\n",
		  output.creation_hash.size);

	tss2_rc = build_creation_ticket(object->hierarchy, object_name,
					&output.creation_hash,
					&output.creation_ticket);
	if (tss2_rc != TSS2_RC_SUCCESS) {
		DBG_TRACE("Failed to create creation ticket\n");
		goto end;
	}

	DBG_TRACE("Creation ticket created: tag=0x%04x, hierarchy=0x%08x\n",
		  output.creation_ticket.tag, output.creation_ticket.hierarchy);

	params_buffer = calloc(1, TPM2_MAX_CAP_BUFFER);
	if (!params_buffer) {
		tss2_rc = TSS2_TCTI_RC_MEMORY;
		goto end;
	}

	/* 6. Calculate params_size for all output parameters */
	tss2_rc = Tss2_MU_TPM2B_PRIVATE_Marshal(&output.out_private,
						params_buffer,
						TPM2_MAX_CAP_BUFFER,
						&resp_params_size);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	tss2_rc =
		Tss2_MU_TPM2B_PUBLIC_Marshal(&output.out_public, params_buffer,
					     TPM2_MAX_CAP_BUFFER,
					     &resp_params_size);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	tss2_rc = Tss2_MU_TPM2B_CREATION_DATA_Marshal(&output.creation_data,
						      params_buffer,
						      TPM2_MAX_CAP_BUFFER,
						      &resp_params_size);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	tss2_rc =
		Tss2_MU_TPM2B_DIGEST_Marshal(&output.creation_hash,
					     params_buffer, TPM2_MAX_CAP_BUFFER,
					     &resp_params_size);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	tss2_rc = Tss2_MU_TPMT_TK_CREATION_Marshal(&output.creation_ticket,
						   params_buffer,
						   TPM2_MAX_CAP_BUFFER,
						   &resp_params_size);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	/* 7. Build auth response */
	tss2_rc = build_auth_response(ctx, sess, TPM2_RC_SUCCESS,
				      TPM2_CC_Create, tag, params_buffer,
				      resp_params_size, &nonce_caller, NULL);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	DBG_TRACE("Create success: SMW ID=%d\n", key_desc.id);

end:
	/* Free allocated memory */
	if (params_buffer)
		free(params_buffer);

	if (tss2_rc != TSS2_RC_SUCCESS) {
		rc = tcti_rc_to_tpm2_rc(tss2_rc);
		tss2_rc = build_rc_response(ctx, TPM_HEADER_SIZE, tag, rc);
	}

	return tss2_rc;
}

uint32_t handle_load(tcti_smw_context_t *ctx, uint16_t tag, const uint8_t *cmd,
		     size_t cmd_size)
{
	TPM2_RC rc = TPM2_RC_SUCCESS;
	TSS2_RC tss2_rc = TSS2_TCTI_RC_GENERAL_FAILURE;
	size_t resp_params_size = 0;

	/* Input parameters */
	load_input_t input = { 0 };
	tcti_smw_object_t *parent = NULL;

	/* Output parameters */
	TPM2_HANDLE object_handle = 0;
	TPM2B_NAME object_name = { 0 };
	TPMT_PUBLIC *pub = NULL;
	uint32_t smw_key_id = 0;

	/* Session handling */
	uint32_t session_handle = 0;
	TPM2B_NONCE nonce_caller = { 0 };
	tcti_smw_session_t *sess = NULL;

	uint8_t *params_buffer = NULL;

	if (!ctx || !cmd) {
		tss2_rc = TSS2_TCTI_RC_BAD_REFERENCE;
		goto end;
	}

	/* 1. Check initialization */
	if (!ctx->initialized) {
		tss2_rc = TSS2_TCTI_RC_BAD_SEQUENCE;
		goto end;
	}

	/* 2. Unmarshal command parameters */
	tss2_rc = load_unmarshal(cmd, cmd_size, &input, &nonce_caller,
				 &session_handle);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	/* Find session */
	if (session_handle != TPM2_RH_PW) {
		sess = find_session_by_handle(ctx, session_handle);
		if (!sess || !sess->active) {
			tss2_rc = TSS2_TCTI_RC_IO_ERROR;
			goto end;
		}
	}

	/* Find parent object */
	parent = find_object_by_handle(ctx, input.parent_handle);
	if (!parent) {
		tss2_rc = TSS2_TCTI_RC_IO_ERROR;
		goto end;
	}

	/* 3. Validate and extract SMW key ID from private blob */
	if (input.in_private.size <
	    (SMW_PRIVATE_BLOB_MAGIC_LEN + sizeof(uint32_t))) {
		DBG_TRACE("Invalid private blob size: %u bytes\n",
			  input.in_private.size);
		tss2_rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	/* Verify magic string */
	if (memcmp(input.in_private.buffer, SMW_PRIVATE_BLOB_MAGIC,
		   SMW_PRIVATE_BLOB_MAGIC_LEN) != 0) {
		DBG_TRACE("Invalid private blob magic string\n");
		tss2_rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	/* Extract SMW key ID */
	memcpy(&smw_key_id,
	       &input.in_private.buffer[SMW_PRIVATE_BLOB_MAGIC_LEN],
	       sizeof(uint32_t));

	DBG_TRACE("Loading key with SMW ID: %u\n", smw_key_id);

	/* 4. Validate key type from public area */
	pub = &input.in_public.publicArea;

	if (pub->type != TPM2_ALG_ECC && pub->type != TPM2_ALG_KEYEDHASH) {
		DBG_TRACE("Unsupported key type: 0x%04x\n", pub->type);
		tss2_rc = TSS2_TCTI_RC_IO_ERROR;
		goto end;
	}

	/* 5. Allocate object handle and associate with SMW key ID */
	tss2_rc = smw_object_alloc(ctx, &object_handle, pub->objectAttributes,
				   smw_key_id, parent->hierarchy,
				   &input.in_public, &object_name);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	/* 6. Prepare parameters buffer for HMAC calculation */
	params_buffer = calloc(1, TPM2_MAX_CAP_BUFFER);
	if (!params_buffer) {
		tss2_rc = TSS2_TCTI_RC_MEMORY;
		goto end;
	}

	tss2_rc = Tss2_MU_TPM2B_NAME_Marshal(&object_name, params_buffer,
					     TPM2_MAX_CAP_BUFFER,
					     &resp_params_size);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	/* 7. Build auth response */
	tss2_rc = build_auth_response(ctx, sess, TPM2_RC_SUCCESS, TPM2_CC_Load,
				      tag, params_buffer, resp_params_size,
				      &nonce_caller, &object_handle);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	DBG_TRACE("Load success: handle=0x%08x, SMW ID=%u\n", object_handle,
		  smw_key_id);

end:
	/* Free allocated memory */
	if (params_buffer)
		free(params_buffer);

	if (tss2_rc != TSS2_RC_SUCCESS) {
		rc = tcti_rc_to_tpm2_rc(tss2_rc);
		tss2_rc = build_rc_response(ctx, TPM_HEADER_SIZE, tag, rc);
	}

	return tss2_rc;
}
