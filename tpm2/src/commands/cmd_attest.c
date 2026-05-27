// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <string.h>

#include <tss2/tss2_mu.h>

#include "utils.h"
#include "commands.h"
#include "trace.h"

#include "smw_keymgr.h"
#include "crypto.h"

static uint32_t decrypt_seed_rsa(tcti_smw_object_t *ek,
				 const TPM2B_ENCRYPTED_SECRET *secret,
				 uint8_t *seed, size_t *seed_size)
{
	TSS2_RC rc = TSS2_RC_SUCCESS;
	enum smw_status_code smw_status = SMW_STATUS_OK;
	struct smw_key_descriptor key_desc = { 0 };
	struct smw_asymmetric_encryption_args smw_args = { 0 };

	if (!ek || !secret || !seed || !seed_size) {
		rc = TSS2_TCTI_RC_BAD_REFERENCE;
		goto end;
	}

	/* Validate key type */
	if (ek->public_area.publicArea.type != TPM2_ALG_RSA) {
		DBG_TRACE("EK is not RSA: 0x%04x\n",
			  ek->public_area.publicArea.type);
		rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	/* Validate EK has decrypt attribute */
	if (!(ek->attributes & TPMA_OBJECT_DECRYPT)) {
		DBG_TRACE("EK does not have DECRYPT attribute\n");
		rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	DBG_TRACE("Decrypting seed with EK:\n"
		  "  SMW key ID: %u\n"
		  "  RSA key size: %u bits\n"
		  "  secret.size: %u\n",
		  ek->smw_key_id,
		  ek->public_area.publicArea.parameters.rsaDetail.keyBits,
		  secret->size);

	key_desc.id = ek->smw_key_id;

	/* Setup decryption args - RSA-PKCS with SHA256 */
	smw_args.subsystem_name = SMW_SUBSYSTEM_NAME_ELE;
	smw_args.algo =
		SMW_ATTR_ALGO_ASYMMETRIC_ENCRYPTION_RSA(SMW_ATTR_MODE_PKCS1_1_5,
							SMW_ATTR_HASH_NONE);
	smw_args.key_descriptor = &key_desc;
	smw_args.input_length = secret->size;
	smw_args.input = (uint8_t *)secret->secret;
	if (SET_OVERFLOW(*seed_size, smw_args.output_length)) {
		DBG_TRACE("Seed size too large: %zu\n", *seed_size);
		rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}
	smw_args.output = seed;

	smw_status = smw_asymmetric_decrypt(&smw_args);
	if (smw_status != SMW_STATUS_OK) {
		DBG_TRACE("RSA decrypt failed: %d\n", smw_status);
		rc = smw_rc_to_tcti_rc(smw_status);
		goto end;
	}

	*seed_size = smw_args.output_length;

	DBG_TRACE("Seed decrypted successfully: %zu bytes\n", *seed_size);

end:
	DBG_TRACE_COND(rc != TSS2_RC_SUCCESS, "return error: 0x%08x\n", rc);
	return rc;
}

static uint32_t decrypt_credential_blob(const TPM2B_ID_OBJECT *credential_blob,
					const TPM2B_NAME *ak_name,
					const uint8_t *seed,
					TPM2B_DIGEST *credential)
{
	TSS2_RC rc = TSS2_RC_SUCCESS;
	enum smw_status_code smw_status = SMW_STATUS_OK;

	struct smw_aead_args aead_args = { 0 };
	struct smw_aead_init_args init_args = { 0 };
	struct smw_aead_aad_args aad_args = { 0 };
	struct smw_aead_final_args final_args = { 0 };
	struct smw_aead_data_args data_args = { 0 };
	struct smw_key_descriptor key_desc = { 0 };
	struct smw_keypair_buffer key_buffer = { 0 };

	const uint8_t *ptr = NULL;
	const uint8_t *iv = NULL;
	const uint8_t *ciphertext = NULL;
	const uint8_t *tag = NULL;
	size_t offset = 0;
	uint16_t stored_name_size = 0;
	size_t aad_size = 0;
	size_t ciphertext_size = 0;
	size_t min_blob_size = 0;
	size_t temp_size = 0;

	if (!credential_blob || !ak_name || !seed || !credential) {
		rc = TSS2_TCTI_RC_BAD_REFERENCE;
		goto end;
	}

	ptr = credential_blob->credential;

	/* Calculate minimum blob size */
	min_blob_size = SMW_CRED_BLOB_MAGIC_LEN + sizeof(uint16_t) +
			SEAL_NONCE_SIZE + SEAL_TAG_SIZE;

	if (credential_blob->size < min_blob_size) {
		DBG_TRACE("Credential blob too small: %u < %zu\n",
			  credential_blob->size, min_blob_size);
		rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	/* 1. Verify magic */
	if (memcmp(ptr, SMW_CRED_BLOB_MAGIC, SMW_CRED_BLOB_MAGIC_LEN) != 0) {
		DBG_TRACE("Invalid credential blob magic\n");
		rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	offset += SMW_CRED_BLOB_MAGIC_LEN;

	/* 2. Extract stored AK Name size */
	memcpy(&stored_name_size, ptr + offset, sizeof(uint16_t));

	if (ADD_OVERFLOW(offset, sizeof(uint16_t), &offset)) {
		rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	/* 3. Verify AK Name size matches */
	if (stored_name_size != ak_name->size) {
		DBG_TRACE("AK Name size mismatch:\n"
			  "  stored: %u\n"
			  "  expected: %u\n",
			  stored_name_size, ak_name->size);
		rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	/* Validate we have enough data for the name */
	if (ADD_OVERFLOW(offset, stored_name_size, &temp_size)) {
		rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	temp_size += SEAL_NONCE_SIZE + SEAL_TAG_SIZE;

	if (credential_blob->size < temp_size) {
		DBG_TRACE("Credential blob too small for stored name\n");
		rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	/* 4. Verify AK Name matches (binding check) */
	if (memcmp(ptr + offset, ak_name->name, ak_name->size) != 0) {
		DBG_TRACE("AK Name mismatch credential not bound to this AK\n");
		DBG_TRACE("Stored AK Name:\n");
		DBG_BUF_HEX(ptr + offset, stored_name_size);
		DBG_TRACE("Expected AK Name:\n");
		DBG_BUF_HEX(ak_name->name, ak_name->size);
		rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	offset += ak_name->size;
	aad_size = offset;

	DBG_TRACE("AK Name binding verified successfully\n");

	/* 5. Extract IV */
	iv = ptr + offset;
	offset += SEAL_NONCE_SIZE;

	/* 6. Calculate ciphertext size */
	ciphertext_size = credential_blob->size - aad_size - SEAL_NONCE_SIZE -
			  SEAL_TAG_SIZE;

	if (ciphertext_size == 0) {
		DBG_TRACE("Ciphertext size is zero\n");
		rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	if (ciphertext_size > sizeof(credential->buffer)) {
		DBG_TRACE("Credential too large: %zu > %zu\n", ciphertext_size,
			  sizeof(credential->buffer));
		rc = TSS2_TCTI_RC_INSUFFICIENT_BUFFER;
		goto end;
	}

	ciphertext = ptr + offset;
	tag = ptr + offset + ciphertext_size;

	DBG_TRACE("Credential blob structure:\n"
		  "  AAD size: %zu\n"
		  "  IV offset: %zu\n"
		  "  Ciphertext size: %zu\n"
		  "  Tag offset: %zu\n",
		  aad_size, aad_size, ciphertext_size,
		  aad_size + SEAL_NONCE_SIZE + ciphertext_size);

	/* 7. Setup AEAD decryption with seed as key */
	key_buffer.gen.private_data = (uint8_t *)seed;
	key_buffer.gen.private_length = SMW_SEED_SIZE;

	key_desc.type_name = SMW_KEY_TYPE_NAME_AES;
	key_desc.buffer = &key_buffer;
	key_desc.security_size = BYTES_TO_BITS(SMW_SEED_SIZE);

	init_args.subsystem_name = SMW_SUBSYSTEM_NAME_ELE;
	init_args.mode_name = SMW_AEAD_MODE_NAME_GCM;
	init_args.op_type_name = SMW_AEAD_OP_TYPE_NAME_DECRYPT;
	init_args.user_iv = (unsigned char *)iv;
	init_args.user_iv_length = SEAL_NONCE_SIZE;
	init_args.iv_length = SEAL_NONCE_SIZE;
	init_args.plaintext_length = ciphertext_size;
	init_args.key_desc = &key_desc;

	aad_args.data = (unsigned char *)ptr;
	aad_args.data_length = aad_size;

	data_args.input = (unsigned char *)ciphertext;
	data_args.input_length = ciphertext_size;
	data_args.output = credential->buffer;
	data_args.output_length = sizeof(credential->buffer);

	final_args.data = &data_args;
	final_args.tag = (unsigned char *)tag;
	final_args.tag_length = SEAL_TAG_SIZE;

	aead_args.init = &init_args;
	aead_args.aad = &aad_args;
	aead_args.final = &final_args;

	/* 8. Execute AEAD decryption */
	smw_status = smw_aead(&aead_args);
	if (smw_status != SMW_STATUS_OK) {
		DBG_TRACE("AEAD decrypt failed: %d\n", smw_status);
		DBG_TRACE("This could mean:\n"
			  "  - Wrong seed (EK mismatch)\n"
			  "  - Tampered credential blob\n"
			  "  - AK Name was modified\n");
		rc = smw_rc_to_tcti_rc(smw_status);
		goto end;
	}

	credential->size = ciphertext_size;

	DBG_TRACE("Credential decrypted successfully: %u bytes\n",
		  credential->size);

end:
	DBG_TRACE_COND(rc != TSS2_RC_SUCCESS, "return error: 0x%08x\n", rc);
	return rc;
}

static uint32_t encrypt_seed_rsa(tcti_smw_object_t *ek, uint8_t *seed,
				 size_t seed_size,
				 TPM2B_ENCRYPTED_SECRET *secret)
{
	TSS2_RC rc = TSS2_RC_SUCCESS;
	enum smw_status_code smw_status = SMW_STATUS_OK;
	struct smw_asymmetric_encryption_args smw_args = { 0 };
	struct smw_key_descriptor key_desc = { 0 };

	if (!ek || !seed || !secret) {
		rc = TSS2_TCTI_RC_BAD_REFERENCE;
		goto end;
	}

	/* Validate key type */
	if (ek->public_area.publicArea.type != TPM2_ALG_RSA) {
		DBG_TRACE("EK is not RSA: 0x%04x\n",
			  ek->public_area.publicArea.type);
		rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	DBG_TRACE("Encrypting seed with RSA-%u\n",
		  ek->public_area.publicArea.parameters.rsaDetail.keyBits);

	key_desc.id = ek->smw_key_id;

	/* Setup encryption args - RSA-PKCS with SHA256 */
	smw_args.subsystem_name = SMW_SUBSYSTEM_NAME_ELE;
	smw_args.algo =
		SMW_ATTR_ALGO_ASYMMETRIC_ENCRYPTION_RSA(SMW_ATTR_MODE_PKCS1_1_5,
							SMW_ATTR_HASH_NONE);
	smw_args.key_descriptor = &key_desc;
	if (SET_OVERFLOW(seed_size, smw_args.input_length)) {
		DBG_TRACE("Seed size too large: %zu\n", seed_size);
		rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}
	smw_args.input = seed;
	smw_args.output_length = sizeof(secret->secret);
	smw_args.output = secret->secret;

	smw_status = smw_asymmetric_encrypt(&smw_args);
	if (smw_status != SMW_STATUS_OK) {
		DBG_TRACE("RSA encrypt failed: %d\n", smw_status);
		rc = smw_rc_to_tcti_rc(smw_status);
		goto end;
	}
	secret->size = smw_args.output_length;

	DBG_TRACE("Seed encrypted: secret.size=%u\n", secret->size);

end:
	return rc;
}

static uint32_t build_credential_blob(const TPM2B_DIGEST *credential,
				      const TPM2B_NAME *ak_name,
				      const uint8_t *seed,
				      TPM2B_ID_OBJECT *credential_blob)
{
	TSS2_RC rc = TSS2_RC_SUCCESS;
	enum smw_status_code smw_status = SMW_STATUS_OK;

	struct smw_aead_args aead_args = { 0 };
	struct smw_aead_init_args init_args = { 0 };
	struct smw_aead_aad_args aad_args = { 0 };
	struct smw_aead_final_args final_args = { 0 };
	struct smw_aead_data_args data_args = { 0 };
	struct smw_key_descriptor key_desc = { 0 };
	struct smw_keypair_buffer key_buffer = { 0 };

	uint8_t *ptr = NULL;
	size_t offset = 0;
	size_t iv_offset = 0;
	size_t aad_size = 0;
	uint8_t output_iv[SEAL_NONCE_SIZE] = { 0 };

	if (!credential || !ak_name || !seed || !credential_blob) {
		rc = TSS2_TCTI_RC_BAD_REFERENCE;
		goto end;
	}

	ptr = credential_blob->credential;

	/* Build AAD: MAGIC || AK_Name_size || AK_Name */
	memcpy(ptr + offset, SMW_CRED_BLOB_MAGIC, SMW_CRED_BLOB_MAGIC_LEN);
	offset += SMW_CRED_BLOB_MAGIC_LEN;

	memcpy(ptr + offset, &ak_name->size, sizeof(uint16_t));

	if (ADD_OVERFLOW(offset, sizeof(uint16_t), &offset)) {
		rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	memcpy(ptr + offset, ak_name->name, ak_name->size);

	if (ADD_OVERFLOW(offset, ak_name->size, &offset)) {
		rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	aad_size = offset;

	/* Reserve space for IV */
	iv_offset = offset;
	offset += SEAL_NONCE_SIZE;

	/* Setup AEAD with seed as key */
	key_buffer.gen.private_data = (uint8_t *)seed;
	key_buffer.gen.private_length = SMW_SEED_SIZE;

	key_desc.type_name = SMW_KEY_TYPE_NAME_AES;
	key_desc.buffer = &key_buffer;
	key_desc.security_size = BYTES_TO_BITS(SMW_SEED_SIZE);

	init_args.subsystem_name = SMW_SUBSYSTEM_NAME_ELE;
	init_args.mode_name = SMW_AEAD_MODE_NAME_GCM;
	init_args.op_type_name = SMW_AEAD_OP_TYPE_NAME_ENCRYPT;
	init_args.iv_length = SEAL_NONCE_SIZE;
	init_args.plaintext_length = credential->size;
	init_args.key_desc = &key_desc;

	aad_args.data = ptr;
	if (SET_OVERFLOW(aad_size, aad_args.data_length)) {
		rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	data_args.input = (uint8_t *)credential->buffer;
	data_args.input_length = credential->size;
	data_args.output = ptr + offset;
	data_args.output_length = credential->size;

	final_args.data = &data_args;
	final_args.tag = ptr + offset + credential->size;
	final_args.tag_length = SEAL_TAG_SIZE;
	final_args.output_iv = output_iv;
	final_args.output_iv_length = SEAL_NONCE_SIZE;

	aead_args.init = &init_args;
	aead_args.aad = &aad_args;
	aead_args.final = &final_args;

	smw_status = smw_aead(&aead_args);
	if (smw_status != SMW_STATUS_OK) {
		DBG_TRACE("AEAD encrypt failed: %d\n", smw_status);
		rc = smw_rc_to_tcti_rc(smw_status);
		goto end;
	}

	/* Store IV */
	memcpy(ptr + iv_offset, output_iv, SEAL_NONCE_SIZE);

	credential_blob->size =
		aad_size + SEAL_NONCE_SIZE + credential->size + SEAL_TAG_SIZE;

	DBG_TRACE("Credential blob built:\n"
		  "  AAD: %zu bytes (magic + name)\n"
		  "  IV: %u bytes\n"
		  "  Encrypted credential: %u bytes\n"
		  "  Tag: %u bytes\n"
		  "  Total: %u bytes\n",
		  aad_size, SEAL_NONCE_SIZE, credential->size, SEAL_TAG_SIZE,
		  credential_blob->size);

end:
	return rc;
}

static uint32_t decrypt_sealed_data(TPMI_RH_HIERARCHY hierarchy,
				    const uint8_t *blob, uint16_t blob_size,
				    uint8_t *plaintext_out,
				    uint16_t *plaintext_size)
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

	const uint8_t *ptr = NULL;
	size_t offset = 0;
	uint8_t *proof = NULL;
	uint16_t stored_plaintext_size = 0;
	uint32_t stored_hierarchy = 0;
	uint16_t ciphertext_size = 0;

	/* Pointers to blob sections */
	const uint8_t *iv = blob + SEAL_AAD_SIZE;
	const uint8_t *ciphertext = blob + SEAL_AAD_SIZE + SEAL_NONCE_SIZE;
	const uint8_t *tag = blob + blob_size - SEAL_TAG_SIZE;

	if (!blob || !plaintext_out || !plaintext_size) {
		rc = TSS2_TCTI_RC_BAD_REFERENCE;
		goto end;
	}

	/* 1. Verify minimum size */
	if (blob_size < SEAL_AAD_SIZE + SEAL_NONCE_SIZE + SEAL_TAG_SIZE) {
		DBG_TRACE("Blob too small: %u < %lu\n", blob_size,
			  SEAL_AAD_SIZE + SEAL_NONCE_SIZE + SEAL_TAG_SIZE);
		rc = TSS2_TCTI_RC_INSUFFICIENT_BUFFER;
		goto end;
	}

	/* 2. Verify magic */
	ptr = blob;
	if (memcmp(ptr, SMW_SEALED_BLOB_MAGIC, SMW_SEALED_BLOB_MAGIC_LEN) !=
	    0) {
		DBG_TRACE("Invalid blob magic\n");
		rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}
	offset += SMW_SEALED_BLOB_MAGIC_LEN;

	/* 3. Extract plaintext size */
	memcpy(&stored_plaintext_size, ptr + offset, sizeof(uint16_t));
	offset += sizeof(uint16_t);
	ciphertext_size =
		blob_size - SEAL_AAD_SIZE - SEAL_NONCE_SIZE - SEAL_TAG_SIZE;

	if (ciphertext_size != stored_plaintext_size) {
		DBG_TRACE("Size mismatch: stored=%u, calculated=%u\n",
			  stored_plaintext_size, ciphertext_size);
		rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	/* 4. Extract hierarchy */
	memcpy(&stored_hierarchy, ptr + offset, sizeof(TPMI_RH_HIERARCHY));

	if (stored_hierarchy != hierarchy) {
		DBG_TRACE("Hierarchy mismatch: stored=0x%08x, expected=0x%08x\n",
			  stored_hierarchy, hierarchy);
		rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	/* 5. Validate sizes */
	if (*plaintext_size < stored_plaintext_size) {
		DBG_TRACE("Output buffer too small: %u < %u\n", *plaintext_size,
			  stored_plaintext_size);
		rc = TSS2_TCTI_RC_INSUFFICIENT_BUFFER;
		goto end;
	}

	/* 6. Get hierarchy proof key */
	proof = calloc(1, TPM2_SHA256_DIGEST_SIZE);
	if (!proof) {
		rc = TSS2_TCTI_RC_MEMORY;
		goto end;
	}

	rc = get_hierarchy_proof_key(hierarchy, proof);
	if (rc != TSS2_RC_SUCCESS)
		goto end;

	/* 7. Setup AEAD key descriptor */
	key_buffer.gen.private_data = proof;
	key_buffer.gen.private_length = TPM2_SHA256_DIGEST_SIZE;

	key_desc.type_name = SMW_KEY_TYPE_NAME_AES;
	key_desc.buffer = &key_buffer;
	key_desc.security_size = BYTES_TO_BITS(TPM2_SHA256_DIGEST_SIZE);

	/* 8. Setup AEAD init args */
	init_args.subsystem_name = SMW_SUBSYSTEM_NAME_ELE;
	init_args.mode_name = SMW_AEAD_MODE_NAME_GCM;
	init_args.op_type_name = SMW_AEAD_OP_TYPE_NAME_DECRYPT;
	init_args.user_iv = (unsigned char *)iv;
	init_args.user_iv_length = SEAL_NONCE_SIZE;
	init_args.iv_length = SEAL_NONCE_SIZE;
	init_args.plaintext_length = stored_plaintext_size;
	init_args.key_desc = &key_desc;

	/* AAD = entire header */
	aad_args.data = (unsigned char *)ptr;
	aad_args.data_length = SEAL_AAD_SIZE;

	/* Data args */
	data_args.input = (unsigned char *)ciphertext;
	data_args.input_length = ciphertext_size;
	data_args.output = plaintext_out;
	data_args.output_length = *plaintext_size;

	/* Final args */
	final_args.data = &data_args;
	final_args.tag = (unsigned char *)tag;
	final_args.tag_length = SEAL_TAG_SIZE;

	/* Assemble AEAD args */
	aead_args.init = &init_args;
	aead_args.aad = &aad_args;
	aead_args.final = &final_args;

	/* Execute AEAD decryption */
	smw_status = smw_aead(&aead_args);
	if (smw_status != SMW_STATUS_OK) {
		DBG_TRACE("AEAD decrypt failed: %d\n", smw_status);
		rc = smw_rc_to_tcti_rc(smw_status);
		goto end;
	}

	*plaintext_size = stored_plaintext_size;

	DBG_TRACE("AEAD unseal success\n");

end:
	if (proof)
		free(proof);

	DBG_TRACE_COND(rc != TSS2_RC_SUCCESS, "return error: 0x%08x\n", rc);
	return rc;
}

static uint32_t verify_creation_ticket(TPMI_RH_HIERARCHY hierarchy,
				       const tcti_smw_object_t *object,
				       const TPM2B_DIGEST creation_hash,
				       TPMT_TK_CREATION ticket)
{
	TSS2_RC rc = TSS2_TCTI_RC_BAD_VALUE;
	size_t digest_size = ticket.digest.size;

	/* 1. Validate creation ticket */
	if (ticket.tag != TPM2_ST_CREATION) {
		DBG_TRACE("Invalid creation ticket tag:\n"
			  "0x%04x (expected 0x%04x)\n",
			  ticket.tag, TPM2_ST_CREATION);
		goto end;
	}

	/* 2. Validate hierarchy matches */
	if (ticket.hierarchy != hierarchy) {
		DBG_TRACE("Hierarchy mismatch:\n"
			  "  ticket.hierarchy: 0x%08x\n"
			  "  expected: 0x%08x\n",
			  ticket.hierarchy, hierarchy);
		goto end;
	}

	/* 3. Handle NULL ticket (empty digest) */
	if (!ticket.digest.size) {
		DBG_TRACE("NULL ticket (empty digest)\n"
			  "- skipping verification\n");
		rc = TSS2_RC_SUCCESS;
		goto end;
	}

	/* 4. Validate ticket digest size */
	if (ticket.digest.size != TPM2_SHA256_DIGEST_SIZE) {
		DBG_TRACE("Invalid ticket digest size: %u (expected %u)\n",
			  ticket.digest.size, TPM2_SHA256_DIGEST_SIZE);
		goto end;
	}

	/* 5. Compute expected HMAC using common function */
	rc = compute_creation_ticket_hmac(hierarchy, &object->object_name,
					  &creation_hash, ticket.digest.buffer,
					  &digest_size, true);
	if (rc != TSS2_RC_SUCCESS) {
		DBG_TRACE("Failed to compute HMAC for verification\n");
		goto end;
	}

	DBG_TRACE("Ticket verification SUCCESS!\n"
		  "Ticket is authentic and valid\n");

end:
	DBG_TRACE_COND(rc != TSS2_RC_SUCCESS, "return error: 0x%08x\n", rc);
	return rc;
}

static uint32_t build_tpms_attest_creation(TPMS_ATTEST *attest,
					   tcti_smw_object_t *object,
					   tcti_smw_object_t *signer,
					   const uint8_t *qualifying_data,
					   uint16_t qualifying_data_size,
					   const uint8_t *creation_hash,
					   uint16_t creation_hash_size)
{
	TSS2_RC rc = TSS2_TCTI_RC_BAD_VALUE;

	if (!attest || !creation_hash)
		goto end;

	memset(attest, 0, sizeof(*attest));

	/* 1. Magic value - indicates TPM generated */
	attest->magic = TPM2_GENERATED_VALUE;

	/* 2. Type - ATTEST_CREATION */
	attest->type = TPM2_ST_ATTEST_CREATION;

	/* 3. Qualified signer Name */
	if (signer) {
		/* Compute Name of signing key */
		rc = calculate_object_name(&signer->public_area,
					   &attest->qualifiedSigner);
		if (rc != TSS2_RC_SUCCESS) {
			DBG_TRACE("Failed to compute signer Name\n");
			goto end;
		}
	} else {
		/* NULL signer - empty qualifiedSigner */
		attest->qualifiedSigner.size = 0;
	}

	/* 4. Extra data (user-provided qualifying data) */
	attest->extraData.size = qualifying_data_size;
	if (qualifying_data && qualifying_data_size > 0) {
		if (qualifying_data_size > sizeof(attest->extraData.buffer)) {
			DBG_TRACE("qualifyingData too large: %u > %zu\n",
				  qualifying_data_size,
				  sizeof(attest->extraData.buffer));
			rc = TSS2_TCTI_RC_BAD_VALUE;
			goto end;
		}

		memcpy(attest->extraData.buffer, qualifying_data,
		       qualifying_data_size);
	}

	/* 5. Clock info (simulated) */
	attest->clockInfo.clock = 0;
	attest->clockInfo.resetCount = 0;
	attest->clockInfo.restartCount = 0;
	attest->clockInfo.safe = TPM2_YES;

	/* 6. Firmware version (simulated) */
	attest->firmwareVersion = 0;

	/* 7. Creation-specific fields */

	/* objectName - Name of the created object */
	rc = calculate_object_name(&object->public_area,
				   &attest->attested.creation.objectName);
	if (rc != TSS2_RC_SUCCESS) {
		DBG_TRACE("Failed to compute object Name\n");
		goto end;
	}

	/* creationHash */
	if (creation_hash_size >
	    sizeof(attest->attested.creation.creationHash.buffer)) {
		DBG_TRACE("creationHash too large: %u > %zu\n",
			  creation_hash_size,
			  sizeof(attest->attested.creation.creationHash.buffer));
		rc = TSS2_TCTI_RC_INSUFFICIENT_BUFFER;
		goto end;
	}

	attest->attested.creation.creationHash.size = creation_hash_size;

	memcpy(attest->attested.creation.creationHash.buffer, creation_hash,
	       creation_hash_size);

end:
	DBG_TRACE_COND(rc != TSS2_RC_SUCCESS, "return error: 0x%08x\n", rc);
	return rc;
}

static uint32_t sign_attest_structure(tcti_smw_object_t *signer,
				      uint8_t *attest_data, size_t attest_size,
				      const TPMT_SIG_SCHEME *in_scheme,
				      TPMT_SIGNATURE *signature)
{
	TSS2_RC rc = TSS2_TCTI_RC_BAD_VALUE;
	enum smw_status_code smw_status = SMW_STATUS_OK;
	struct smw_sign_verify_args sign_args = { 0 };
	struct smw_key_descriptor key_desc = { 0 };

	/* SMW hash attributes algorithm */
	smw_attr_algo_t smw_hash_attr = SMW_ATTR_HASH_NONE;
	smw_attr_algo_t curve_hash_attr = SMW_ATTR_HASH_NONE;

	/* Curve security size */
	unsigned int security_size = 0;
	TPMI_ECC_CURVE curve_id = 0;

	/* Signature buffer */
	unsigned char signature_buffer[TPM2_MAX_ECC_KEY_BYTES * 2] = { 0 };
	unsigned int signature_length = sizeof(signature_buffer);

	if (!signer || !attest_data || !in_scheme || !signature)
		goto end;

	/* 1. Validate key type (only ECC supported) */

	if (signer->public_area.publicArea.type != TPM2_ALG_ECC) {
		DBG_TRACE("Unsupported key type: 0x%04x\n",
			  signer->public_area.publicArea.type);
		rc = TSS2_TCTI_RC_IO_ERROR;
		goto end;
	}

	if (in_scheme->scheme != TPM2_ALG_ECDSA) {
		DBG_TRACE("Unsupported signing scheme: 0x%04x\n",
			  in_scheme->scheme);
		rc = TSS2_TCTI_RC_IO_ERROR;
		goto end;
	}

	curve_id = signer->public_area.publicArea.parameters.eccDetail.curveID;

	/* 2. Get curve information and validate */
	rc = map_curve_info(curve_id, &security_size, NULL, &curve_hash_attr);
	if (rc != TSS2_RC_SUCCESS)
		goto end;

	/* 3. Map TPM hash algorithm to SMW hash algorithm */
	rc = map_hash_info(in_scheme->details.ecdsa.hashAlg, NULL, NULL,
			   &smw_hash_attr);
	if (rc != TSS2_RC_SUCCESS)
		goto end;

	/* 4. Validate hash algorithm consistency */
	if (smw_hash_attr != curve_hash_attr) {
		DBG_TRACE("Hash algorithm mismatch: curve=0x%lx, scheme=0x%lx\n",
			  curve_hash_attr, smw_hash_attr);
		rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	if (attest_size > UINT32_MAX) {
		DBG_TRACE("Attest data size too large: %zu\n", attest_size);
		rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	/* 6. Hash and sign the attest data */
	key_desc.id = signer->smw_key_id;
	key_desc.type_name = SMW_KEY_TYPE_NAME_SECP_R1;
	key_desc.security_size = security_size;

	sign_args.key_descriptor = &key_desc;
	sign_args.sign_algo =
		SMW_ATTR_ALGO_ASYMMETRIC_SIGNATURE_ECDSA(SMW_ATTR_CURVE_SECP_R1,
							 smw_hash_attr);
	sign_args.message = attest_data;
	sign_args.message_length = attest_size;
	sign_args.signature = signature_buffer;
	sign_args.signature_length = signature_length;

	smw_status = smw_sign(&sign_args);
	if (smw_status != SMW_STATUS_OK) {
		DBG_TRACE("SMW sign failed: %d\n", smw_status);
		rc = smw_rc_to_tcti_rc(smw_status);
		goto end;
	}

	DBG_TRACE("SMW sign success: signature_length=%u\n",
		  sign_args.signature_length);

	/* 7. Build TPMT_SIGNATURE structure */
	signature->sigAlg = TPM2_ALG_ECDSA;
	signature->signature.ecdsa.hash = in_scheme->details.ecdsa.hashAlg;

	rc = extract_ecdsa_signature(signature_buffer,
				     sign_args.signature_length, signature);
	if (rc != TSS2_RC_SUCCESS)
		goto end;

end:
	DBG_TRACE_COND(rc != TSS2_RC_SUCCESS, "return error: 0x%08x\n", rc);
	return rc;
}

uint32_t handle_certifycreation(tcti_smw_context_t *ctx, uint16_t tag,
				const uint8_t *cmd, size_t cmd_size)
{
	TPM2_RC rc = TPM2_RC_SUCCESS;
	TSS2_RC tss2_rc = TSS2_TCTI_RC_GENERAL_FAILURE;
	size_t offset = TPM_HEADER_SIZE;
	TPMT_SIG_SCHEME effective_scheme = { 0 };
	TPMT_SIG_SCHEME key_scheme = { 0 };

	/* Input parameters */
	TPM2_HANDLE sign_handle = 0;
	TPM2_HANDLE object_handle = 0;
	TPM2B_DATA qualifying_data = { 0 };
	TPM2B_DIGEST creation_hash = { 0 };
	TPMT_SIG_SCHEME in_scheme = { 0 };
	TPMT_TK_CREATION creation_ticket = { 0 };

	/* Session handling */
	uint32_t session_handle = 0;
	TPM2B_NONCE nonce_caller = { 0 };
	tcti_smw_session_t *sess = NULL;

	/* Objects */
	tcti_smw_object_t *signer = NULL;
	tcti_smw_object_t *object = NULL;

	/* Output parameters */
	TPM2B_ATTEST certify_info = { 0 };
	TPMT_SIGNATURE signature = { 0 };
	TPMS_ATTEST attest = { 0 };
	size_t attest_offset = 0;
	size_t attest_buf_size = sizeof(certify_info.attestationData);

	/* Buffers */
	uint8_t *params_buffer = NULL;
	size_t resp_params_size = 0;

	if (!ctx) {
		tss2_rc = TSS2_TCTI_RC_BAD_REFERENCE;
		goto end;
	}

	/* 1. Unmarshal handles */
	tss2_rc =
		Tss2_MU_UINT32_Unmarshal(cmd, cmd_size, &offset, &sign_handle);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	tss2_rc = Tss2_MU_UINT32_Unmarshal(cmd, cmd_size, &offset,
					   &object_handle);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	/* 2. Get signing key */
	signer = find_object_by_handle(ctx, sign_handle);
	if (!signer) {
		tss2_rc = TSS2_TCTI_RC_IO_ERROR;
		goto end;
	}

	/* Verify signing key has sign attribute */
	if (!(signer->attributes & TPMA_OBJECT_SIGN_ENCRYPT)) {
		DBG_TRACE("Key 0x%08x cannot sign\n", sign_handle);
		tss2_rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	/* 3. Get the object associated with the creation data */
	object = find_object_by_handle(ctx, object_handle);
	if (!object) {
		tss2_rc = TSS2_TCTI_RC_IO_ERROR;
		goto end;
	}

	/* 4. Unmarshal authorization area */
	tss2_rc = unmarshal_auth_area(cmd, cmd_size, &offset, &nonce_caller,
				      &session_handle);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	if (session_handle != TPM2_RH_PW) {
		sess = find_session_by_handle(ctx, session_handle);
		if (!sess || !sess->active) {
			DBG_TRACE("Session 0x%08x not found or inactive\n",
				  session_handle);
			tss2_rc = TSS2_TCTI_RC_IO_ERROR;
			goto end;
		}
	}

	/* 5. Unmarshal parameters */

	/* qualifyingData */
	tss2_rc = Tss2_MU_TPM2B_DATA_Unmarshal(cmd, cmd_size, &offset,
					       &qualifying_data);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	/* creationHash */
	tss2_rc = Tss2_MU_TPM2B_DIGEST_Unmarshal(cmd, cmd_size, &offset,
						 &creation_hash);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	/* inScheme */
	tss2_rc = Tss2_MU_TPMT_SIG_SCHEME_Unmarshal(cmd, cmd_size, &offset,
						    &in_scheme);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	/* creationTicket */
	tss2_rc = Tss2_MU_TPMT_TK_CREATION_Unmarshal(cmd, cmd_size, &offset,
						     &creation_ticket);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	/* 6. Validate creation ticket */
	tss2_rc = verify_creation_ticket(object->hierarchy, object,
					 creation_hash, creation_ticket);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	/* Extract key's signature scheme */
	tss2_rc = extract_key_sig_scheme(&signer->public_area, &key_scheme);
	if (tss2_rc != TSS2_RC_SUCCESS) {
		DBG_TRACE("Failed to extract key signature scheme\n");
		goto end;
	}

	/* Determine effective scheme according to TPM 2.0 spec */
	tss2_rc = get_effective_scheme(&signer->public_area.publicArea,
				       &key_scheme, &in_scheme,
				       &effective_scheme);
	if (tss2_rc != TSS2_RC_SUCCESS) {
		DBG_TRACE("Failed to determine effective scheme\n");
		goto end;
	}

	/* 7. Build TPMS_ATTEST structure using existing function */
	tss2_rc = build_tpms_attest_creation(&attest, object, signer,
					     qualifying_data.buffer,
					     qualifying_data.size,
					     creation_hash.buffer,
					     creation_hash.size);
	if (tss2_rc != TSS2_RC_SUCCESS) {
		DBG_TRACE("Failed to build TPMS_ATTEST\n");
		goto end;
	}

	/* 8. Marshal TPMS_ATTEST */
	tss2_rc = Tss2_MU_TPMS_ATTEST_Marshal(&attest,
					      certify_info.attestationData,
					      attest_buf_size, &attest_offset);
	if (tss2_rc != TSS2_RC_SUCCESS) {
		DBG_TRACE("Failed to marshal TPMS_ATTEST\n");
		goto end;
	}

	certify_info.size = attest_offset;

	/* 9. Sign the attestation structure */
	tss2_rc = sign_attest_structure(signer, certify_info.attestationData,
					certify_info.size, &effective_scheme,
					&signature);
	if (tss2_rc != TSS2_RC_SUCCESS) {
		DBG_TRACE("Failed to sign attest structure\n");
		goto end;
	}

	/* 10. Marshal output parameters */
	params_buffer = calloc(1, TPM2_MAX_CAP_BUFFER);
	if (!params_buffer) {
		tss2_rc = TSS2_TCTI_RC_MEMORY;
		goto end;
	}

	/* Marshal certifyInfo */
	tss2_rc = Tss2_MU_TPM2B_ATTEST_Marshal(&certify_info, params_buffer,
					       TPM2_MAX_CAP_BUFFER,
					       &resp_params_size);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	/* Marshal signature */
	tss2_rc = Tss2_MU_TPMT_SIGNATURE_Marshal(&signature, params_buffer,
						 TPM2_MAX_CAP_BUFFER,
						 &resp_params_size);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	/* 11. Build response */
	tss2_rc =
		build_auth_response(ctx, sess, TPM2_RC_SUCCESS,
				    TPM2_CC_CertifyCreation, tag, params_buffer,
				    resp_params_size, &nonce_caller, NULL);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	DBG_TRACE("CertifyCreation successful:\n"
		  "  signHandle: 0x%08x\n"
		  "  objectHandle: 0x%08x\n"
		  "  certifyInfo size: %u bytes\n",
		  sign_handle, object_handle, certify_info.size);

end:
	if (params_buffer)
		free(params_buffer);

	if (tss2_rc != TSS2_RC_SUCCESS) {
		rc = tcti_rc_to_tpm2_rc(tss2_rc);
		tss2_rc = build_rc_response(ctx, TPM_HEADER_SIZE, tag, rc);
	}

	return tss2_rc;
}

uint32_t handle_unseal(tcti_smw_context_t *ctx, uint16_t tag,
		       const uint8_t *cmd, size_t cmd_size)
{
	TPM2_RC rc = TPM2_RC_SUCCESS;
	TSS2_RC tss2_rc = TSS2_TCTI_RC_GENERAL_FAILURE;
	size_t offset = TPM_HEADER_SIZE;

	/* Input parameters */
	TPMI_DH_OBJECT item_handle = 0;

	/* Output parameters */
	TPM2B_SENSITIVE_DATA out_data = { 0 };
	uint16_t plaintext_size = sizeof(out_data.buffer);

	/* Session handling */
	uint32_t session_handle = 0;
	TPM2B_NONCE nonce_caller = { 0 };
	tcti_smw_session_t *sess = NULL;

	/* Object */
	tcti_smw_object_t *obj = NULL;

	/* Response buffer */
	uint8_t *params_buffer = NULL;
	size_t resp_params_size = 0;

	/* 1. Check initialization */
	if (!ctx || !ctx->initialized) {
		tss2_rc = TSS2_TCTI_RC_BAD_SEQUENCE;
		goto end;
	}

	/* 2. Unmarshal item handle */
	tss2_rc =
		Tss2_MU_UINT32_Unmarshal(cmd, cmd_size, &offset, &item_handle);
	if (tss2_rc != TSS2_RC_SUCCESS) {
		DBG_TRACE("Failed to unmarshal item handle\n");
		goto end;
	}

	/* 3. Unmarshal authorization area */
	tss2_rc = unmarshal_auth_area(cmd, cmd_size, &offset, &nonce_caller,
				      &session_handle);
	if (tss2_rc != TSS2_RC_SUCCESS) {
		DBG_TRACE("Failed to unmarshal auth area\n");
		goto end;
	}

	/* Find session */
	if (session_handle != TPM2_RH_PW) {
		sess = find_session_by_handle(ctx, session_handle);
		if (!sess || !sess->active) {
			tss2_rc = TSS2_TCTI_RC_IO_ERROR;
			goto end;
		}
	}

	/* 4. Find the sealed object */
	obj = find_object_by_handle(ctx, item_handle);
	if (!obj) {
		tss2_rc = TSS2_TCTI_RC_IO_ERROR;
		goto end;
	}

	/* 5. Validate object type */
	if (obj->public_area.publicArea.type != TPM2_ALG_KEYEDHASH) {
		DBG_TRACE("Object is not KEYEDHASH type: 0x%04x\n",
			  obj->public_area.publicArea.type);
		tss2_rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	/* 6. Validate it's a sealed data object (not HMAC key) */
	if (!is_sealed_data_object(&obj->public_area.publicArea)) {
		DBG_TRACE("Object is not a sealed data object\n");
		tss2_rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	/* 7. Check scheme is NULL (sealed data, not HMAC) */
	if (obj->public_area.publicArea.parameters.keyedHashDetail.scheme
		    .scheme != TPM2_ALG_NULL) {
		DBG_TRACE("Object scheme is not NULL: 0x%04x\n",
			  obj->public_area.publicArea.parameters.keyedHashDetail
				  .scheme.scheme);
		tss2_rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	/* 8. Retrieve the sealed data */
	if (obj->sealed_blob.size == 0) {
		DBG_TRACE("No sealed data in object\n");
		tss2_rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	tss2_rc = decrypt_sealed_data(obj->hierarchy, obj->sealed_blob.buffer,
				      obj->sealed_blob.size, out_data.buffer,
				      &plaintext_size);
	if (tss2_rc != TSS2_RC_SUCCESS) {
		DBG_TRACE("Failed to decrypt sealed data\n");
		goto end;
	}

	out_data.size = plaintext_size;

	/* 9. Marshal output parameters */
	params_buffer = calloc(1, TPM2_MAX_CAP_BUFFER);
	if (!params_buffer) {
		tss2_rc = TSS2_TCTI_RC_MEMORY;
		goto end;
	}

	tss2_rc = Tss2_MU_TPM2B_SENSITIVE_DATA_Marshal(&out_data, params_buffer,
						       TPM2_MAX_CAP_BUFFER,
						       &resp_params_size);
	if (tss2_rc != TSS2_RC_SUCCESS) {
		DBG_TRACE("Failed to marshal outData\n");
		goto end;
	}

	/* 10. Build auth response */
	tss2_rc = build_auth_response(ctx, sess, TPM2_RC_SUCCESS,
				      TPM2_CC_Unseal, tag, params_buffer,
				      resp_params_size, &nonce_caller, NULL);
	if (tss2_rc != TSS2_RC_SUCCESS) {
		DBG_TRACE("Failed to build auth response\n");
		goto end;
	}

	DBG_TRACE("Unseal successful: handle=0x%08x, data_size=%u\n",
		  item_handle, out_data.size);

end:
	if (params_buffer)
		free(params_buffer);

	if (tss2_rc != TSS2_RC_SUCCESS) {
		rc = tcti_rc_to_tpm2_rc(tss2_rc);
		tss2_rc = build_rc_response(ctx, TPM_HEADER_SIZE, tag, rc);
	}

	return tss2_rc;
}

uint32_t handle_makecredential(tcti_smw_context_t *ctx, uint16_t tag,
			       const uint8_t *cmd, size_t cmd_size)
{
	TSS2_RC tss2_rc = TSS2_TCTI_RC_GENERAL_FAILURE;
	TPM2_RC rc = TPM2_RC_SUCCESS;
	size_t offset = TPM_HEADER_SIZE;
	enum smw_status_code smw_status = SMW_STATUS_OK;

	/* Input parameters */
	TPMI_DH_OBJECT handle = 0;
	TPM2B_DIGEST credential = { 0 };
	TPM2B_NAME object_name = { 0 };

	/* Output parameters */
	TPM2B_ID_OBJECT credential_blob = { 0 };
	TPM2B_ENCRYPTED_SECRET secret = { 0 };

	/* Seed */
	struct smw_rng_args rng_args = { 0 };
	uint8_t seed[SMW_SEED_SIZE] = { 0 };

	/* EK object */
	tcti_smw_object_t *obj_ek = NULL;

	/* Session handling */
	uint32_t session_handle = 0;
	TPM2B_NONCE nonce_caller = { 0 };
	tcti_smw_session_t *sess = NULL;

	/* Response buffer */
	uint8_t *params_buffer = NULL;
	size_t resp_params_size = 0;

	/* 1. Check initialization */
	if (!ctx || !ctx->initialized) {
		tss2_rc = TSS2_TCTI_RC_BAD_SEQUENCE;
		goto end;
	}

	/* 2. Unmarshal handle */
	tss2_rc = Tss2_MU_UINT32_Unmarshal(cmd, cmd_size, &offset, &handle);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	/* 3. Unmarshal authorization area if present */
	if (tag == TPM2_ST_SESSIONS) {
		tss2_rc = unmarshal_auth_area(cmd, cmd_size, &offset,
					      &nonce_caller, &session_handle);
		if (tss2_rc != TSS2_RC_SUCCESS)
			goto end;

		if (session_handle != TPM2_RH_PW) {
			sess = find_session_by_handle(ctx, session_handle);
			if (!sess || !sess->active) {
				tss2_rc = TSS2_TCTI_RC_IO_ERROR;
				goto end;
			}
		}
	}

	/* 4. Unmarshal credential */
	tss2_rc = Tss2_MU_TPM2B_DIGEST_Unmarshal(cmd, cmd_size, &offset,
						 &credential);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	/* 5. Unmarshal objectName (AK Name) */
	tss2_rc = Tss2_MU_TPM2B_NAME_Unmarshal(cmd, cmd_size, &offset,
					       &object_name);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	DBG_TRACE("MakeCredential:\n"
		  "  handle: 0x%08x\n"
		  "  credential.size: %u\n"
		  "  objectName.size: %u\n",
		  handle, credential.size, object_name.size);

	/* 6. Validate inputs */
	if (credential.size == 0 || credential.size > TPM2_SHA256_DIGEST_SIZE) {
		DBG_TRACE("Invalid credential size: %u\n", credential.size);
		tss2_rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	if (object_name.size < 2 ||
	    object_name.size > sizeof(object_name.name)) {
		DBG_TRACE("Invalid objectName size: %u\n", object_name.size);
		tss2_rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	/* 7. Find EK object */
	obj_ek = find_object_by_handle(ctx, handle);
	if (!obj_ek) {
		DBG_TRACE("Object handle 0x%08x not found\n", handle);
		tss2_rc = TSS2_TCTI_RC_IO_ERROR;
		goto end;
	}

	/* 8. Validate EK is RSA with decrypt attribute */
	if (obj_ek->public_area.publicArea.type != TPM2_ALG_RSA) {
		DBG_TRACE("Key 0x%08x is not RSA\n", handle);
		tss2_rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	if (!(obj_ek->attributes & TPMA_OBJECT_DECRYPT)) {
		DBG_TRACE("Key 0x%08x does not have DECRYPT attribute\n",
			  handle);
		tss2_rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	/* 9. Generate random seed */
	rng_args.subsystem_name = SMW_SUBSYSTEM_NAME_ELE;
	rng_args.output = seed;
	rng_args.output_length = sizeof(seed);

	smw_status = smw_rng(&rng_args);
	if (smw_status != SMW_STATUS_OK) {
		DBG_TRACE("RNG failed: %d\n", smw_status);
		tss2_rc = smw_rc_to_tcti_rc(smw_status);
		goto end;
	}

	DBG_TRACE("Seed generated (%zu bytes)\n", sizeof(seed));

	/* 10. Encrypt seed with EK public key -> secret */
	tss2_rc = encrypt_seed_rsa(obj_ek, seed, sizeof(seed), &secret);
	if (tss2_rc != TSS2_RC_SUCCESS) {
		DBG_TRACE("Failed to encrypt seed with EK\n");
		goto end;
	}

	/* 11. Build credentialBlob (AES-GCM with seed, AAD = AK_Name) */
	tss2_rc = build_credential_blob(&credential, &object_name, seed,
					&credential_blob);
	if (tss2_rc != TSS2_RC_SUCCESS) {
		DBG_TRACE("Failed to build credential blob\n");
		goto end;
	}

	DBG_TRACE("MakeCredential success:\n"
		  "  credentialBlob.size: %u\n"
		  "  secret.size: %u\n",
		  credential_blob.size, secret.size);

	/* 12. Marshal output parameters */
	params_buffer = calloc(1, TPM2_MAX_CAP_BUFFER);
	if (!params_buffer) {
		tss2_rc = TSS2_TCTI_RC_MEMORY;
		goto end;
	}

	tss2_rc =
		Tss2_MU_TPM2B_ID_OBJECT_Marshal(&credential_blob, params_buffer,
						TPM2_MAX_CAP_BUFFER,
						&resp_params_size);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	tss2_rc = Tss2_MU_TPM2B_ENCRYPTED_SECRET_Marshal(&secret, params_buffer,
							 TPM2_MAX_CAP_BUFFER,
							 &resp_params_size);
	if (tss2_rc != TSS2_RC_SUCCESS)
		goto end;

	/* 13. Build response */
	tss2_rc =
		build_auth_response(ctx, sess, TPM2_RC_SUCCESS,
				    TPM2_CC_MakeCredential, tag, params_buffer,
				    resp_params_size, &nonce_caller, NULL);

end:
	if (params_buffer)
		free(params_buffer);

	if (tss2_rc != TSS2_RC_SUCCESS) {
		rc = tcti_rc_to_tpm2_rc(tss2_rc);
		tss2_rc = build_rc_response(ctx, TPM_HEADER_SIZE, tag, rc);
	}

	return tss2_rc;
}

uint32_t handle_activatecredential(tcti_smw_context_t *ctx, uint16_t tag,
				   const uint8_t *cmd, size_t cmd_size)
{
	TSS2_RC tss2_rc = TSS2_TCTI_RC_GENERAL_FAILURE;
	TPM2_RC rc = TPM2_RC_SUCCESS;
	size_t offset = TPM_HEADER_SIZE;

	/* Input parameters */
	TPMI_DH_OBJECT activate_handle = 0;
	TPMI_DH_OBJECT key_handle = 0;
	TPM2B_ID_OBJECT credential_blob = { 0 };
	TPM2B_ENCRYPTED_SECRET secret = { 0 };

	/* Output */
	TPM2B_DIGEST cert_info = { 0 };

	/* Seed buffer */
	uint8_t seed[SMW_SEED_SIZE] = { 0 };
	size_t seed_size = sizeof(seed);

	/* Objects */
	tcti_smw_object_t *obj_ak = NULL;
	tcti_smw_object_t *obj_ek = NULL;

	/* AK Name for binding verification */
	TPM2B_NAME ak_name = { 0 };

	/* Session handling - need auth for both AK and EK */
	auth_session_info_t auth_sessions[2] = { 0 };
	tcti_smw_session_t *sess_ak = NULL;
	tcti_smw_session_t *sess_ek = NULL;
	size_t nb_auth_sessions = 0;
	TPM2_HANDLE session_handle = 0;

	/* Response buffer */
	uint8_t *params_buffer = NULL;
	size_t resp_params_size = 0;

	/* 1. Check initialization */
	if (!ctx || !ctx->initialized) {
		tss2_rc = TSS2_TCTI_RC_BAD_SEQUENCE;
		goto end;
	}

	/* 2. Unmarshal activate handle (AK) */
	tss2_rc = Tss2_MU_UINT32_Unmarshal(cmd, cmd_size, &offset,
					   &activate_handle);
	if (tss2_rc != TSS2_RC_SUCCESS) {
		DBG_TRACE("Failed to unmarshal activate_handle\n");
		goto end;
	}

	/* 3. Unmarshal key handle (EK) */
	tss2_rc = Tss2_MU_UINT32_Unmarshal(cmd, cmd_size, &offset, &key_handle);
	if (tss2_rc != TSS2_RC_SUCCESS) {
		DBG_TRACE("Failed to unmarshal key_handle\n");
		goto end;
	}

	DBG_TRACE("ActivateCredential:\n"
		  "  activate_handle (AK): 0x%08x\n"
		  "  key_handle (EK): 0x%08x\n",
		  activate_handle, key_handle);

	/* 4. Find AK object */
	obj_ak = find_object_by_handle(ctx, activate_handle);
	if (!obj_ak) {
		DBG_TRACE("AK handle 0x%08x not found\n", activate_handle);
		tss2_rc = TSS2_TCTI_RC_IO_ERROR;
		goto end;
	}

	/* 5. Find EK object */
	obj_ek = find_object_by_handle(ctx, key_handle);
	if (!obj_ek) {
		DBG_TRACE("EK handle 0x%08x not found\n", key_handle);
		tss2_rc = TSS2_TCTI_RC_IO_ERROR;
		goto end;
	}

	/* 6. Unmarshal authorization area (up to 2 sessions) */
	if (tag == TPM2_ST_SESSIONS) {
		tss2_rc = unmarshal_auth_area_multi(cmd, cmd_size, &offset,
						    auth_sessions,
						    &nb_auth_sessions);
		if (tss2_rc != TSS2_RC_SUCCESS) {
			DBG_TRACE("Failed to unmarshal auth area\n");
			goto end;
		}

		DBG_TRACE("Unmarshaled %zu auth session(s)\n",
			  nb_auth_sessions);

		/* Find sessions */
		if (nb_auth_sessions >= 1) {
			session_handle = auth_sessions[0].session_handle;
			if (session_handle != TPM2_RH_PW) {
				sess_ak =
					find_session_by_handle(ctx,
							       session_handle);
				if (!sess_ak || !sess_ak->active) {
					DBG_TRACE("Session 0x%08x not found\n",
						  session_handle);
					tss2_rc = TSS2_TCTI_RC_IO_ERROR;
					goto end;
				}
			}
		}

		if (nb_auth_sessions == 2) {
			session_handle = auth_sessions[1].session_handle;
			if (session_handle != TPM2_RH_PW) {
				sess_ek =
					find_session_by_handle(ctx,
							       session_handle);
				if (!sess_ek || !sess_ek->active) {
					DBG_TRACE("Session 0x%08x not found\n",
						  session_handle);
					tss2_rc = TSS2_TCTI_RC_IO_ERROR;
					goto end;
				}
			}
		}
	}

	/* 7. Unmarshal credentialBlob */
	tss2_rc = Tss2_MU_TPM2B_ID_OBJECT_Unmarshal(cmd, cmd_size, &offset,
						    &credential_blob);
	if (tss2_rc != TSS2_RC_SUCCESS) {
		DBG_TRACE("Failed to unmarshal credentialBlob\n");
		goto end;
	}

	/* 8. Unmarshal secret */
	tss2_rc = Tss2_MU_TPM2B_ENCRYPTED_SECRET_Unmarshal(cmd, cmd_size,
							   &offset, &secret);
	if (tss2_rc != TSS2_RC_SUCCESS) {
		DBG_TRACE("Failed to unmarshal secret\n");
		goto end;
	}

	DBG_TRACE("Input parameters:\n"
		  "  credentialBlob.size: %u\n"
		  "  secret.size: %u\n",
		  credential_blob.size, secret.size);

	/* 9. Validate EK is RSA with decrypt attribute */
	if (obj_ek->public_area.publicArea.type != TPM2_ALG_RSA) {
		DBG_TRACE("EK is not RSA: 0x%04x\n",
			  obj_ek->public_area.publicArea.type);
		tss2_rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	if (!(obj_ek->attributes & TPMA_OBJECT_DECRYPT)) {
		DBG_TRACE("EK does not have DECRYPT attribute\n");
		tss2_rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	/* 10. Calculate AK Name for binding verification */
	tss2_rc = calculate_object_name(&obj_ak->public_area, &ak_name);
	if (tss2_rc != TSS2_RC_SUCCESS) {
		DBG_TRACE("Failed to calculate AK Name\n");
		goto end;
	}

	DBG_TRACE("AK Name calculated: %u bytes\n", ak_name.size);

	/* 11. Decrypt seed using EK private key (RSA-OAEP) */
	tss2_rc = decrypt_seed_rsa(obj_ek, &secret, seed, &seed_size);
	if (tss2_rc != TSS2_RC_SUCCESS) {
		DBG_TRACE("Failed to decrypt seed\n");
		goto end;
	}

	/* Validate seed size */
	if (seed_size != SMW_SEED_SIZE) {
		DBG_TRACE("Invalid seed size: %zu (expected %u)\n", seed_size,
			  SMW_SEED_SIZE);
		tss2_rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	/* 12. Decrypt credentialBlob and verify AK Name binding */
	tss2_rc = decrypt_credential_blob(&credential_blob, &ak_name, seed,
					  &cert_info);
	if (tss2_rc != TSS2_RC_SUCCESS) {
		DBG_TRACE("Failed to decrypt credential blob\n");
		goto end;
	}

	DBG_TRACE("ActivateCredential success:\n"
		  "  certInfo.size: %u\n",
		  cert_info.size);

	/* 13. Marshal output parameters */
	params_buffer = calloc(1, TPM2_MAX_CAP_BUFFER);
	if (!params_buffer) {
		tss2_rc = TSS2_TCTI_RC_MEMORY;
		goto end;
	}

	tss2_rc = Tss2_MU_TPM2B_DIGEST_Marshal(&cert_info, params_buffer,
					       TPM2_MAX_CAP_BUFFER,
					       &resp_params_size);
	if (tss2_rc != TSS2_RC_SUCCESS) {
		DBG_TRACE("Failed to marshal certInfo\n");
		goto end;
	}

	/* 14. Build response */
	tss2_rc = build_auth_response_multi(ctx, auth_sessions, 2,
					    TPM2_RC_SUCCESS,
					    TPM2_CC_ActivateCredential, tag,
					    params_buffer, resp_params_size,
					    NULL);
	if (tss2_rc != TSS2_RC_SUCCESS) {
		DBG_TRACE("Failed to build auth response\n");
		goto end;
	}

	DBG_TRACE("ActivateCredential completed successfully\n");

end:
	if (params_buffer)
		free(params_buffer);

	if (tss2_rc != TSS2_RC_SUCCESS) {
		rc = tcti_rc_to_tpm2_rc(tss2_rc);
		tss2_rc = build_rc_response(ctx, TPM_HEADER_SIZE, tag, rc);
	}

	return tss2_rc;
}
