// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <string.h>

#include "smw_keymgr.h"
#include "builtin_macros.h"

#include "crypto.h"
#include "trace.h"

uint32_t map_hash_info(TPMI_ALG_HASH hash_alg, uint16_t *digest_size,
		       smw_hash_algo_t *smw_name)
{
	TSS2_RC rc = TSS2_TCTI_RC_BAD_VALUE;
	uint16_t size = 0;
	smw_hash_algo_t name = SMW_HASH_ALGO_NAME_NONE;

	switch (hash_alg) {
	case TPM2_ALG_SHA1:
		size = TPM2_SHA1_DIGEST_SIZE;
		name = SMW_HASH_ALGO_NAME_SHA1;
		break;
	case TPM2_ALG_SHA256:
		size = TPM2_SHA256_DIGEST_SIZE;
		name = SMW_HASH_ALGO_NAME_SHA256;
		break;
	case TPM2_ALG_SHA384:
		size = TPM2_SHA384_DIGEST_SIZE;
		name = SMW_HASH_ALGO_NAME_SHA384;
		break;
	case TPM2_ALG_SHA512:
		size = TPM2_SHA512_DIGEST_SIZE;
		name = SMW_HASH_ALGO_NAME_SHA512;
		break;
	default:
		DBG_TRACE("Unknown hash algorithm 0x%04x\n", hash_alg);
		goto end;
	}

	if (digest_size)
		*digest_size = size;

	if (smw_name)
		*smw_name = name;

	rc = TSS2_RC_SUCCESS;

end:
	DBG_TRACE_COND(rc != TSS2_RC_SUCCESS, "return error: 0x%08x\n", rc);
	return rc;
}

uint32_t calculate_response_hmac(tcti_smw_session_t *session,
				 TPM2_RC responseCode, TPM2_CC commandCode,
				 const uint8_t *parameters,
				 size_t parameters_size,
				 const uint8_t *nonceCaller,
				 size_t nonceCaller_size, uint8_t **hmac_out,
				 uint16_t *hmac_size)
{
	TSS2_RC rc = TSS2_TCTI_RC_MEMORY;
	enum smw_status_code smw_status = SMW_STATUS_OK;
	struct smw_mac_args mac_args = { 0 };
	struct smw_key_descriptor key_desc = { 0 };
	struct smw_keypair_buffer key_buffer = { 0 };
	struct smw_hash_args hash_args = { 0 };
	smw_hash_algo_t hash_name = SMW_HASH_ALGO_NAME_NONE;
	size_t rp_offset = 0;
	size_t rp_buffer_size = 0, hmac_offset = 0, hmac_msg_size = 0;
	const size_t rp_hash_header_size =
		sizeof(uint32_t) * 2; /* responseCode + commandCode */
	uint8_t *rp_hash_buffer = NULL;
	uint8_t *rp_hash = NULL;
	uint8_t *hmac_message = NULL;

	if (parameters_size > SIZE_MAX - rp_hash_header_size) {
		DBG_TRACE("Parameters size too large: %zu\n", parameters_size);
		rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	/* rpHash buffer : responseCode(4) + commandCode(4) + parameters */
	if (ADD_OVERFLOW(rp_hash_header_size, parameters_size,
			 &rp_buffer_size)) {
		DBG_TRACE("Buffer size overflow: header=%zu + params=%zu\n",
			  rp_hash_header_size, parameters_size);
		rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	rp_hash_buffer = malloc(rp_buffer_size);
	if (!rp_hash_buffer)
		goto end;

	/*
	 * 1. Compute rpHash (response parameter hash)
	 * rpHash = Hash(responseCode || commandCode || parameters)
	 */
	rc = Tss2_MU_UINT32_Marshal(responseCode, rp_hash_buffer,
				    rp_buffer_size, &rp_offset);
	if (rc != TSS2_RC_SUCCESS)
		goto end;

	rc = Tss2_MU_UINT32_Marshal(commandCode, rp_hash_buffer, rp_buffer_size,
				    &rp_offset);
	if (rc != TSS2_RC_SUCCESS)
		goto end;

	if (rp_offset != rp_hash_header_size) {
		DBG_TRACE("Unexpected offset after header marshal: %zu\n",
			  rp_offset);
		rc = TSS2_TCTI_RC_GENERAL_FAILURE;
		goto end;
	}

	if (parameters && parameters_size > 0) {
		if (rp_offset + parameters_size > rp_buffer_size) {
			DBG_TRACE("Parameters would overflow buffer:\n"
				  "offset=%zu + size=%zu > buffer=%zu\n",
				  rp_offset, parameters_size, rp_buffer_size);
			rc = TSS2_TCTI_RC_BAD_VALUE;
			goto end;
		}
		memcpy(&rp_hash_buffer[rp_offset], parameters, parameters_size);
		rp_offset += parameters_size;
	}

	rc = map_hash_info(session->auth_hash, hmac_size, &hash_name);
	if (rc != TSS2_RC_SUCCESS)
		goto end;

	rp_hash = malloc(*hmac_size);
	if (!rp_hash) {
		rc = TSS2_TCTI_RC_MEMORY;
		goto end;
	}

	*hmac_out = malloc(*hmac_size);
	if (!*hmac_out) {
		rc = TSS2_TCTI_RC_MEMORY;
		goto end;
	}

	if (rp_offset > UINT32_MAX) {
		DBG_TRACE("rpHash buffer size too large: %zu\n", rp_offset);
		rc = TSS2_TCTI_RC_BAD_VALUE;
		goto end;
	}

	hash_args.algo_name = hash_name;
	hash_args.input = rp_hash_buffer;
	hash_args.input_length = (uint32_t)rp_offset;
	hash_args.output = rp_hash;
	hash_args.output_length = *hmac_size;

	smw_status = smw_hash(&hash_args);
	if (smw_status != SMW_STATUS_OK) {
		DBG_TRACE("Failed to compute rpHash: %d\n", smw_status);
		rc = smw_rc_to_tcti_rc(smw_status);
		goto end;
	}

	/*
	 * Build the HMAC message following TPM2 spec with rpHash
	 * Max size : hash + nonceTPM + nonceCaller + 1 byte attrs
	 */
	hmac_msg_size = *hmac_size + session->nonce.size + nonceCaller_size + 1;
	hmac_message = malloc(hmac_msg_size);
	if (!hmac_message) {
		rc = TSS2_TCTI_RC_MEMORY;
		goto end;
	}

	/* Message = rpHash || nonceTPM || nonceCaller || sessionAttributes */
	memcpy(&hmac_message[hmac_offset], rp_hash, *hmac_size);

	hmac_offset += *hmac_size;

	if (session->nonce.size > 0) {
		memcpy(&hmac_message[hmac_offset], session->nonce.buffer,
		       session->nonce.size);

		hmac_offset += session->nonce.size;
	}

	if (nonceCaller && nonceCaller_size > 0) {
		memcpy(&hmac_message[hmac_offset], nonceCaller,
		       nonceCaller_size);

		hmac_offset += nonceCaller_size;
	}

	hmac_message[hmac_offset++] = TPMA_SESSION_CONTINUESESSION;

	/* Give the key in plaintext */
	key_buffer.gen.private_data = session->session_key;
	key_buffer.gen.private_length = session->session_key_size;
	key_buffer.format_name = SMW_KEY_FORMAT_NAME_NONE;

	/* Configuring key descriptor */
	key_desc.type_name = SMW_KEY_TYPE_NAME_HMAC;
	key_desc.security_size = session->session_key_size * 8; // in bits;
	key_desc.buffer = &key_buffer;
	key_desc.attributes.usage_flags =
		SMW_ATTR_USAGE_SIGN_MESSAGE | SMW_ATTR_USAGE_VERIFY_MESSAGE;
	key_desc.attributes.permitted_algo = SMW_ATTR_ALGO_HMAC;
	key_desc.attributes.attributes =
		SMW_ATTR_SET_PERSISTENCE(0, SMW_ATTR_PERSISTENCE_TRANSIENT);

	mac_args.key_descriptor = &key_desc;
	mac_args.algo_name = SMW_MAC_ALGO_NAME_HMAC;
	mac_args.hash_name = hash_name;
	mac_args.input = hmac_message;
	mac_args.input_length = hmac_offset;
	mac_args.mac = *hmac_out;
	mac_args.mac_length = *hmac_size;

	smw_status = smw_mac(&mac_args);
	if (smw_status != SMW_STATUS_OK) {
		DBG_TRACE("Failed to compute HMAC: %d\n", smw_status);
		rc = smw_rc_to_tcti_rc(smw_status);
		goto end;
	}

end:
	/* Free all temp buffers */
	free(rp_hash_buffer);
	free(rp_hash);
	free(hmac_message);

	if (rc != TSS2_RC_SUCCESS && *hmac_out) {
		free(*hmac_out);
		*hmac_out = NULL;
	}

	DBG_TRACE_COND(rc != TSS2_RC_SUCCESS, "return error: 0x%08x\n", rc);
	return rc;
}
