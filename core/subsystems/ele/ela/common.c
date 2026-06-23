// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include "local.h"

int ela_load_aes_key(prime_hdl_t service_hdl,
		     struct smw_keymgr_descriptor *key_desc, uint8_t *keyslot)
{
	int status = SMW_STATUS_INVALID_PARAM;
	prime_err_t err = PRIME_ERR_NONE;

	aes_key_t key_args = { 0 };
	unsigned char *key_buffer = NULL;
	unsigned int key_length = 0;
	unsigned int hex_private_len = 0;
	unsigned char *key_buffer_hex = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	key_buffer = smw_keymgr_get_private_data(key_desc);
	key_length = smw_keymgr_get_private_length(key_desc);

	if (!key_buffer || !key_length) {
		SMW_DBG_PRINTF(ERROR, "Invalid key buffer\n");
		goto end;
	}

	status = smw_utils_key_set_hex_buffer(key_desc->format_id, key_buffer,
					      key_length, &key_buffer_hex,
					      &hex_private_len);
	if (status != SMW_STATUS_OK)
		goto end;

	if (SET_OVERFLOW(hex_private_len, key_args.keylen)) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	key_args.key = key_buffer_hex;
	key_args.keyslot = 0;

	/* Initialize AES cipher with the specified key */
	err = prime_cipher_init(service_hdl, &key_args);
	status = convert_ela_err(err);
	if (status != SMW_STATUS_OK) {
		SMW_DBG_PRINTF(ERROR, "prime_cipher_init failed: %d\n", err);
		goto end;
	}

	*keyslot = key_args.keyslot;

	SMW_DBG_PRINTF(DEBUG, "AES key loaded into slot %u\n", *keyslot);

end:
	if (key_desc->format_id == SMW_KEYMGR_FORMAT_ID_BASE64 &&
	    key_buffer_hex)
		SMW_UTILS_FREE(key_buffer_hex);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}
