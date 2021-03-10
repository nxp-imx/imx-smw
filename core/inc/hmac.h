/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021 NXP
 */

/**
 * struct smw_crypto_hmac_args - HMAC arguments
 * @key_descriptor: Descriptor of the Key
 * @algo_id: Algorithm ID
 * @pub: Pointer to the public API arguments structure
 *
 */
struct smw_crypto_hmac_args {
	/* Inputs */
	struct smw_keymgr_descriptor key_descriptor;
	enum smw_config_hmac_algo_id algo_id;
	struct smw_hmac_args *pub;
};

/**
 * smw_hmac_get_input_data() - Return the address of the HMAC input buffer.
 * @args: Pointer to the internal HMAC args structure.
 *
 * This function returns the address of the HMAC input buffer.
 *
 * Return:
 * NULL
 * address of the HMAC input buffer.
 */
unsigned char *smw_hmac_get_input_data(struct smw_crypto_hmac_args *args);

/**
 * smw_hmac_get_input_length() - Return the length of the HMAC input buffer.
 * @args: Pointer to the internal HMAC args structure.
 *
 * This function returns the length of the HMAC input buffer.
 *
 * Return:
 * 0
 * length of the HMAC input buffer.
 */
unsigned int smw_hmac_get_input_length(struct smw_crypto_hmac_args *args);

/**
 * smw_hmac_get_output_data() - Return the address of the HMAC output buffer.
 * @args: Pointer to the internal HMAC args structure.
 *
 * This function returns the address of the HMAC output buffer.
 *
 * Return:
 * NULL
 * address of the HMAC output buffer.
 */
unsigned char *smw_hmac_get_output_data(struct smw_crypto_hmac_args *args);

/**
 * smw_hmac_get_output_length() - Return the length of the HMAC output buffer.
 * @args: Pointer to the internal HMAC args structure.
 *
 * This function returns the length of the HMAC output buffer.
 *
 * Return:
 * 0
 * length of the HMAC output buffer.
 */
unsigned int smw_hmac_get_output_length(struct smw_crypto_hmac_args *args);

/**
 * smw_hmac_set_output_length() - Set the length of the HMAC output buffer.
 * @args: Pointer to the internal HMAC args structure.
 * @output_length: Length of the HMAC output buffer.
 *
 * This function sets the length of the HMAC output buffer.
 *
 * Return:
 * none.
 */
void smw_hmac_set_output_length(struct smw_crypto_hmac_args *args,
				unsigned int output_length);
