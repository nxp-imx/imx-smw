/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020 NXP
 */

/**
 * struct smw_crypto_sign_args - Sign arguments
 * @key_descriptor: Descriptor of the Key
 * @algo_id: Algorithm ID
 * @hashed: Is the message hashed
 * @message: Location of the message to be signed
 * @message_length: Length of the message to be signed
 * @signature: Location where the signature has to be written
 * @signature_length: Length of the signature
 *
 * @subsystem_name designates the Secure Subsystem to be used.
 * If this field is NULL, the default configured Secure Subsystem is used.
 */
struct smw_crypto_sign_args {
	/* Inputs */
	struct smw_keymgr_descriptor key_descriptor;
	enum smw_config_hash_algo_id algo_id;
	int hashed;
	unsigned char *message;
	unsigned int message_length;
	/* Outputs */
	unsigned char *signature;
	unsigned int signature_length;
};

/**
 * struct smw_crypto_verify_args - Verify arguments
 * @key_descriptor: Descriptor of the Key
 * @algo_id: Algorithm ID
 * @hashed: Is the message hashed
 * @message: Location of the message
 * @message_length: Length of the message
 * @signature: Location of the signature
 * @signature_length: Length of the signature
 *
 * @subsystem_name designates the Secure Subsystem to be used.
 * If this field is NULL, the default configured Secure Subsystem is used.
 */
struct smw_crypto_verify_args {
	/* Inputs */
	struct smw_keymgr_descriptor key_descriptor;
	enum smw_config_hash_algo_id algo_id;
	int hashed;
	unsigned char *message;
	unsigned int message_length;
	unsigned char *signature;
	unsigned int signature_length;
};
