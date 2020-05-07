/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020 NXP
 */

/**
 * struct smw_crypto_hash_args - Hash arguments
 * @algo_id: Algorithm ID
 * @input: Location of the stream to be hashed
 * @input_length: Length of the stream to be hashed
 * @output: Location where the digest has to be written
 * @output_length: Maximum length of the digest
 *
 */
struct smw_crypto_hash_args {
	/* Inputs */
	enum smw_config_hash_algo_id algo_id;
	unsigned char *input;
	unsigned int input_length;
	/* Outputs */
	unsigned char *output;
	unsigned int output_length;
};

/**
 * struct smw_crypto_sign_args - Sign arguments
 * @key_identifier: Pointer to the Key identifier
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
	struct smw_key_identifier *key_identifier;
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
 * @key_type_id: Key type ID
 * @security_size: Security size
 * @algo_id: Algorithm ID
 * @hashed: Is the message hashed
 * @key: Pointer to the Key
 * @key_size: Length of the key
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
	enum smw_config_key_type_id key_type_id;
	unsigned int security_size;
	enum smw_config_hash_algo_id algo_id;
	int hashed;
	unsigned char *key;
	unsigned int key_size;
	unsigned char *message;
	unsigned int message_length;
	unsigned char *signature;
	unsigned int signature_length;
};
