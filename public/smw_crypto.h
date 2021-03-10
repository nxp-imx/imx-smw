/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2021 NXP
 */

/**
 * struct smw_hash_args - Hash arguments
 * @version: Version of this structure
 * @subsystem_name: Secure Subsystem name
 * @algo_name: Algorithm name
 * @input: Location of the stream to be hashed
 * @input_length: Length of the stream to be hashed
 * @output: Location where the digest has to be written
 * @output_length: Length of the digest
 *
 * @subsystem_name designates the Secure Subsystem to be used.
 * If this field is NULL, the default configured Secure Subsystem is used.
 */
struct smw_hash_args {
	/* Inputs */
	unsigned char version;
	const char *subsystem_name;
	const char *algo_name;
	unsigned char *input;
	unsigned int input_length;
	/* Outputs */
	unsigned char *output;
	unsigned int output_length;
};

/**
 * struct smw_sign_verify_args - Sign or verify arguments
 * @version: Version of this structure
 * @subsystem_name: Secure Subsystem name
 * @key_descriptor: Pointer to a Key descriptor object
 * @algo_name: Hash algorithm name
 * @message: Location of the message
 * @message_length: Length of the message
 * @signature: Location of the signature
 * @signature_length: Length of the signature
 *
 * @subsystem_name designates the Secure Subsystem to be used.
 * If this field is NULL, the default configured Secure Subsystem is used.
 */
struct smw_sign_verify_args {
	/* Inputs */
	unsigned char version;
	const char *subsystem_name;
	struct smw_key_descriptor *key_descriptor;
	const char *algo_name;
	unsigned char *message;
	unsigned int message_length;
	unsigned char *signature;
	unsigned int signature_length;
};

/**
 * struct smw_hmac_args - HMAC arguments
 * @version: Version of this structure
 * @subsystem_name: Secure Subsystem name
 * @key_descriptor: Pointer to a Key descriptor object
 * @algo_name: Algorithm name
 * @input: Location of the stream to be hash-mac'ed
 * @input_length: Length of the stream to be hashed
 * @output: Location where the MAC has to be written
 * @output_length: Length of the MAC
 *
 * @subsystem_name designates the Secure Subsystem to be used.
 * If this field is NULL, the default configured Secure Subsystem is used.
 */
struct smw_hmac_args {
	/* Inputs */
	unsigned char version;
	const char *subsystem_name;
	struct smw_key_descriptor *key_descriptor;
	const char *algo_name;
	unsigned char *input;
	unsigned int input_length;
	/* Outputs */
	unsigned char *output;
	unsigned int output_length;
};

/**
 * smw_hash() - Compute hash.
 * @args: Pointer to the structure that contains the Hash arguments.
 *
 * This function computes a hash.
 *
 * Return:
 * error code.
 */
int smw_hash(struct smw_hash_args *args);

/**
 * smw_sign() - Generate a signature.
 * @args: Pointer to the structure that contains the Sign arguments.
 *
 * This function generates a signature.
 *
 * Return:
 * error code.
 */
int smw_sign(struct smw_sign_verify_args *args);

/**
 * smw_verify() - Verify a signature.
 * @args: Pointer to the structure that contains the Verify arguments.
 *
 * This function verifies a sigature.
 *
 * Return:
 * error code.
 */
int smw_verify(struct smw_sign_verify_args *args);

/**
 * smw_hmac() - Compute a HASH-MAC.
 * @args: Pointer to the structure that contains the HMAC arguments.
 *
 * This function computes a Keyed-Hash Message Authentication Code.
 *
 * Return:
 * error code.
 */
int smw_hmac(struct smw_hmac_args *args);
