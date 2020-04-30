/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020 NXP
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
 * smw_hash() - Compute hash.
 * @args: Pointer to the structure that contains the Hash arguments.
 *
 * This function computes a hash.
 *
 * Return:
 * error code.
 */
int smw_hash(struct smw_hash_args *args);
