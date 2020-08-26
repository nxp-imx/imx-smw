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
