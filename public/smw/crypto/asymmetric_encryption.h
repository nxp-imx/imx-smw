/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2025 NXP
 */

#ifndef __SMW_ASYMMETRIC_ENCRYPTION_H__
#define __SMW_ASYMMETRIC_ENCRYPTION_H__

#include "smw_status.h"
#include "smw/names.h"
#include "smw/attr.h"

/**
 * struct smw_asymmetric_encryption_args - Asymmetric encryption and decryption
 *                                         arguments structure
 * @version: Version of this structure
 * @subsystem_name: Secure Subsystem name. See &typedef smw_subsystem_t
 * @key_descriptor: Pointer to a Key descriptor object.
 *		    See &struct smw_key_descriptor
 * @algo: Encryption/decryption algorithm and attributes.
 *          See &typedef smw_attr_algo_t
 * @input: Pointer to input data buffer
 * @input_length: Input data buffer length in bytes
 * @output: Pointer to output buffer
 * @output_length: Output buffer length in bytes
 * @salt: Pointer to salt or label buffer
 * @salt_length: Salt buffer length in bytes
 *
 * @algo is defined by set of parameters, including encryption algorithm,
 * mode (padding schemes), hashing algorithm used in the padding scheme and
 * operation class.
 * @salt and @salt_length are optional arguments. These parameters are ignored
 * if not supported by the encryption modes.
 */
struct smw_asymmetric_encryption_args {
	unsigned char version;
	smw_subsystem_t subsystem_name;
	struct smw_key_descriptor *key_descriptor;
	smw_attr_algo_t algo;
	unsigned char *input;
	unsigned int input_length;
	unsigned char *output;
	unsigned int output_length;
	unsigned char *salt;
	unsigned int salt_length;
};

/**
 * smw_asymmetric_encrypt() - Encrypt a message
 * @args: Pointer to asymmetric encryption and decryption arguments structure.
 *
 * This function encrypts a message using public key ID or key buffer.
 *
 * This function updates @args->output_length field to required output
 * buffer length if @args->output is a NULL pointer and returns error code
 * SMW_STATUS_OK.
 *
 * @args->output_length field is updated to the correct value in the following
 * cases
 *
 *  - If the provided output length is bigger than required, the operation
 *    succeeds.
 *  - If the provided output length is shorter than required, the operation
 *    fails and returns SMW_STATUS_OUTPUT_TOO_SHORT.
 *
 * Return:
 * See &enum smw_status_code
 *	- Common return codes
 */
enum smw_status_code
smw_asymmetric_encrypt(struct smw_asymmetric_encryption_args *args);

/**
 * smw_asymmetric_decrypt() - Decrypt a message
 * @args: Pointer to asymmetric encryption and decryption arguments structure.
 *
 * This function decrypts a message using private key ID or key buffer.
 *
 * @args->output_length field is updated to the correct value in the following
 * cases
 *
 *  - If the provided output length is bigger than required, the operation
 *    succeeds.
 *  - If the provided output length is shorter than required, the operation
 *    fails and returns SMW_STATUS_OUTPUT_TOO_SHORT.
 *
 * Return:
 * See &enum smw_status_code
 *	- Common return codes
 */
enum smw_status_code
smw_asymmetric_decrypt(struct smw_asymmetric_encryption_args *args);

#endif /* __SMW_ASYMMETRIC_ENCRYPTION_H__ */
