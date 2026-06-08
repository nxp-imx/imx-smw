// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <smw/names.h>
#include <smw_crypto.h>
#include <smw_keymgr.h>
#include <smw_status.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "apis_dispatcher.h"
#include "cli_print.h"
#include "asym_enc_algo_generated.h"
#include "common.h"
#include "error_handler.h"
#include "helper.h"
#include "logger.h"
#include "smw_asym_enc_mapping_generated.h"
#include "utils.h"

/**
 * @brief Log SMW asymmetric encryption parameters for debugging
 *
 * @param args     Pointer to the SMW asymmetric encryption arguments
 * @param encrypt  true for encryption, false for decryption
 */
static void
log_smw_asym_enc_params(const struct smw_asymmetric_encryption_args *args,
			bool encrypt)
{
	if (!args)
		return;

	LOG_INFO("=== smw_asymmetric_%s Parameters ===",
		 encrypt ? "encrypt" : "decrypt");
	LOG_INFO("  version: %u", args->version);
	LOG_INFO("  key_descriptor: %p", (void *)args->key_descriptor);
	LOG_INFO("  algo: 0x%016llx", (unsigned long long)args->algo);
	LOG_INFO("  input: %p", (void *)args->input);
	LOG_INFO("  input_length: %u", args->input_length);
	LOG_INFO("  output: %p", (void *)args->output);
	LOG_INFO("  output_length: %u", args->output_length);
	LOG_INFO("  salt: %p", (void *)args->salt);
	LOG_INFO("  salt_length: %u", args->salt_length);
	LOG_INFO("=====================================");
}

/**
 * @brief Execute an asymmetric encrypt or decrypt operation using the SMW API
 *
 * Builds the SMW algorithm bitmask from the CLI algorithm enum, sets up the
 * key descriptor, input/output buffers, and optional salt, then calls the
 * appropriate SMW asymmetric API function.
 *
 * @param args     Parsed command-line options
 * @param encrypt  true for encryption, false for decryption
 */
static enum cli_exit_code asym_enc_execute(struct parsed_options *args,
					   bool encrypt)
{
	unsigned char *input = NULL;
	unsigned char *output = NULL;
	unsigned char *salt = NULL;
	size_t input_size = 0;
	size_t output_size = 0;
	size_t salt_len = 0;
	struct smw_asymmetric_encryption_args enc_args = { 0 };
	struct smw_key_descriptor key_desc = { 0 };
	smw_key_type_t smw_key_type = SMW_KEY_TYPE_NAME_RSA;
	enum smw_status_code status = SMW_STATUS_OK;
	enum cli_exit_code ret = CLI_EXIT_OPERATION_FAILURE;
	const char *direction_str = encrypt ? "encrypt" : "decrypt";
	const char *api_name =
		encrypt ? "smw_asymmetric_encrypt" : "smw_asymmetric_decrypt";

	if (!args) {
		LOG_ERROR("NULL arguments passed to %s", __func__);
		goto cleanup;
	}

	if (!args->input_filename) {
		LOG_ERROR("Missing input filename");
		goto cleanup;
	}

	LOG_INFO("Asymmetric %s operation started (SMW API)", direction_str);
	LOG_VERBOSE("  algo           : %d", args->op.asym_enc.algo);
	LOG_VERBOSE("  key_id         : 0x%08x (%u)", args->key_id,
		    args->key_id);
	LOG_VERBOSE("  salt_hex       : %s",
		    args->op.asym_enc.salt_hex ? args->op.asym_enc.salt_hex :
						 "(none)");
	LOG_VERBOSE("  input_filename : %s", args->input_filename);
	LOG_VERBOSE("  output_filename: %s",
		    args->output_filename ? args->output_filename : "(stdout)");
	LOG_VERBOSE("  subsystem      : %s",
		    cli_smw_get_subsystem_name(args->subsystem));

	/* Parse salt if provided (optional for OAEP) */
	if (args->op.asym_enc.salt_hex) {
		LOG_VERBOSE("Parsing Salt hex string: %s",
			    args->op.asym_enc.salt_hex);
		if (util_hex_string_to_bytes(args->op.asym_enc.salt_hex, &salt,
					     &salt_len)) {
			LOG_ERROR("Failed to parse salt hex string");
			goto cleanup;
		}
		if (salt_len > UINT32_MAX) {
			LOG_ERROR("Salt length too large: %zu", salt_len);
			goto cleanup;
		}

		LOG_VERBOSE("Salt parsed: %zu bytes", salt_len);
	} else {
		LOG_VERBOSE("No Salt provided");
	}

	/* Read input file */
	LOG_VERBOSE("Reading input file: %s", args->input_filename);
	if (util_read_file(args->input_filename, &input, &input_size))
		goto cleanup;

	LOG_VERBOSE("Input file read successfully: %zu bytes", input_size);

	if (input_size > UINT32_MAX) {
		LOG_ERROR("Input size too large for SMW API: %zu", input_size);
		goto cleanup;
	}

	/*
	 * Output buffer for RSA = key security size in bytes.
	 * Use 512 bytes as safe upper bound (covers RSA-4096).
	 */
	output_size = 512;
	LOG_VERBOSE("Allocating output buffer: %zu bytes", output_size);
	output = util_alloc_buffer(output_size, "asym enc output");
	if (!output)
		goto cleanup;

	/* Setup key descriptor */
	LOG_VERBOSE("Setting up key descriptor: id=0x%08x, type=%u",
		    args->key_id, smw_key_type);
	key_desc.id = args->key_id;
	key_desc.type_name = smw_key_type;

	/* Build algo attribute bitmask */
	enc_args.algo = get_smw_asym_enc_algo(args->op.asym_enc.algo);
	if (!enc_args.algo) {
		LOG_ERROR("Unsupported asymmetric encryption algorithm");
		goto cleanup;
	}

	/* Setup SMW asymmetric encryption arguments */
	enc_args.version = 0;
	enc_args.key_descriptor = &key_desc;
	enc_args.input = input;
	enc_args.input_length = (unsigned int)input_size;
	enc_args.output = output;
	enc_args.output_length = (unsigned int)output_size;
	enc_args.salt = salt;
	enc_args.salt_length = (unsigned int)salt_len;

	if (args->subsystem != SMW_SUBSYSTEM_NAME_NONE) {
		LOG_VERBOSE("Forcing subsystem: %s",
			    cli_smw_get_subsystem_name(args->subsystem));
		enc_args.subsystem_name = args->subsystem;
	}

	log_smw_asym_enc_params(&enc_args, encrypt);

	/* Call SMW asymmetric API */
	if (encrypt) {
		LOG_VERBOSE("Calling smw_asymmetric_encrypt()");
		status = smw_asymmetric_encrypt(&enc_args);
	} else {
		LOG_VERBOSE("Calling smw_asymmetric_decrypt()");
		status = smw_asymmetric_decrypt(&enc_args);
	}

	if (!is_smw_api_success(api_name, status)) {
		if (status == SMW_STATUS_OUTPUT_TOO_SHORT)
			LOG_ERROR("Output buffer too short, need %u bytes",
				  enc_args.output_length);
		goto cleanup;
	}

	if (encrypt)
		SUCCESS("Asymmetric Encryption");
	else
		SUCCESS("Asymmetric Decryption");

	/* Use the actual output length returned by SMW */
	output_size = enc_args.output_length;
	LOG_VERBOSE("Output length: %zu bytes", output_size);

	/* Write output */
	LOG_VERBOSE("Writing output data");
	if (util_write_output_data(output, output_size, args->output_filename,
				   false)) {
		goto cleanup;
	}

	ret = CLI_EXIT_SUCCESS;

cleanup:
	if (input)
		free(input);

	if (output)
		free(output);

	if (salt)
		free(salt);

	return ret;
}

/**
 * @brief Execute asymmetric encryption using the SMW API
 *
 * @param args  Parsed command-line options
 */
enum cli_exit_code cli_asym_encrypt(struct parsed_options *args)
{
	return asym_enc_execute(args, true);
}

/**
 * @brief Execute asymmetric decryption using the SMW API
 *
 * @param args  Parsed command-line options
 */
enum cli_exit_code cli_asym_decrypt(struct parsed_options *args)
{
	return asym_enc_execute(args, false);
}
