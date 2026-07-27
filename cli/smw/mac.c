// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <smw_crypto.h>
#include <smw_keymgr.h>
#include <smw_status.h>
#include "apis_dispatcher.h"
#include "cli_print.h"
#include "common.h"
#include "error_handler.h"
#include "helper.h"
#include "logger.h"
#include "parser_mac.h"
#include "smw_mac_algo_table_generated.h"
#include "utils.h"

#define MAC_BASE_MAX_LEN 32
#define MAC_HASH_MAX_LEN 32

/**
 * @brief Print MAC compute help
 */
void cli_mac_help(void)
{
	const char *prog_name = get_program_name();

	printf("\n");
	print_tool_banner();
	printf("MAC Operation - SMW API\n\n");

	cli_mac_help_common();

	printf("  -S, --subsystem <name>  Force subsystem (ELE/TEE/SECO)\n\n");
	printf("Examples:\n");
	printf("  %s mac -k 8 -a HMAC-SHA256 -i input -m mac.bin\n", prog_name);
	printf("  %s mac -k 9 -a CMAC -i input -m cmac.bin -t\n\n", prog_name);
}

/**
 * @brief Print MAC verify help
 */
void cli_mac_verify_help(void)
{
	const char *prog_name = get_program_name();

	printf("\n");
	print_tool_banner();
	printf("MAC Verify Operation - SMW API\n\n");

	cli_mac_verify_help_common();

	printf("  -S, --subsystem <name>  Force subsystem (ELE/TEE/SECO)\n\n");
	printf("Examples:\n");
	printf("  %s mac-verify -k 8 -a HMAC-SHA256 -i input -m mac.bin\n",
	       prog_name);
	printf("  %s mac-verify -k 9 -a CMAC -i input -m cmac.bin\n\n",
	       prog_name);
}

/**
 * @brief Log SMW MAC operation parameters
 *
 * @param args   Pointer to SMW MAC arguments structure
 * @param verify true if verify mode, false if compute mode
 */
static void log_smw_mac_params(const struct smw_mac_args *args, bool verify)
{
	if (!args)
		return;

	LOG_INFO("=== smw_mac%s Parameters ===", verify ? "_verify" : "");
	LOG_INFO("  version: %u", args->version);
	LOG_INFO("  subsystem_name: %s",
		 cli_smw_get_subsystem_name(args->subsystem_name));
	LOG_INFO("  algo_name: %u", (unsigned int)args->algo_name);
	LOG_INFO("  hash_name: %u", (unsigned int)args->hash_name);
	LOG_INFO("  input: %p", (void *)args->input);
	LOG_INFO("  input_length: %u", args->input_length);
	LOG_INFO("  mac: %p", (void *)args->mac);
	LOG_INFO("  mac_length: %u", args->mac_length);
	LOG_INFO("==============================");
}

/**
 * @brief Parse algo string and fill SMW algo/hash fields
 *
 * @param algo_str Combined algo string from CLI (e.g. "HMAC-SHA256", "CMAC")
 * @param smw_algo Output SMW MAC algorithm enum value
 * @param smw_hash Output SMW hash algorithm enum value
 */
static int resolve_smw_algo(const char *algo_str, smw_mac_algo_t *smw_algo,
			    smw_hash_algo_t *smw_hash)
{
	char base[MAC_BASE_MAX_LEN] = { 0 };
	char hash[MAC_HASH_MAX_LEN] = { 0 };

	if (mac_parse_algo_string(algo_str, base, sizeof(base), hash,
				  sizeof(hash)))
		return -1;

	*smw_algo = cli_mac_base_to_smw(base);
	if (*smw_algo == SMW_MAC_ALGO_NAME_NONE) {
		LOG_ERROR("Failed to map MAC algorithm: %s", base);
		return -1;
	}

	*smw_hash = cli_hash_str_to_smw(hash);

	return 0;
}

/**
 * @brief Core MAC operation logic shared by compute and verify
 *
 * @param args    Parsed CLI options
 * @param verify  true = verify mode, false = compute mode
 */
static enum cli_exit_code mac_run(struct parsed_options *args, bool verify)
{
	unsigned char *input = NULL;
	unsigned char *mac_buf = NULL;
	size_t input_size = 0;
	size_t mac_size = 0;
	struct smw_mac_args mac_args = { 0 };
	struct smw_key_descriptor key_desc = { 0 };
	enum smw_status_code status = SMW_STATUS_OK;
	enum cli_exit_code ret = CLI_EXIT_OPERATION_FAILURE;
	smw_mac_algo_t smw_algo = SMW_MAC_ALGO_NAME_NONE;
	smw_hash_algo_t smw_hash = SMW_HASH_ALGO_NAME_NONE;

	LOG_VERBOSE("  algo           : %s", args->op.mac.algo);
	LOG_VERBOSE("  key_id         : 0x%08x (%u)", args->op.mac.key_id,
		    args->op.mac.key_id);
	LOG_VERBOSE("  mac_filename   : %s", args->op.mac.mac_filename ?
						     args->op.mac.mac_filename :
						     "(none)");
	LOG_VERBOSE("  input_filename : %s",
		    args->input_filename ? args->input_filename : "(none)");
	LOG_VERBOSE("  subsystem      : %s",
		    cli_smw_get_subsystem_name(args->subsystem));

	/* Parse combined algo string e.g. "HMAC-SHA256" */
	LOG_VERBOSE("Parsing MAC algorithm string: %s", args->op.mac.algo);
	if (resolve_smw_algo(args->op.mac.algo, &smw_algo, &smw_hash))
		goto cleanup;

	LOG_VERBOSE("SMW MAC algo resolved: %u, hash: %u",
		    (unsigned int)smw_algo, (unsigned int)smw_hash);

	/* Read input data file */
	LOG_VERBOSE("Reading input file: %s", args->input_filename);
	if (util_read_file(args->input_filename, &input, &input_size))
		goto cleanup;

	LOG_VERBOSE("Input file read successfully: %zu bytes", input_size);

	if (input_size > UINT32_MAX) {
		LOG_ERROR("Input size too large for SMW API: %zu", input_size);
		goto cleanup;
	}

	/* Setup key descriptor (key by ID) */
	LOG_VERBOSE("Setting up key descriptor: id=0x%08x",
		    args->op.mac.key_id);
	key_desc.id = args->op.mac.key_id;

	/* Setup MAC arguments */
	mac_args.version = 0;
	mac_args.key_descriptor = &key_desc;
	mac_args.algo_name = smw_algo;
	mac_args.hash_name = smw_hash;
	mac_args.input = input;
	mac_args.input_length = (unsigned int)input_size;

	if (args->subsystem != SMW_SUBSYSTEM_NAME_NONE) {
		LOG_VERBOSE("Forcing subsystem: %s",
			    cli_smw_get_subsystem_name(args->subsystem));
		mac_args.subsystem_name = args->subsystem;
	}

	if (verify) {
		/*
		 * Verify mode: read MAC from file and pass to
		 * smw_mac_verify()
		 */
		LOG_VERBOSE("Reading MAC file: %s", args->op.mac.mac_filename);
		if (util_read_file(args->op.mac.mac_filename, &mac_buf,
				   &mac_size))
			goto cleanup;

		LOG_VERBOSE("MAC file read successfully: %zu bytes", mac_size);

		if (mac_size > UINT32_MAX) {
			LOG_ERROR("MAC size too large for SMW API: %zu",
				  mac_size);
			goto cleanup;
		}

		mac_args.mac = mac_buf;
		mac_args.mac_length = (unsigned int)mac_size;

		log_smw_mac_params(&mac_args, true);

		LOG_VERBOSE("Calling smw_mac_verify()");
		status = smw_mac_verify(&mac_args);
		if (!is_smw_api_success("smw_mac_verify", status))
			goto cleanup;

		SUCCESS("MAC Verification");

	} else {
		/*
		 * Compute mode: first call with NULL mac to get output size,
		 * then allocate and call again.
		 */
		mac_args.mac = NULL;
		mac_args.mac_length = 0;

		log_smw_mac_params(&mac_args, false);

		/* First call: get required MAC length */
		LOG_VERBOSE("Calling smw_mac() to get required MAC length");
		status = smw_mac(&mac_args);
		if (status != SMW_STATUS_OUTPUT_TOO_SHORT &&
		    status != SMW_STATUS_OK) {
			/*
			 * CID 54620330: Capture and use the return value of
			 * is_smw_api_success to avoid unchecked return value.
			 */
			(void)is_smw_api_success("smw_mac (get length)",
						 status);
			goto cleanup;
		}

		mac_size = mac_args.mac_length;
		if (!mac_size) {
			LOG_ERROR("SMW returned zero MAC length");
			goto cleanup;
		}

		LOG_VERBOSE("Required MAC length: %zu bytes", mac_size);

		mac_buf = util_alloc_buffer(mac_size, "MAC output");
		if (!mac_buf)
			goto cleanup;

		if (mac_size > UINT32_MAX) {
			LOG_ERROR("MAC size too large for SMW API: %zu",
				  mac_size);
			goto cleanup;
		}

		mac_args.mac = mac_buf;
		mac_args.mac_length = (unsigned int)mac_size;

		/* Second call: compute MAC */
		LOG_VERBOSE("Calling smw_mac() to compute MAC");
		status = smw_mac(&mac_args);
		if (!is_smw_api_success("smw_mac", status))
			goto cleanup;

		SUCCESS("MAC Computation");

		LOG_VERBOSE("MAC computed successfully: %u bytes",
			    mac_args.mac_length);

		/* Write output (file or stdout) */
		LOG_VERBOSE("Writing MAC output data");
		if (util_write_output_data(mac_buf, mac_args.mac_length,
					   args->op.mac.mac_filename,
					   args->text_format))
			goto cleanup;

		LOG_INFO("MAC computed successfully (%u bytes)",
			 mac_args.mac_length);
	}

	ret = CLI_EXIT_SUCCESS;

cleanup:
	if (input)
		free(input);

	if (mac_buf)
		free(mac_buf);

	return ret;
}

/**
 * @brief Execute MAC compute operation using SMW API
 *
 * @param args Pointer to parsed command-line arguments
 */
enum cli_exit_code cli_mac_operation(struct parsed_options *args)
{
	if (!args) {
		LOG_ERROR("NULL arguments passed to %s", __func__);
		return CLI_EXIT_OPERATION_FAILURE;
	}

	LOG_INFO("MAC compute operation started (SMW API)");
	return mac_run(args, false);
}

/**
 * @brief Execute MAC verify operation using SMW API
 *
 * @param args Pointer to parsed command-line arguments
 */
enum cli_exit_code cli_mac_verify_operation(struct parsed_options *args)
{
	if (!args) {
		LOG_ERROR("NULL arguments passed to %s", __func__);
		return CLI_EXIT_OPERATION_FAILURE;
	}

	LOG_INFO("MAC verify operation started (SMW API)");
	return mac_run(args, true);
}
