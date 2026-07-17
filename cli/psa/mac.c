// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <assert.h>
#include <psa/crypto.h>
#include "apis_dispatcher.h"
#include "cli_print.h"
#include "common.h"
#include "helper.h"
#include "logger.h"
#include "parser_mac.h"
#include "psa_mac_algo_table_generated.h"
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
	printf("MAC Operation - PSA API\n\n");

	cli_mac_help_common();

	printf("\nExamples:\n");
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
	printf("MAC Verify Operation - PSA API\n\n");

	cli_mac_verify_help_common();

	printf("\nExamples:\n");
	printf("  %s mac-verify -k 8 -a HMAC-SHA256 -i input -m mac.bin\n",
	       prog_name);
	printf("  %s mac-verify -k 9 -a CMAC -i input -m cmac.bin\n",
	       prog_name);
}

/**
 * @brief Log PSA MAC operation parameters
 *
 * @param key_id    PSA key identifier
 * @param alg       PSA algorithm identifier
 * @param input     Input data buffer
 * @param input_len Input data length in bytes
 * @param mac       MAC buffer
 * @param mac_size  MAC buffer size in bytes
 * @param verify    true if verify mode, false if compute mode
 */
static void log_psa_mac_params(psa_key_id_t key_id, psa_algorithm_t alg,
			       const uint8_t *input, size_t input_len,
			       const uint8_t *mac, size_t mac_size, bool verify)
{
	LOG_INFO("=== psa_mac_%s Parameters ===",
		 verify ? "verify" : "compute");
	LOG_INFO("  key_id: 0x%08x (%u)", (unsigned int)key_id,
		 (unsigned int)key_id);
	LOG_INFO("  alg: 0x%08x", (unsigned int)alg);
	LOG_INFO("  input: %p", (const void *)input);
	LOG_INFO("  input_length: %zu", input_len);
	LOG_INFO("  mac: %p", (const void *)mac);
	LOG_INFO("  mac_size: %zu", mac_size);
	LOG_INFO("==============================");
}

/**
 * @brief Resolve PSA algorithm from CLI algo string
 *
 * @param algo_str   Combined algo string e.g. "HMAC-SHA256", "CMAC"
 * @param psa_alg    Output: PSA algorithm (without truncation applied)
 * @param truncated  Output: true if truncated variant requested
 */
static int resolve_psa_algo(const char *algo_str, psa_algorithm_t *psa_alg,
			    bool *truncated)
{
	char base[MAC_BASE_MAX_LEN] = { 0 };
	char hash[MAC_HASH_MAX_LEN] = { 0 };
	psa_algorithm_t base_alg = PSA_ALG_NONE;
	psa_algorithm_t hash_alg = PSA_ALG_NONE;

	if (mac_parse_algo_string(algo_str, base, sizeof(base), hash,
				  sizeof(hash)))
		return -1;

	/*
	 * cli_mac_base_to_psa() is auto-generated from psa_cmac_algos[].
	 * Sets *truncated = true for CMAC_TRUNCATED / HMAC_TRUNCATED.
	 */
	base_alg = cli_mac_base_to_psa(base, truncated);
	if (base_alg == PSA_ALG_NONE) {
		LOG_ERROR("Failed to map MAC algorithm: %s", base);
		return -1;
	}

	if (base_alg == PSA_ALG_HMAC_BASE) {
		if (!*hash) {
			LOG_ERROR("HMAC requires a hash algorithm");
			return -1;
		}

		hash_alg = cli_hash_str_to_psa(hash);
		if (hash_alg == PSA_ALG_NONE) {
			LOG_ERROR("Failed to map hash algorithm: %s", hash);
			return -1;
		}

		*psa_alg = PSA_ALG_HMAC(hash_alg);
	} else {
		/* CMAC / CBC-MAC: algorithm is already complete */
		*psa_alg = base_alg;
	}

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
	int mac_max = 0;
	size_t mac_length = 0;
	psa_algorithm_t psa_alg = PSA_ALG_NONE;
	psa_algorithm_t final_alg = PSA_ALG_NONE;
	psa_key_id_t key_id = 0;
	psa_status_t status = PSA_SUCCESS;
	enum cli_exit_code ret = CLI_EXIT_OPERATION_FAILURE;
	bool truncated = false;

	/* Resolve PSA algorithm from CLI algo string e.g. "HMAC-SHA256" */
	if (resolve_psa_algo(args->op.mac.algo, &psa_alg, &truncated))
		goto cleanup;

	/* Read input data file */
	if (util_read_file(args->input_filename, &input, &input_size))
		goto cleanup;

	key_id = (psa_key_id_t)args->op.mac.key_id;

	if (verify) {
		/*
		 * Verify mode: read MAC from file, apply truncation if needed
		 * using the actual MAC size from the file, then call
		 * psa_mac_verify().
		 */
		if (util_read_file(args->op.mac.mac_filename, &mac_buf,
				   &mac_size))
			goto cleanup;

		/*
		 * For truncated MACs: apply PSA_ALG_TRUNCATED_MAC()
		 */
		if (truncated)
			final_alg = PSA_ALG_TRUNCATED_MAC(psa_alg, mac_size);
		else
			final_alg = psa_alg;

		log_psa_mac_params(key_id, final_alg, input, input_size,
				   mac_buf, mac_size, true);

		status = psa_mac_verify(key_id, final_alg, input, input_size,
					mac_buf, mac_size);
		if (!is_psa_api_success("psa_mac_verify", status))
			goto cleanup;

		SUCCESS("MAC Verification");

	} else {
		/*
		 * Compute mode: allocate PSA_MAC_MAX_SIZE buffer,
		 * call psa_mac_compute(), write actual mac_length bytes.
		 */
		mac_max = PSA_MAC_MAX_SIZE;

		if (mac_max < 0) {
			LOG_ERROR("Invalid PSA_MAC_MAX_SIZE value: %d",
				  mac_max);
			goto cleanup;
		}
		mac_size = (size_t)mac_max;

		mac_buf = util_alloc_buffer(mac_size, "MAC output");
		if (!mac_buf)
			goto cleanup;

		final_alg = psa_alg;

		log_psa_mac_params(key_id, final_alg, input, input_size,
				   mac_buf, mac_size, false);

		status = psa_mac_compute(key_id, final_alg, input, input_size,
					 mac_buf, mac_size, &mac_length);
		if (!is_psa_api_success("psa_mac_compute", status))
			goto cleanup;

		SUCCESS("MAC Computation");

		if (util_write_output_data(mac_buf, mac_length,
					   args->op.mac.mac_filename,
					   args->text_format))
			goto cleanup;

		LOG_INFO("MAC computed successfully (%zu bytes)", mac_length);
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
 * @brief Execute MAC compute operation using PSA API
 * @param args Parsed CLI options
 */
enum cli_exit_code cli_mac_operation(struct parsed_options *args)
{
	if (!args) {
		LOG_ERROR("NULL arguments passed to %s", __func__);
		return CLI_EXIT_OPERATION_FAILURE;
	}

	LOG_INFO("MAC compute operation (PSA API)");
	return mac_run(args, false);
}

/**
 * @brief Execute MAC verify operation using PSA API
 * @param args Parsed CLI options
 */
enum cli_exit_code cli_mac_verify_operation(struct parsed_options *args)
{
	if (!args) {
		LOG_ERROR("NULL arguments passed to %s", __func__);
		return CLI_EXIT_OPERATION_FAILURE;
	}

	LOG_INFO("MAC verify operation (PSA API)");
	return mac_run(args, true);
}
