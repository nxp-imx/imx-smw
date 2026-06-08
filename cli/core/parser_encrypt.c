// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "asym_enc_algo_generated.h"
#include "cipher_algo_generated.h"
#include "cli_print.h"
#include "helper.h"
#include "logger.h"
#include "opt_parser.h"
#include "parser_encrypt.h"
#include "utils.h"

/* Short getopt options for asymmetric and symmetric encryption operations */
static const char *ecnrypt_short_opts = ":ha:k:i:o:S:";

/* Define options for asymmetric and symmetric encryption operations */
static const struct option encrypt_long_opts[] = {
	{ "help", no_argument, 0, 'h' },
	{ "algo", required_argument, 0, 'a' },
	{ "key-id", required_argument, 0, 'k' },
	{ "input", required_argument, 0, 'i' },
	{ "output", required_argument, 0, 'o' },
	{ "iv", required_argument, 0, 1 },
	{ "salt", required_argument, 0, 2 },
	{ "subsystem", required_argument, 0, 'S' },
	{ "list", no_argument, 0, 0 },
	{ "v", optional_argument, 0, 0 },
	{ "vv", optional_argument, 0, 0 },
	{ 0, 0, 0, 0 }
};

/**
 * @brief Get inline description for encryption operation
 */
const char *cli_encrypt_inline_desc(void)
{
	return "Compute cryptographic encryption (symmetric or asymmetric)";
}

/**
 * @brief Get inline description for decryption operation
 */
const char *cli_decrypt_inline_desc(void)
{
	return "Compute cryptographic decryption (symmetric or asymmetric)";
}

/**
 * @brief Print common help for encrypt operation (backend-agnostic)
 */
void cli_encrypt_help_common(void)
{
	const char *prog_name = get_program_name();

	printf("Options:\n");
	printf("\n      --list                List all available algorithms\n\n");
	printf("  -a, --algo <algorithm>    Algorithm (required)\n");
	printf("  -k, --key-id <id>         Key identifier (required)\n");
	printf("  -i, --input <file>        Input file (required)\n");
	printf("  -o, --output <file>       Output file\n");
	if (!is_psa(prog_name))
		printf("      --iv <hex>            IV for symmetric encryption (hex string)\n");
	printf("      --salt <hex>          Salt for RSA-OAEP (hex string, optional)\n");
	print_log_options_help(prog_name);
	print_help_option_help();
}

/**
 * @brief Common encryption and decryption option parser
 *
 * @param argc       Argument count
 * @param argv       Argument vector
 * @param opts       Parsed options structure to fill
 * @param prog_name  Program name for error messages
 * @param op_name    Operation name ("encrypt" or "decrypt")
 */
static int parse_encrypt_common(int argc, char **argv,
				struct parsed_options *opts,
				const char *prog_name, const char *op_name)
{
	int opt = 0;
	int opt_index = 0;
	opterr = 0;
	bool psa_backend = is_psa(prog_name);
	char *iv_hex = NULL;
	char *salt_hex = NULL;

	LOG_VERBOSE("Parsing %s options (argc=%d)", op_name, argc);

	while ((opt = getopt_long(argc, argv, ecnrypt_short_opts,
				  encrypt_long_opts, &opt_index)) != -1) {
		switch (opt) {
		case 0:
			if (!strcmp(encrypt_long_opts[opt_index].name,
				    "list")) {
				opts->show_list = true;
			} else if (!strcmp(encrypt_long_opts[opt_index].name,
					   "v")) {
				if (parse_log_option(opts, argc, argv,
						     prog_name, op_name,
						     LOG_LEVEL_INFO))
					goto err;
			} else if (!strcmp(encrypt_long_opts[opt_index].name,
					   "vv")) {
				if (parse_log_option(opts, argc, argv,
						     prog_name, op_name,
						     LOG_LEVEL_VERBOSE))
					goto err;
			}
			break;

		case 'h':
			opts->show_help = true;
			break;

		case 'a':
			if (!optarg) {
				ERROR("--algo requires an argument");
				print_help_hint(prog_name, op_name);
				goto err;
			}

			LOG_VERBOSE("  algo = %s", optarg);

			/* Try cipher first */
			opts->op.cipher.algo = parse_cipher_algo_str(optarg);
			if (opts->op.cipher.algo != CIPHER_ALGO_NONE) {
				opts->cipher_family = CIPHER_FAMILY_SYMMETRIC;
				break;
			}

			/* Try asymmetric encryption */
			opts->op.asym_enc.algo =
				parse_asym_enc_algo_str(optarg);
			if (opts->op.asym_enc.algo != ASYM_ENC_ALGO_NONE) {
				opts->cipher_family = CIPHER_FAMILY_ASYMMETRIC;
				break;
			}

			ERROR("Unknown algorithm '%s'\n", optarg);
			PRINT_USE_LIST("algorithms");
			print_help_hint(prog_name, op_name);
			goto err;

		case 'k': {
			char *endptr = NULL;
			unsigned long tmp = 0;

			if (!optarg) {
				ERROR("--key-id requires an argument");
				print_help_hint(prog_name, op_name);
				goto err;
			}

			errno = 0;
			tmp = strtoul(optarg, &endptr, 0);

			if (errno || endptr == optarg || *endptr != '\0') {
				ERROR("Invalid key ID '%s'", optarg);
				print_help_hint(prog_name, op_name);
				goto err;
			}

			if (tmp > UINT32_MAX) {
				ERROR("Key ID value out of range");
				print_help_hint(prog_name, op_name);
				goto err;
			}

			opts->key_id = (unsigned int)tmp;
			LOG_VERBOSE("  key_id = %lu", tmp);
			break;
		}

		case 'i':
			opts->input_filename =
				parse_file_opt(optarg, "Input filename");
			if (!opts->input_filename) {
				print_help_hint(prog_name, op_name);
				goto err;
			}
			LOG_VERBOSE("  input_filename = %s",
				    opts->input_filename);
			break;

		case 'o':
			opts->output_filename =
				parse_file_opt(optarg, "Output filename");
			if (!opts->output_filename) {
				print_help_hint(prog_name, op_name);
				goto err;
			}
			LOG_VERBOSE("  output_filename = %s",
				    opts->output_filename);
			break;

		case 1: /* --iv (stored in local, assigned to union later) */
			if (!optarg) {
				ERROR("--iv requires a hex string argument");
				print_help_hint(prog_name, op_name);
				goto err;
			}
			free(iv_hex);
			iv_hex = strdup(optarg);
			if (!iv_hex) {
				ERROR("Memory allocation failed for IV");
				goto err;
			}

			LOG_VERBOSE("  iv_hex = %s", optarg);
			break;

		case 2: /* --salt (stored in local, assigned to union later) */
			if (!optarg) {
				ERROR("--salt requires a hex string argument");
				print_help_hint(prog_name, op_name);
				goto err;
			}
			free(salt_hex);
			salt_hex = strdup(optarg);
			if (!salt_hex) {
				ERROR("Memory allocation failed for salt");
				goto err;
			}

			LOG_VERBOSE("  salt_hex = %s", optarg);
			break;

		case 'S':
			opts->subsystem = parse_subsystem(optarg);
			LOG_VERBOSE("  subsystem = %s", optarg);
			break;

		case ':':
			ERROR("Option '%s' requires an argument",
			      SAFE_ARGV_OPT(argv, "<unknown>"));
			print_help_hint(prog_name, op_name);
			goto err;

		case '?':
		default:
			ERROR("Unknown option '%s'",
			      SAFE_ARGV_OPT(argv, "<unknown>"));
			print_help_hint(prog_name, op_name);
			goto err;
		}
	}

	/* --list: show both symmetric and asymmetric algorithms */
	if (opts->show_list) {
		print_cipher_algo_list();
		print_asym_enc_algo_list();
		free(iv_hex);
		free(salt_hex);
		return 0;
	}

	if (opts->show_help) {
		free(iv_hex);
		free(salt_hex);
		return 0;
	}

	/* Common required options */
	if (opts->cipher_family == CIPHER_FAMILY_NONE) {
		ERROR("--algo is required for %s operation", op_name);
		PRINT_USE_LIST("algorithms");
		print_help_hint(prog_name, op_name);
		goto err;
	}

	if (!opts->key_id) {
		ERROR("--key-id is required for %s operation", op_name);
		print_help_hint(prog_name, op_name);
		goto err;
	}

	if (!opts->input_filename) {
		ERROR("--input is required for %s operation", op_name);
		print_help_hint(prog_name, op_name);
		goto err;
	}

	/* Assign locals to the correct union member based on family */
	if (opts->cipher_family == CIPHER_FAMILY_SYMMETRIC) {
		opts->op.cipher.iv_hex = iv_hex;

		if (salt_hex) {
			WARNING("-salt is ignored for symmetric cipher\n");
			free(salt_hex);
		}

		if (!psa_backend && !opts->op.cipher.iv_hex &&
		    cipher_algo_requires_iv(opts->op.cipher.algo)) {
			ERROR("--iv is required for this algorithm");
			print_help_hint(prog_name, op_name);
			goto err;
		}

		if (opts->op.cipher.iv_hex &&
		    !cipher_algo_requires_iv(opts->op.cipher.algo)) {
			WARNING("--iv is ignored for ECB mode\n");
		}

		if (psa_backend && opts->op.cipher.iv_hex &&
		    cipher_algo_requires_iv(opts->op.cipher.algo)) {
			WARNING("--iv accepted but ignored (PSA manages IV internally)\n");
		}
	} else if (opts->cipher_family == CIPHER_FAMILY_ASYMMETRIC) {
		opts->op.asym_enc.salt_hex = salt_hex;

		if (iv_hex) {
			WARNING("--iv is ignored for asymmetric operation\n");
			free(iv_hex);
		}
	}

	LOG_VERBOSE("Cipher %s options parsed successfully", op_name);

	return 0;

err:
	if (iv_hex)
		free(iv_hex);

	if (salt_hex)
		free(salt_hex);

	return -1;
}

/**
 * @brief Parse command-line options for the encrypt operation
 *
 * @param argc       Argument count
 * @param argv       Argument vector
 * @param opts       Parsed options structure to fill
 * @param prog_name  Program name for error messages
 */
int parse_encrypt_options(int argc, char **argv, struct parsed_options *opts,
			  const char *prog_name)
{
	return parse_encrypt_common(argc, argv, opts, prog_name, "encrypt");
}

/**
 * @brief Parse command-line options for the decrypt operation
 *
 * @param argc       Argument count
 * @param argv       Argument vector
 * @param opts       Parsed options structure to fill
 * @param prog_name  Program name for error messages
 */
int parse_decrypt_options(int argc, char **argv, struct parsed_options *opts,
			  const char *prog_name)
{
	return parse_encrypt_common(argc, argv, opts, prog_name, "decrypt");
}
