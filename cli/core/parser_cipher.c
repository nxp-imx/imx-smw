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
#include "cipher_algo_generated.h"
#include "helper.h"
#include "opt_parser.h"
#include "parser_cipher.h"
#include "utils.h"

/* Short getopt options for CIPHER operations */
static const char *cipher_short_opts = "ha:k:i:o:S:L::";

/* Define options for CIPHER operations */
static const struct option cipher_long_opts[] = {
	{ "help", no_argument, 0, 'h' },
	{ "algo", required_argument, 0, 'a' },
	{ "key-id", required_argument, 0, 'k' },
	{ "input", required_argument, 0, 'i' },
	{ "output", required_argument, 0, 'o' },
	{ "iv", required_argument, 0, 1 },
	{ "subsystem", required_argument, 0, 'S' },
	{ "log", optional_argument, 0, 'L' },
	{ "list", no_argument, 0, 0 },
	{ 0, 0, 0, 0 }
};

/**
 * @brief Get inline description for encryption operation
 */
const char *cli_encrypt_inline_desc(void)
{
	return "Compute cryptographic encryption";
}

/**
 * @brief Get inline description for decryption operation
 */
const char *cli_decrypt_inline_desc(void)
{
	return "Compute cryptographic decryption";
}

/**
 * @brief Print common help for cipher operation (backend-agnostic)
 */
void cli_cipher_help_common(void)
{
	const char *prog_name = get_program_name();

	printf("Options:\n");
	printf("\n      --list                List all available cipher algorithms\n\n");
	printf("  -a, --algo <algorithm>    Cipher algorithm (required)\n");
	printf("  -k, --key-id <id>         Key identifier (required)\n");
	printf("  -i, --input <file>        Input file (required)\n");
	printf("  -o, --output <file>       Output file\n");
	if (!is_psa(prog_name))
		printf("      --iv <hex>            Initialization vector (hex string)\n");
	printf("  -L, --log <dest>          Enable session logging");
	printf(" (%s log --help for info)\n", prog_name);
	printf("  -h, --help                Show help\n");
}

/**
 * @brief Common cipher option parser used by both encrypt and decrypt
 *
 * @param argc       Argument count
 * @param argv       Argument vector
 * @param opts       Parsed options structure to fill
 * @param prog_name  Program name for error messages
 * @param op_name    Operation name ("encrypt" or "decrypt")
 */
static int parse_cipher_common(int argc, char **argv,
			       struct parsed_options *opts,
			       const char *prog_name, const char *op_name)
{
	int opt = 0;
	bool psa_backend = is_psa(prog_name);

	while ((opt = getopt_long(argc, argv, cipher_short_opts,
				  cipher_long_opts, NULL)) != -1) {
		switch (opt) {
		case 0: /* --list */
			opts->show_list = true;
			break;

		case 'h':
			opts->show_help = true;
			break;

		case 'a':
			if (!optarg) {
				FPRINTF(stderr,
					"Error: --algo requires an argument\n");
				print_help_hint(prog_name, op_name);
				return -1;
			}
			opts->op.cipher.algo = parse_cipher_algo_str(optarg);
			if (opts->op.cipher.algo == CIPHER_ALGO_NONE) {
				print_help_hint(prog_name, op_name);
				return -1;
			}
			break;

		case 'k': {
			char *endptr = NULL;
			unsigned long tmp = 0;

			if (!optarg) {
				FPRINTF(stderr,
					"Error: --key-id requires an argument\n");
				print_help_hint(prog_name, op_name);
				return -1;
			}

			errno = 0;
			tmp = strtoul(optarg, &endptr, 0);

			if (errno || endptr == optarg || *endptr != '\0') {
				FPRINTF(stderr, "Error: Invalid key ID '%s'\n",
					optarg);
				print_help_hint(prog_name, op_name);
				return -1;
			}

			if (tmp > UINT32_MAX) {
				FPRINTF(stderr,
					"Error: Key ID value out of range\n");
				print_help_hint(prog_name, op_name);
				return -1;
			}

			opts->op.cipher.key_id = (unsigned int)tmp;
			break;
		}

		case 'i':
			opts->input_filename =
				parse_file_opt(optarg, "Input filename");
			if (!opts->input_filename) {
				print_help_hint(prog_name, op_name);
				return -1;
			}
			break;

		case 'o':
			opts->output_filename =
				parse_file_opt(optarg, "Output filename");
			if (!opts->output_filename) {
				print_help_hint(prog_name, op_name);
				return -1;
			}
			break;

		case 1: /* --iv */
			if (!optarg) {
				FPRINTF(stderr,
					"Error: --iv requires a hex string argument\n");
				print_help_hint(prog_name, op_name);
				return -1;
			}
			opts->op.cipher.iv_hex = strdup(optarg);
			if (!opts->op.cipher.iv_hex) {
				FPRINTF(stderr,
					"Error: Memory allocation failed for IV\n");
				return -1;
			}
			break;

		case 'S':
			opts->subsystem = parse_subsystem(optarg);
			break;

		case 'L':
			if (parse_log_option(opts, argc, argv, prog_name,
					     op_name))
				return -1;
			break;

		default:
			print_help_hint(prog_name, op_name);
			return -1;
		}
	}

	/* --list requested */
	if (opts->show_list) {
		print_cipher_algo_list();
		return 0;
	}

	/* Validate required options (skip if --help) */
	if (!opts->show_help) {
		if (opts->op.cipher.algo == CIPHER_ALGO_NONE) {
			FPRINTF(stderr,
				"Error: --algo is required for %s operation\n",
				op_name);
			FPRINTF(stderr,
				"       Use --list to see available algorithms\n");
			print_help_hint(prog_name, op_name);
			return -1;
		}

		if (!opts->op.cipher.key_id) {
			FPRINTF(stderr,
				"Error: --key-id is required for %s operation\n",
				op_name);
			print_help_hint(prog_name, op_name);
			return -1;
		}

		if (!opts->input_filename) {
			FPRINTF(stderr,
				"Error: --input is required for %s operation\n",
				op_name);
			print_help_hint(prog_name, op_name);
			return -1;
		}

		/*
		 * IV validation is backend-dependent:
		 *   - SMW: user must provide --iv for modes that need it
		 *   - PSA: IV is managed internally (--iv accepted but ignored)
		 */
		if (!psa_backend && !opts->op.cipher.iv_hex &&
		    cipher_algo_requires_iv(opts->op.cipher.algo)) {
			FPRINTF(stderr,
				"Error: --iv is required for this algorithm\n");
			print_help_hint(prog_name, op_name);
			return -1;
		}

		if (opts->op.cipher.iv_hex &&
		    !cipher_algo_requires_iv(opts->op.cipher.algo)) {
			FPRINTF(stderr,
				"Warning: --iv is ignored for ECB mode\n");
		}

		if (psa_backend && opts->op.cipher.iv_hex &&
		    cipher_algo_requires_iv(opts->op.cipher.algo)) {
			FPRINTF(stderr,
				"Note: --iv accepted but ignored (PSA manages IV internally)\n");
		}
	}

	return 0;
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
	return parse_cipher_common(argc, argv, opts, prog_name, "encrypt");
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
	return parse_cipher_common(argc, argv, opts, prog_name, "decrypt");
}
