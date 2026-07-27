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
#include "cli_print.h"
#include "helper.h"
#include "logger.h"
#include "mac_algo_mappings.h"
#include "opt_parser.h"
#include "parser_mac.h"
#include "utils.h"

#define MAC_BASE_MAX_LEN 32
#define MAC_HASH_MAX_LEN 32

/**
 * @brief Check if a base MAC algorithm is HMAC-based (requires a hash)
 *
 * @param base algorithm name string (e.g. "HMAC", "CMAC")
 */
static bool mac_base_needs_hash(const char *base)
{
	const struct mac_base_entry *entries = get_mac_base_entries();
	size_t count = get_mac_base_entries_count();
	size_t i = 0;

	if (!base)
		return false;

	for (; i < count; i++) {
		if (!strcasecmp(base, entries[i].name))
			return entries[i].needs_hash;
	}

	return false;
}

/**
 * @brief Check if a base MAC algorithm string is valid
 *
 * @param base algorithm name string to validate
 */
static bool is_valid_mac_base(const char *base)
{
	const struct mac_base_entry *entries = get_mac_base_entries();
	size_t count = get_mac_base_entries_count();
	size_t i = 0;

	if (!base)
		return false;

	for (; i < count; i++) {
		if (!strcasecmp(base, entries[i].name))
			return true;
	}

	return false;
}

/**
 * @brief Check if a hash algorithm string is valid for HMAC
 *
 * @param hash algorithm name string to validate (e.g. "SHA256")
 */
static bool is_valid_hmac_hash(const char *hash)
{
	const struct mac_hash_entry *entries = get_mac_hash_entries();
	size_t count = get_mac_hash_entries_count();
	size_t i = 0;

	if (!hash)
		return false;

	for (; i < count; i++) {
		if (!strcasecmp(hash, entries[i].name))
			return true;
	}

	return false;
}

/**
 * @brief Parse combined algo string into base algo and hash parts
 *
 * @param algo_str  Combined algorithm string from CLI
 * @param base_algo Output buffer for base algorithm name
 * @param base_size Size of base_algo buffer
 * @param hash_out  Output buffer for hash algorithm name (empty if none)
 * @param hash_size Size of hash_out buffer
 */
int mac_parse_algo_string(const char *algo_str, char *base_algo,
			  size_t base_size, char *hash_out, size_t hash_size)
{
	const char *dash = NULL;
	size_t base_len = 0;

	if (!algo_str || !base_algo || !hash_out)
		return -1;

	base_algo[0] = '\0';
	hash_out[0] = '\0';

	dash = strchr(algo_str, '-');

	if (!dash) {
		if (!is_valid_mac_base(algo_str)) {
			ERROR("Unknown MAC algorithm '%s'", algo_str);
			return -1;
		}

		if (mac_base_needs_hash(algo_str)) {
			ERROR("'%s' requires a hash, use e.g. '%s-SHA256'",
			      algo_str, algo_str);
			return -1;
		}

		SNPRINTF(base_algo, base_size, "%s", algo_str);
		return 0;
	}

	base_len = (size_t)(dash - algo_str);

	if (!base_len || base_len >= base_size) {
		ERROR("Invalid MAC algorithm format '%s'", algo_str);
		return -1;
	}

	memcpy(base_algo, algo_str, base_len);
	base_algo[base_len] = '\0';

	if (!is_valid_mac_base(base_algo)) {
		ERROR("Unknown MAC base algorithm '%s'", base_algo);
		return -1;
	}

	if (!mac_base_needs_hash(base_algo)) {
		ERROR("'%s' does not use a hash, remove '-%s'", base_algo,
		      dash + 1);
		return -1;
	}

	if (!*(dash + 1)) {
		ERROR("Missing hash after '-' in '%s'", algo_str);
		return -1;
	}

	if (!is_valid_hmac_hash(dash + 1)) {
		ERROR("Unknown hash algorithm '%s' for %s", dash + 1,
		      base_algo);
		PRINT_USE_LIST("algorithms");
		return -1;
	}

	SNPRINTF(hash_out, hash_size, "%s", dash + 1);
	return 0;
}

/**
 * @brief Parse key ID from string
 *
 * @param id_str String representing the key ID (decimal or hex with 0x prefix)
 * @param id     Pointer to store the parsed key ID value
 */
static int parse_mac_key_id(const char *id_str, unsigned int *id)
{
	char *endptr = NULL;
	unsigned long tmp = 0;

	if (!id_str || !id)
		return -1;

	errno = 0;
	tmp = strtoul(id_str, &endptr, 0);

	if (errno || endptr == id_str || *endptr != '\0') {
		ERROR("Invalid key ID value '%s'", id_str);
		return -1;
	}

	if (tmp > UINT32_MAX) {
		ERROR("Key ID value too large");
		return -1;
	}

	*id = (unsigned int)tmp;
	return 0;
}

/**
 * @brief Print list of supported MAC algorithms (driven by backend table)
 */
static void print_mac_algo_list(void)
{
	const struct mac_base_entry *base = get_mac_base_entries();
	size_t base_count = get_mac_base_entries_count();
	const struct mac_hash_entry *hash = get_mac_hash_entries();
	size_t hash_count = get_mac_hash_entries_count();
	size_t i = 0;

	printf("\n");
	printf("Supported MAC Algorithms\n");
	printf("========================\n\n");

	/* Print non-HMAC base algorithms (CMAC, CMAC_TRUNCATED, CBC-MAC, ...) */
	printf("Cipher-based:\n");
	printf("  Algorithms: ");
	for (i = 0; i < base_count; i++) {
		if (!base[i].needs_hash) {
			if (i > 0)
				printf(", ");
			printf("%s", base[i].name);
		}
	}
	printf("\n");

	/* Print HMAC section only if hash algos are available */
	if (hash_count > 0) {
		printf("\nHMAC-based (format: HMAC-<hash> or HMAC_TRUNCATED-<hash>):\n");
		printf("  Algorithms: HMAC, HMAC_TRUNCATED\n");
		printf("  Hash:       ");
		for (i = 0; i < hash_count; i++) {
			if (i > 0)
				printf(", ");
			printf("%s", hash[i].name);
		}
		printf("\n");
		printf("  Example:    HMAC-SHA256, HMAC_TRUNCATED-SHA256\n");
	}

	printf("\nNote: Actual support depends on the backend and subsystem");
	printf(" capabilities.\n\n");
}

/**
 * @brief Print common options shared by mac and mac-verify commands
 *
 * @param prog_name Program name string
 * @param command   Command name string (e.g. "mac", "mac-verify")
 */
static void print_mac_common_options(const char *prog_name, const char *command)
{
	printf("Usage: %s %s [OPTIONS]\n\n", prog_name, command);
	printf("Options:\n");
	printf("\n      --list              List supported MAC algorithms\n\n");
	printf("  -k, --key-id <id>       Key ID (required)\n");
	printf("  -a, --algo <algorithm>  MAC algorithm (required)\n");
	printf("  -i, --input <file>      Input data file (required)\n");
}

/**
 * @brief Get inline description for MAC compute operation
 */
const char *cli_mac_inline_desc(void)
{
	return "Compute Message Authentication Code (MAC)";
}

/**
 * @brief Get inline description for MAC verify operation
 */
const char *cli_mac_verify_inline_desc(void)
{
	return "Verify Message Authentication Code (MAC)";
}

/**
 * @brief Print common MAC compute help (backend-agnostic)
 */
void cli_mac_help_common(void)
{
	const char *prog_name = get_program_name();

	printf("Compute a Message Authentication Code (MAC) from input data.\n\n");

	print_mac_common_options(prog_name, "mac");

	printf("  -m, --mac <file>        Output file for computed MAC\n");
	printf("                          (prints hex to stdout if omitted)\n");
	printf("  -t, --text              Write MAC in hex text format\n");
	print_log_options_help(prog_name);
	print_help_option_help();
}

/**
 * @brief Print common MAC verify help (backend-agnostic)
 */
void cli_mac_verify_help_common(void)
{
	const char *prog_name = get_program_name();

	printf("Verify a Message Authentication Code (MAC) against input data.\n\n");

	print_mac_common_options(prog_name, "mac-verify");

	printf("  -m, --mac <file>        MAC file to verify against (required)\n");
	print_log_options_help(prog_name);
	print_help_option_help();
}

/* Short getopt options string for MAC (compute) */
static const char *mac_short_opts = ":hk:a:i:m:S:t";

/* Define options for MAC (compute) operation */
static const struct option mac_options[] = {
	{ "help", no_argument, 0, 'h' },
	{ "key-id", required_argument, 0, 'k' },
	{ "algo", required_argument, 0, 'a' },
	{ "input", required_argument, 0, 'i' },
	{ "mac", required_argument, 0, 'm' },
	{ "subsystem", required_argument, 0, 'S' },
	{ "text", no_argument, 0, 't' },
	{ "list", no_argument, 0, 0 },
	{ "v", optional_argument, 0, 0 },
	{ "vv", optional_argument, 0, 0 },
	{ 0, 0, 0, 0 }
};

/**
 * @brief Parse command-line options for MAC compute operation
 *
 * @param argc      Argument count from command line
 * @param argv      Argument vector from command line
 * @param opts      Pointer to parsed_options structure to populate
 * @param prog_name Program name string
 */
int parse_mac_options(int argc, char **argv, struct parsed_options *opts,
		      const char *prog_name)
{
	int opt = 0;
	int option_index = 0;
	bool key_id_set = false;
	opterr = 0;

	LOG_VERBOSE("Parsing mac options (argc=%d)", argc);

	while ((opt = getopt_long(argc, argv, mac_short_opts, mac_options,
				  &option_index)) != -1) {
		switch (opt) {
		case 0:
			if (!strcmp(mac_options[option_index].name, "list")) {
				opts->show_list = true;
			} else if (!strcmp(mac_options[option_index].name,
					   "v")) {
				if (parse_log_option(opts, argc, argv,
						     prog_name, "mac",
						     LOG_LEVEL_INFO))
					return -1;
			} else if (!strcmp(mac_options[option_index].name,
					   "vv")) {
				if (parse_log_option(opts, argc, argv,
						     prog_name, "mac",
						     LOG_LEVEL_VERBOSE))
					return -1;
			}
			break;

		case 'h':
			opts->show_help = true;
			break;

		case 'k':
			if (!optarg) {
				ERROR("--key-id requires an argument");
				print_help_hint(prog_name, "mac");
				return -1;
			}
			if (parse_mac_key_id(optarg, &opts->op.mac.key_id)) {
				print_help_hint(prog_name, "mac");
				return -1;
			}
			key_id_set = true;
			LOG_VERBOSE("  key_id = %u", opts->op.mac.key_id);
			break;

		case 'a': {
			char base[MAC_BASE_MAX_LEN] = { 0 };
			char hash[MAC_HASH_MAX_LEN] = { 0 };

			if (!optarg || optarg[0] == '-') {
				ERROR("--algo requires an argument");
				print_help_hint(prog_name, "mac");
				return -1;
			}

			if (mac_parse_algo_string(optarg, base, sizeof(base),
						  hash, sizeof(hash))) {
				print_help_hint(prog_name, "mac");
				return -1;
			}

			opts->op.mac.algo = strdup(optarg);
			if (!opts->op.mac.algo) {
				ERROR("Memory allocation failed");
				return -1;
			}
			LOG_VERBOSE("  algo = %s", optarg);
			break;
		}

		case 'i':
			opts->input_filename =
				parse_file_opt(optarg, "Input filename");
			if (!opts->input_filename) {
				print_help_hint(prog_name, "mac");
				return -1;
			}
			LOG_VERBOSE("  input_filename = %s",
				    opts->input_filename);
			break;

		case 'm':
			opts->op.mac.mac_filename =
				parse_file_opt(optarg, "MAC output filename");
			if (!opts->op.mac.mac_filename) {
				print_help_hint(prog_name, "mac");
				return -1;
			}
			LOG_VERBOSE("  mac_filename = %s",
				    opts->op.mac.mac_filename);
			break;

		case 'S':
			opts->subsystem = parse_subsystem(optarg);
			LOG_VERBOSE("  subsystem = %s", optarg);
			break;

		case 't':
			opts->text_format = true;
			LOG_VERBOSE("  text_format = true");
			break;

		case ':':
			ERROR("Option '%s' requires an argument",
			      SAFE_ARGV_OPT(argv, "<unknown>"));
			print_help_hint(prog_name, "mac");
			return -1;

		case '?':
		default:
			ERROR("Unknown option '%s'",
			      SAFE_ARGV_OPT(argv, "<unknown>"));
			print_help_hint(prog_name, "mac");
			return -1;
		}
	}

	if (opts->show_list) {
		print_mac_algo_list();
		return 0;
	}

	if (!opts->show_help) {
		if (!key_id_set) {
			ERROR("--key-id is required for mac");
			print_help_hint(prog_name, "mac");
			return -1;
		}

		if (!opts->op.mac.algo) {
			ERROR("--algo is required for mac");
			PRINT_USE_LIST("algorithms");
			print_help_hint(prog_name, "mac");
			return -1;
		}

		if (!opts->input_filename) {
			ERROR("--input is required for mac");
			print_help_hint(prog_name, "mac");
			return -1;
		}
	}

	LOG_VERBOSE("MAC options parsed successfully");

	return 0;
}

/* Short getopt options string for MAC (verify) */
static const char *mac_verify_short_opts = ":hk:a:i:m:S:";

/* Define options for MAC (verify) operation */
static const struct option mac_verify_options[] = {
	{ "help", no_argument, 0, 'h' },
	{ "key-id", required_argument, 0, 'k' },
	{ "algo", required_argument, 0, 'a' },
	{ "input", required_argument, 0, 'i' },
	{ "mac", required_argument, 0, 'm' },
	{ "subsystem", required_argument, 0, 'S' },
	{ "list", no_argument, 0, 0 },
	{ "v", optional_argument, 0, 0 },
	{ "vv", optional_argument, 0, 0 },
	{ 0, 0, 0, 0 }
};

/**
 * @brief Parse command-line options for MAC verify operation
 *
 * @param argc      Argument count from command line
 * @param argv      Argument vector from command line
 * @param opts      Pointer to parsed_options structure to populate
 * @param prog_name Program name string
 */
int parse_mac_verify_options(int argc, char **argv, struct parsed_options *opts,
			     const char *prog_name)
{
	int opt = 0;
	int option_index = 0;
	bool key_id_set = false;
	opterr = 0;

	LOG_VERBOSE("Parsing mac-verify options (argc=%d)", argc);

	while ((opt = getopt_long(argc, argv, mac_verify_short_opts,
				  mac_verify_options, &option_index)) != -1) {
		switch (opt) {
		case 0:
			if (!strcmp(mac_verify_options[option_index].name,
				    "list")) {
				opts->show_list = true;
			} else if (!strcmp(mac_verify_options[option_index].name,
					   "v")) {
				if (parse_log_option(opts, argc, argv,
						     prog_name, "mac-verify",
						     LOG_LEVEL_INFO))
					return -1;
			} else if (!strcmp(mac_verify_options[option_index].name,
					   "vv")) {
				if (parse_log_option(opts, argc, argv,
						     prog_name, "mac-verify",
						     LOG_LEVEL_VERBOSE))
					return -1;
			}
			break;

		case 'h':
			opts->show_help = true;
			break;

		case 'k':
			if (!optarg) {
				ERROR("--key-id requires an argument");
				print_help_hint(prog_name, "mac-verify");
				return -1;
			}
			if (parse_mac_key_id(optarg, &opts->op.mac.key_id)) {
				print_help_hint(prog_name, "mac-verify");
				return -1;
			}
			key_id_set = true;
			LOG_VERBOSE("  key_id = %u", opts->op.mac.key_id);
			break;

		case 'a': {
			char base[MAC_BASE_MAX_LEN] = { 0 };
			char hash[MAC_HASH_MAX_LEN] = { 0 };

			if (!optarg || optarg[0] == '-') {
				ERROR("--algo requires an argument");
				print_help_hint(prog_name, "mac-verify");
				return -1;
			}

			if (mac_parse_algo_string(optarg, base, sizeof(base),
						  hash, sizeof(hash))) {
				print_help_hint(prog_name, "mac-verify");
				return -1;
			}

			opts->op.mac.algo = strdup(optarg);
			if (!opts->op.mac.algo) {
				ERROR("Memory allocation failed");
				return -1;
			}
			LOG_VERBOSE("  algo = %s", optarg);
			break;
		}

		case 'i':
			opts->input_filename =
				parse_file_opt(optarg, "Input filename");
			if (!opts->input_filename) {
				print_help_hint(prog_name, "mac-verify");
				return -1;
			}
			LOG_VERBOSE("  input_filename = %s",
				    opts->input_filename);
			break;

		case 'm':
			opts->op.mac.mac_filename =
				parse_file_opt(optarg, "MAC filename");
			if (!opts->op.mac.mac_filename) {
				print_help_hint(prog_name, "mac-verify");
				return -1;
			}
			LOG_VERBOSE("  mac_filename = %s",
				    opts->op.mac.mac_filename);
			break;

		case 'S':
			opts->subsystem = parse_subsystem(optarg);
			LOG_VERBOSE("  subsystem = %s", optarg);
			break;

		case ':':
			ERROR("Option '%s' requires an argument",
			      SAFE_ARGV_OPT(argv, "<unknown>"));
			print_help_hint(prog_name, "mac-verify");
			return -1;

		case '?':
		default:
			ERROR("Unknown option '%s'",
			      SAFE_ARGV_OPT(argv, "<unknown>"));
			print_help_hint(prog_name, "mac-verify");
			return -1;
		}
	}

	if (opts->show_list) {
		print_mac_algo_list();
		return 0;
	}

	if (!opts->show_help) {
		if (!key_id_set) {
			ERROR("--key-id is required for mac-verify");
			print_help_hint(prog_name, "mac-verify");
			return -1;
		}

		if (!opts->op.mac.algo) {
			ERROR("--algo is required for mac-verify");
			PRINT_USE_LIST("algorithms");
			print_help_hint(prog_name, "mac-verify");
			return -1;
		}

		if (!opts->input_filename) {
			ERROR("--input is required for mac-verify");
			print_help_hint(prog_name, "mac-verify");
			return -1;
		}

		if (!opts->op.mac.mac_filename) {
			ERROR("--mac is required for mac-verify");
			print_help_hint(prog_name, "mac-verify");
			return -1;
		}
	}

	LOG_VERBOSE("MAC verify options parsed successfully");

	return 0;
}
