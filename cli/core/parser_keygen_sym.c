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
#include <time.h>
#include "helper.h"
#include "opt_parser.h"
#include "parser_keygen_sym.h"
#include "utils.h"

#define MAX_KEY_SIZE 4096
#define MAX_KEY_ID   0x40000000

/* Short getopt options for symmetric KEYGEN */
static const char *keygen_sym_short_opts = "ht:s:i:a:u:S:L::";

/* Define options for symmetric KEYGEN operation */
static const struct option keygen_sym_options[] = {
	{ "help", no_argument, 0, 'h' },
	{ "type", required_argument, 0, 't' },
	{ "size", required_argument, 0, 's' },
	{ "id", required_argument, 0, 'i' },
	{ "algo", required_argument, 0, 'a' },
	{ "usage", required_argument, 0, 'u' },
	{ "transient", no_argument, 0, 0 },
	{ "non-sensitive", no_argument, 0, 0 },
	{ "subsystem", required_argument, 0, 'S' },
	{ "log", optional_argument, 0, 'L' },
	{ "list", no_argument, 0, 0 },
	{ 0, 0, 0, 0 }
};

/**
 * @brief Print a list of strings separated by commas
 *
 * @param list Array of string pointers
 * @param count Number of entries in @list
 */
static void print_list(const char **list, size_t count)
{
	size_t i = 0;

	for (; i < count; i++) {
		if (i > 0)
			printf(", ");
		printf("%s", list[i]);
	}
}

/**
 * @brief Print a list of algo/key mapping names separated by commas
 *
 * @param list Array of mappings with a .name field
 * @param count Number of entries in @list
 */
static void print_mapping_list(const struct algo_mapping *list, size_t count)
{
	size_t i = 0;

	for (; i < count; i++) {
		if (i > 0)
			printf(", ");
		printf("%s", list[i].name);
	}
}

/**
 * @brief Get inline description for symmetric keygen operation
 */
const char *cli_keygen_sym_inline_desc(void)
{
	return "Generate symmetric cryptographic key";
}

/**
 * @brief Print common symmetric keygen help (backend-agnostic)
 */
void cli_keygen_sym_help_common(void)
{
	const char *prog_name = get_program_name();

	printf("Usage: %s keygen-sym [OPTIONS]\n\n", prog_name);
	printf("Generate a symmetric cryptographic key.\n\n");

	printf("Options:\n");
	printf("\n      --list                List all available symmetric key types\n\n");
	printf("  -t, --type <type>         Symmetric key type (required)\n");
	printf("  -s, --size <bits>         Key size in bits (required)\n");
	printf("  -a, --algo <algorithm>    Permitted algorithm(s) (required, comma-separated)\n");
	printf("  -u, --usage <flags>       Usage flags (required, comma-separated)\n");
	printf("                            Possible values: encrypt, decrypt, sign, verify,");
	printf(" sign_hash, verify_hash\n");
	printf("  -i, --id <id>             Key ID in range (0 < id < 0x%08x)",
	       MAX_KEY_ID);
	printf(" (required for persistent keys)\n");
	printf("      --transient           Create transient key (default: persistent)\n");
	if (strstr(prog_name, "nxp_smw")) {
		printf("      --non-sensitive       Mark key as non-sensitive");
		printf(" (default: sensitive)\n");
	}
	printf("  -L, --log <dest>          Enable session logging");
	printf(" (%s log --help for info)\n", prog_name);
	printf("  -h, --help                Show help\n");
}

/**
 * @brief Print list of available symmetric key types
 * Works for both PSA and SMW backends (compile-time selection)
 */
void cli_keygen_sym_print_list(void)
{
	const struct key_type_mapping *key_types = NULL;
	const struct algo_mapping *cipher_algos = NULL;
	const struct algo_mapping *aead_algos = NULL;
	const struct algo_mapping *hash_algos = NULL;
	const struct algo_mapping *cmac_algos = NULL;
	const char **cipher_key_types = NULL;
	const char **aead_key_types = NULL;
	const char **cmac_key_types = NULL;
	size_t key_count = 0;
	size_t cipher_count = 0;
	size_t aead_count = 0;
	size_t hash_count = 0;
	size_t cmac_count = 0;
	size_t cipher_kt_count = 0;
	size_t aead_kt_count = 0;
	size_t cmac_kt_count = 0;
	size_t i = 0;

	key_types = get_key_type_mappings();
	key_count = get_key_type_mappings_count();

	cipher_algos = get_cipher_algo_mappings();
	cipher_count = get_cipher_algo_mappings_count();

	aead_algos = get_aead_algo_mappings();
	aead_count = get_aead_algo_mappings_count();

	hash_algos = get_hmac_hash_algo_mappings();
	hash_count = get_hmac_hash_algo_mappings_count();

	cmac_algos = get_cmac_algo_mappings();
	cmac_count = get_cmac_algo_mappings_count();

	cipher_key_types = get_cipher_key_types(&cipher_kt_count);
	aead_key_types = get_aead_key_types(&aead_kt_count);
	cmac_key_types = get_cmac_key_types(&cmac_kt_count);

	printf("\n");
	printf("Available Symmetric Key Types (%s)\n", CLI_BACKEND_NAME);
	printf("=======================================\n\n");

	printf("Usage Flags: encrypt, decrypt, sign, verify,");
	printf(" sign_hash, verify_hash.\n\n");

	printf("Key Types: ");
	for (i = 0; i < key_count; i++) {
		if (i > 0)
			printf(", ");
		printf("%s", key_types[i].name);
	}
	printf("\n\n");

	if (cipher_count > 0) {
		printf("Keys supporting Symmetric Encryption (encrypt/decrypt):\n");
		printf("  Key types: ");
		print_list(cipher_key_types, cipher_kt_count);
		printf("\n  Modes:     ");
		print_mapping_list(cipher_algos, cipher_count);
		printf("\n  Example:   %s keygen-sym -t AES -s 256 -a CBC",
		       get_program_name());
		printf(" -u encrypt,decrypt --transient\n\n");
	}

	if (aead_count > 0) {
		printf("Keys supporting AEAD:\n");
		printf("  Key types: ");
		print_list(aead_key_types, aead_kt_count);
		printf("\n  Modes:     ");
		print_mapping_list(aead_algos, aead_count);
		printf("\n  Example:   %s keygen-sym -t AES -s 256 -a GCM",
		       get_program_name());
		printf(" -u encrypt,decrypt --transient\n\n");
	}

	if (cmac_count > 0 || hash_count > 0) {
		printf("Keys supporting MAC (sign/verify):\n\n");

		if (cmac_count > 0) {
			printf("  CMAC:\n");
			printf("    Key types: ");
			print_list(cmac_key_types, cmac_kt_count);
			printf("\n    Modes:     ");
			print_mapping_list(cmac_algos, cmac_count);
			printf("\n    Example:   %s keygen-sym -t AES -s 256",
			       get_program_name());
			printf(" -a CMAC -u sign,verify --transient\n\n");
		}

		if (hash_count > 0) {
			printf("  HMAC:\n");
			printf("    Key types: HMAC\n");
			printf("    Hash:      ");
			print_mapping_list(hash_algos, hash_count);
			printf("\n    Example:   %s keygen-sym -t HMAC -s 256",
			       get_program_name());
			printf(" -a SHA256 -u sign,verify --transient\n\n");
		}
	}
}

/**
 * @brief Parse key size
 *
 * @param size_str String representing the key size
 * @param size Pointer to store parsed size
 */
static int parse_key_size(const char *size_str, unsigned int *size)
{
	char *endptr = NULL;
	unsigned long tmp = 0;

	if (!size_str || !size)
		return -1;

	errno = 0;
	tmp = strtoul(size_str, &endptr, 10);

	if (errno || endptr == size_str || *endptr != '\0') {
		FPRINTF(stderr, "Error: Invalid key size value '%s'\n",
			size_str);
		return -1;
	}

	if (!tmp || tmp > MAX_KEY_SIZE) {
		FPRINTF(stderr,
			"Error: Key size must be between 1 and 4096 bits\n");
		return -1;
	}

	*size = (unsigned int)tmp;
	return 0;
}

/**
 * @brief Parse key ID
 *
 * @param id_str String representing the key ID
 * @param id Pointer to store parsed ID
 */
static int parse_key_id(const char *id_str, unsigned int *id)
{
	char *endptr = NULL;
	unsigned long tmp = 0;

	if (!id_str || !id)
		return -1;

	errno = 0;
	tmp = strtoul(id_str, &endptr, 0);

	if (errno || endptr == id_str || *endptr != '\0') {
		FPRINTF(stderr, "Error: Invalid key ID value '%s'\n", id_str);
		return -1;
	}

	if (tmp > UINT32_MAX) {
		FPRINTF(stderr, "Error: Key ID value too large\n");
		return -1;
	}

	*id = (unsigned int)tmp;
	return 0;
}

/**
 * @brief Check if a string is a valid usage flag
 *
 * @param flag String to check
 * @return true if valid, false otherwise
 */
static bool is_valid_usage_flag(const char *flag)
{
	static const char *const valid_flags[] = { "encrypt",	"decrypt",
						   "sign",	"verify",
						   "sign_hash", "verify_hash",
						   "derive",	NULL };
	int i = 0;

	for (; valid_flags[i]; i++) {
		if (!strcasecmp(flag, valid_flags[i]))
			return true;
	}

	return false;
}

/**
 * @brief Warn user about ignored arguments and suggest correction if possible
 *
 * @param argc Argument count
 * @param argv Argument vector
 * @param optind_start Index of first ignored argument
 * @param parsed_usage Already parsed usage string
 */
static void warn_ignored_args(int argc, char **argv, int optind_start,
			      const char *parsed_usage)
{
	int i = 0;
	size_t len = 0;
	bool all_valid = true;
	char *arg = NULL;
	char stripped[64] = { 0 };

	/* Print ignored arguments */
	FPRINTF(stderr, "Warning: The following argument(s) were ignored:");
	for (i = optind_start; i < argc; i++)
		FPRINTF(stderr, " '%s'", argv[i]);
	FPRINTF(stderr, "\n");

	/* Check if all ignored arguments are valid usage flags */
	for (i = optind_start; i < argc; i++) {
		SNPRINTF(stripped, sizeof(stripped), "%s", argv[i]);

		/* Strip trailing commas and spaces */
		len = strlen(stripped);
		while (len > 0 &&
		       (stripped[len - 1] == ',' || stripped[len - 1] == ' '))
			stripped[--len] = '\0';

		if (!is_valid_usage_flag(stripped)) {
			all_valid = false;
			break;
		}
	}

	if (!all_valid)
		return;

	/* Build and print suggestion */
	FPRINTF(stderr, "         Did you mean -u ");

	/* Print parsed usage stripped of trailing comma */
	if (parsed_usage) {
		SNPRINTF(stripped, sizeof(stripped), "%s", parsed_usage);
		len = strlen(stripped);
		if (len > 0 && stripped[len - 1] == ',')
			stripped[len - 1] = '\0';
		FPRINTF(stderr, "%s", stripped);
	}

	for (i = optind_start; i < argc; i++) {
		arg = argv[i];
		SNPRINTF(stripped, sizeof(stripped), "%s", arg);

		/* Strip trailing commas and spaces */
		len = strlen(stripped);
		while (len > 0 &&
		       (stripped[len - 1] == ',' || stripped[len - 1] == ' '))
			stripped[--len] = '\0';

		if (len > 0)
			FPRINTF(stderr, ",%s", stripped);
	}
	FPRINTF(stderr, "?\n");
}

/**
 * @brief Parse command-line options for symmetric KEYGEN operation
 *
 * @param argc Argument count from command line
 * @param argv Argument vector from command line
 * @param opts Pointer to parsed_options structure to populate
 * @param prog_name The program name (executable)
 */
int parse_keygen_sym_options(int argc, char **argv, struct parsed_options *opts,
			     const char *prog_name)
{
	int opt = 0;
	int option_index = 0;
	bool id_specified = false;

	opts->op.keygen.key_id = 0;

	while ((opt = getopt_long(argc, argv, keygen_sym_short_opts,
				  keygen_sym_options, &option_index)) != -1) {
		switch (opt) {
		case 0:
			/* Long option */
			if (!strcmp(keygen_sym_options[option_index].name,
				    "list")) {
				opts->show_list = true;
			} else if (!strcmp(keygen_sym_options[option_index].name,
					   "transient")) {
				opts->op.keygen.transient = true;
			} else if (!strcmp(keygen_sym_options[option_index].name,
					   "non-sensitive")) {
				opts->op.keygen.non_sensitive = true;
			}
			break;

		case 'h':
			opts->show_help = true;
			break;

		case 't':
			if (!optarg || optarg[0] == '\0' || optarg[0] == '-') {
				FPRINTF(stderr,
					"Error: --type requires an argument\n");
				print_help_hint(prog_name, "keygen-sym");
				return -1;
			}
			opts->op.keygen.key_type = strdup(optarg);
			if (!opts->op.keygen.key_type) {
				FPRINTF(stderr,
					"Error: Memory allocation failed\n");
				return -1;
			}
			break;

		case 's':
			if (!optarg) {
				FPRINTF(stderr,
					"Error: --size requires an argument\n");
				print_help_hint(prog_name, "keygen-sym");
				return -1;
			}
			if (parse_key_size(optarg, &opts->op.keygen.key_size)) {
				print_help_hint(prog_name, "keygen-sym");
				return -1;
			}
			break;

		case 'i':
			if (!optarg) {
				FPRINTF(stderr,
					"Error: --id requires an argument\n");
				print_help_hint(prog_name, "keygen-sym");
				return -1;
			}
			if (parse_key_id(optarg, &opts->op.keygen.key_id)) {
				print_help_hint(prog_name, "keygen-sym");
				return -1;
			}
			id_specified = true;
			break;

		case 'a':
			if (!optarg) {
				FPRINTF(stderr,
					"Error: --algo requires an argument\n");
				print_help_hint(prog_name, "keygen-sym");
				return -1;
			}
			opts->op.keygen.permitted_algo = strdup(optarg);
			if (!opts->op.keygen.permitted_algo) {
				FPRINTF(stderr,
					"Error: Memory allocation failed\n");
				return -1;
			}
			break;

		case 'u':
			if (!optarg) {
				FPRINTF(stderr,
					"Error: --usage requires an argument\n");
				print_help_hint(prog_name, "keygen-sym");
				return -1;
			}
			opts->op.keygen.usage = strdup(optarg);
			if (!opts->op.keygen.usage) {
				FPRINTF(stderr,
					"Error: Memory allocation failed\n");
				return -1;
			}
			break;

		case 'S':
			opts->subsystem = parse_subsystem(optarg);
			break;

		case 'L':
			if (parse_log_option(opts, argc, argv, prog_name,
					     "keygen-sym"))
				return -1;
			break;

		default:
			print_help_hint(prog_name, "keygen-sym");
			return -1;
		}
	}

	if (opts->show_list) {
		cli_keygen_sym_print_list();
		return 0;
	}

	if (optind < argc)
		warn_ignored_args(argc, argv, optind, opts->op.keygen.usage);

	/* Validate required options */
	if (!opts->show_help) {
		if (!opts->op.keygen.key_type) {
			FPRINTF(stderr,
				"Error: --type is required for symmetric key gen\n");
			FPRINTF(stderr,
				"       Use --list to see available types\n");
			print_help_hint(prog_name, "keygen-sym");
			return -1;
		}

		if (!opts->op.keygen.key_size) {
			FPRINTF(stderr,
				"Error: --size is required for symmetric key gen\n");
			print_help_hint(prog_name, "keygen-sym");
			return -1;
		}

		if (!opts->op.keygen.permitted_algo) {
			FPRINTF(stderr,
				"Error: --algo is required for symmetric key gen\n");
			print_help_hint(prog_name, "keygen-sym");
			return -1;
		}

		if (!opts->op.keygen.usage) {
			FPRINTF(stderr,
				"Error: --usage is required for symmetric key gen\n");
			print_help_hint(prog_name, "keygen-sym");
			return -1;
		}

		/* Validate ID constraints based on persistence */
		if (opts->op.keygen.transient) {
			/* Transient key: ID must not be specified */
			if (id_specified) {
				FPRINTF(stderr,
					"Error: --id cannot be used with --transient\n");
				print_help_hint(prog_name, "keygen-sym");
				return -1;
			}
			opts->op.keygen.key_id = 0;
		} else {
			/* Persistent key: ID must be provided by the user */
			if (!id_specified) {
				FPRINTF(stderr,
					"Error: --id is required for persistent keys\n");
				FPRINTF(stderr, "       ID must be in range");
				FPRINTF(stderr, " (0 < id < 0x%08x)\n",
					MAX_KEY_ID);
				print_help_hint(prog_name, "keygen-sym");
				return -1;
			}
			/* Validate specified ID is in valid range */
			if (!opts->op.keygen.key_id ||
			    opts->op.keygen.key_id >= MAX_KEY_ID) {
				FPRINTF(stderr,
					"Error: Persistent key ID must be in range");
				FPRINTF(stderr, " (0 < id < 0x%08x)\n",
					MAX_KEY_ID);
				print_help_hint(prog_name, "keygen-sym");
				return -1;
			}
		}
	}

	return 0;
}
