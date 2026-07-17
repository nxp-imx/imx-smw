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
#include "key_asym_mappings.h"
#include "opt_parser.h"
#include "parser_keygen_asym.h"
#include "utils.h"

/* Key ID constraints */
#define KEY_ID_PERSISTENT_MIN 0x00000001
#define KEY_ID_PERSISTENT_MAX 0x3FFFFFFF
#define KEY_ID_TRANSIENT      0x00000000
#define KEY_ID_RESERVED_START 0x40000000

/* Short getopt options for asymmetric KEYGEN */
static const char *keygen_asym_short_opts = ":ht:s:i:a:u:S:L::";

/* Define options for asymmetric KEYGEN operation */
static const struct option keygen_asym_options[] = {
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
 * @brief Get inline description for asymmetric keygen operation
 */
const char *cli_keygen_asym_inline_desc(void)
{
	return "Generate asymmetric cryptographic key pair";
}

/**
 * @brief Print common asymmetric keygen help (backend-agnostic)
 */
void cli_keygen_asym_help_common(void)
{
	const char *prog_name = get_program_name();

	printf("Usage: %s keygen-asym [OPTIONS]\n\n", prog_name);
	printf("Generate an asymmetric cryptographic key pair.\n\n");

	printf("Options:\n");
	printf("\n      --list                List all available asymmetric key types\n\n");
	printf("  -t, --type <type>         Asymmetric key type/curve (required)\n");
	printf("  -a, --algo <algorithm>    Permitted algorithm(s) (required, comma-separated)\n");
	printf("  -u, --usage <flags>       Usage flags (required, comma-separated)\n");
	printf("  -s, --size <bits>         Key size in bits\n");
	printf("  -i, --id <id>             Key ID in range (0 < id < 0x%08x)",
	       KEY_ID_RESERVED_START);
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
 * @brief Print a list of asym key type mapping names separated by commas
 *
 * @param list Array of asym_key_type_mapping with a .name field
 * @param count Number of entries in @list
 */
static void print_key_type_list(const struct asym_key_type_mapping *list,
				size_t count)
{
	size_t i = 0;

	for (; i < count; i++) {
		if (i > 0)
			printf(", ");
		if (list[i].name)
			printf("%s", list[i].name);
	}
}

/**
 * @brief Print a list of asym algo mapping names separated by commas
 *
 * @param list Array of asym_algo_mapping with a .name field
 * @param count Number of entries in @list
 */
static void print_algo_list(const struct asym_algo_mapping *list, size_t count)
{
	size_t i = 0;

	for (; i < count; i++) {
		if (i > 0)
			printf(", ");
		if (list[i].name)
			printf("%s", list[i].name);
	}
}

/**
 * @brief Print list of available asymmetric key types
 */
void cli_keygen_asym_print_list(void)
{
	const char *variant = NULL;
	const char *prog_name = get_program_name();
	const struct asym_key_type_mapping *all_key_types = NULL;
	const struct asym_key_type_mapping *rsa_sig_keys = NULL;
	const struct asym_key_type_mapping *ecdsa_sig_keys = NULL;
	const struct asym_key_type_mapping *eddsa_sig_keys = NULL;
	const struct asym_key_type_mapping *dsa_sig_keys = NULL;
	const struct asym_key_type_mapping *rsa_enc_keys = NULL;
	const struct asym_key_type_mapping *kex_keys = NULL;
	const struct asym_algo_mapping *sign_modes = NULL;
	const struct asym_algo_mapping *encrypt_modes = NULL;
	const struct asym_algo_mapping *hash_algos = NULL;
	const struct asym_algo_mapping *eddsa_algos = NULL;
	const struct asym_algo_mapping *tls_algos = NULL;
	const struct asym_algo_mapping *kdf_algos = NULL;
	size_t eddsa_algo_count = 0;
	size_t tls_algo_count = 0;
	size_t kdf_algo_count = 0;
	size_t all_count = 0;
	size_t rsa_sig_count = 0;
	size_t ecdsa_sig_count = 0;
	size_t eddsa_sig_count = 0;
	size_t dsa_sig_count = 0;
	size_t rsa_enc_count = 0;
	size_t kex_count = 0;
	size_t sign_mode_count = 0;
	size_t encrypt_mode_count = 0;
	size_t hash_count = 0;
	size_t i = 0;

	all_key_types = get_asym_key_type_mappings();
	all_count = get_asym_key_type_mappings_count();

	rsa_sig_keys = get_rsa_sig_key_types();
	rsa_sig_count = get_rsa_sig_key_types_count();

	ecdsa_sig_keys = get_ecdsa_sig_key_types();
	ecdsa_sig_count = get_ecdsa_sig_key_types_count();

	eddsa_sig_keys = get_eddsa_sig_key_types();
	eddsa_sig_count = get_eddsa_sig_key_types_count();

	dsa_sig_keys = get_dsa_sig_key_types();
	dsa_sig_count = get_dsa_sig_key_types_count();

	rsa_enc_keys = get_rsa_enc_key_types();
	rsa_enc_count = get_rsa_enc_key_types_count();

	kex_keys = get_key_exchange_key_types();
	kex_count = get_key_exchange_key_types_count();

	sign_modes = get_sign_mode_mappings();
	sign_mode_count = get_sign_mode_mappings_count();

	encrypt_modes = get_encrypt_mode_mappings();
	encrypt_mode_count = get_encrypt_mode_mappings_count();

	hash_algos = get_sign_hash_algo_mappings();
	hash_count = get_sign_hash_algo_mappings_count();

	tls_algos = get_tls_algo_mappings();
	tls_algo_count = get_tls_algo_mappings_count();

	kdf_algos = get_kdf_algo_mappings();
	kdf_algo_count = get_kdf_algo_mappings_count();

	printf("\n");
	printf("Available Asymmetric Key Types (%s)\n", CLI_BACKEND_NAME);
	printf("========================================\n\n");

	printf("Key Types: ");
	print_key_type_list(all_key_types, all_count);
	printf("\n\nUsage Flags: sign, verify, sign_hash, verify_hash,");
	printf(" encrypt, decrypt, derive.\n\n");

	printf("Keys supporting Signature (sign/verify):\n\n");

	/* RSA Signature */
	if (rsa_sig_count > 0) {
		printf("  RSA Signature:\n");
		printf("    Key types:  ");
		print_key_type_list(rsa_sig_keys, rsa_sig_count);
		printf("\n    Format:     {MODE}-{HASH}\n");
		printf("    Modes:      ");
		print_algo_list(sign_modes, sign_mode_count);
		printf("\n    Hashes:     ");
		print_algo_list(hash_algos, hash_count);
		printf("\n    Examples:\n");
		printf("      %s keygen-asym -t RSA -s 2048 -a PKCS1V15-SHA512",
		       prog_name);
		printf(" -u sign,verify --transient\n");
		printf("      %s keygen-asym -t RSA -s 2048 -a PSS-SHA512",
		       prog_name);
		printf(" -u sign,verify --transient\n\n");
	}

	/* ECDSA Signature */
	if (ecdsa_sig_count > 0) {
		printf("  ECDSA Signature:\n");
		printf("    Key types:  ");
		print_key_type_list(ecdsa_sig_keys, ecdsa_sig_count);
		printf("\n    Format:     ECDSA-{HASH}\n");
		printf("    Hashes:     ");
		print_algo_list(hash_algos, hash_count);
		printf("\n    Examples:\n");
		if (hash_count > 0 && ecdsa_sig_count > 0) {
			printf("      %s keygen-asym -t %s -s 256 -a ECDSA-SHA256",
			       prog_name, ecdsa_sig_keys[0].name);
			printf(" -u sign,verify --transient\n");
			if (ecdsa_sig_count > 1)
				printf("      %s keygen-asym -t %s -s 256",
				       prog_name, ecdsa_sig_keys[1].name);
			printf(" -a ECDSA-SHA256");
			printf(" -u sign,verify --transient\n");
		}
		printf("\n");
	}

	/* EdDSA Signature */
	if (eddsa_sig_count > 0) {
		eddsa_algos = get_eddsa_algo_mappings();
		eddsa_algo_count = get_eddsa_algo_mappings_count();

		printf("  EdDSA Signature:\n");
		printf("    Key types:  ");
		print_key_type_list(eddsa_sig_keys, eddsa_sig_count);
		printf("\n    Format:     EDDSA-{VARIANT}\n");
		printf("    Variants:   ");
		for (i = 0; i < eddsa_algo_count; i++) {
			if (i > 0)
				printf(", ");
			/* Strip EDDSA- prefix for display */
			variant = eddsa_algos[i].name + strlen("EDDSA-");
			printf("%s", variant);
		}
		printf("\n    Examples:\n");
		if (eddsa_sig_count > 0 && eddsa_algo_count > 0) {
			printf("      %s keygen-asym -t %s -a EDDSA-PURE",
			       prog_name, eddsa_sig_keys[0].name);
			printf(" -u sign,verify --transient\n");
			printf("      %s keygen-asym -t %s -a EDDSA-PREHASHED",
			       prog_name, eddsa_sig_keys[1].name);
			printf(" -u sign,verify --transient\n");
		}
		printf("\n");
	}

	/* DSA Signature */
	if (dsa_sig_count > 0) {
		printf("  DSA Signature:\n");
		printf("    Key types:  ");
		print_key_type_list(dsa_sig_keys, dsa_sig_count);
		printf("\n    Format:     {HASH}\n");
		printf("    Hashes:     ");
		print_algo_list(hash_algos, hash_count);
		printf("\n    Example:    %s keygen-asym -t %s -s 2048 -a SHA512",
		       prog_name, dsa_sig_keys[0].name);
		printf(" -u sign,verify --transient\n\n");
	}

	/* RSA Encryption */
	if (rsa_enc_count > 0 && encrypt_mode_count > 0) {
		printf("Keys supporting Asymmetric Encryption (encrypt/decrypt):\n\n");
		printf("  Key types:    ");
		print_key_type_list(rsa_enc_keys, rsa_enc_count);
		printf("\n");
		printf("  Algorithms:   ");
		for (i = 0; i < encrypt_mode_count; i++) {
			if (!encrypt_modes[i].name)
				continue;
			if (i > 0)
				printf(", ");
			printf("%s", encrypt_modes[i].name);
			if (!strcasecmp(encrypt_modes[i].name, "OAEP"))
				printf("-{HASH}");
		}
		printf("\n");
		printf("    Hashes:     ");
		print_algo_list(hash_algos, hash_count);
		printf("\n    Examples:\n");
		if (rsa_enc_count > 0) {
			printf("      %s keygen-asym -t %s -s 2048 -a OAEP-SHA256",
			       prog_name, rsa_enc_keys[0].name);
			printf(" -u encrypt,decrypt --transient\n");
			printf("      %s keygen-asym -t %s -s 2048 -a PKCS1V15-CRYPT",
			       prog_name, rsa_enc_keys[0].name);
			printf(" -u encrypt,decrypt --transient\n");
		}
		printf("\n");
	}

	/* TLS Key Derivation */
	if (tls_algo_count > 0) {
		printf("Keys supporting TLS Key Derivation (derive):\n\n");
		printf("  Key types:  ");
		print_key_type_list(kex_keys, kex_count);
		printf("\n  Algorithms: {TLS}-{HASH}\n");
		printf("  TLS Modes:  ");
		print_algo_list(tls_algos, tls_algo_count);
		printf("\n  Hashes:     ");
		print_algo_list(hash_algos, hash_count);
		printf("\n  Examples:\n");
		if (kex_count > 0) {
			printf("    %s keygen-asym -t %s -a TLS13-SHA256",
			       prog_name, kex_keys[0].name);
			printf(" -s 256 -u derive --transient\n");
			printf("    %s keygen-asym -t X25519 -a TLS13-SHA256",
			       prog_name);
			printf(" -u derive --transient\n");
		}
		printf("\n");
	}

	/* KDF */
	if (kdf_algo_count > 0) {
		printf("Keys supporting key derivation (KDF):\n\n");
		printf("  Key types:  ");
		print_key_type_list(kex_keys, kex_count);
		printf("\n  Algorithms: {KDF}-{HASH} / {KDF}\n");
		printf("  KDFs:       ");
		print_algo_list(kdf_algos, kdf_algo_count);
		printf("\n  Hashes:     ");
		print_algo_list(hash_algos, hash_count);
		printf("\n  Examples:\n");
		printf("    %s keygen-asym -t X25519 -a HKDF-SHA256",
		       prog_name);
		printf(" -u derive --transient\n");
		printf("    %s keygen-asym -t X25519 -a ECDH", prog_name);
		printf(" -u derive --transient\n");
		printf("\n");
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
		ERROR("Invalid key size value '%s'", size_str);
		return -1;
	}

	if (!tmp || tmp > 16384) {
		ERROR("Key size must be between 1 and 16384 bits");
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
 * @brief Parse command-line options for asymmetric KEYGEN operation
 *
 * @param argc Argument count from command line
 * @param argv Argument vector from command line
 * @param opts Pointer to parsed_options structure to populate
 * @param prog_name The program name (executable)
 */
int parse_keygen_asym_options(int argc, char **argv,
			      struct parsed_options *opts,
			      const char *prog_name)
{
	int opt = 0;
	int option_index = 0;
	bool id_specified = false;
	opterr = 0;

	opts->op.keygen.key_id = 0;

	while ((opt = getopt_long(argc, argv, keygen_asym_short_opts,
				  keygen_asym_options, &option_index)) != -1) {
		switch (opt) {
		case 0:
			if (!strcmp(keygen_asym_options[option_index].name,
				    "list")) {
				opts->show_list = true;
			} else if (!strcmp(keygen_asym_options[option_index]
						   .name,
					   "transient")) {
				opts->op.keygen.transient = true;
			} else if (!strcmp(keygen_asym_options[option_index]
						   .name,
					   "non-sensitive")) {
				opts->op.keygen.non_sensitive = true;
			}
			break;

		case 'h':
			opts->show_help = true;
			break;

		case 't':
			if (!optarg || optarg[0] == '\0' || optarg[0] == '-') {
				ERROR("--type requires an argument");
				print_help_hint(prog_name, "keygen-asym");
				return -1;
			}
			opts->op.keygen.key_type = strdup(optarg);
			if (!opts->op.keygen.key_type) {
				ERROR("Memory allocation failed");
				return -1;
			}
			break;

		case 's':
			if (!optarg) {
				ERROR("--size requires an argument");
				print_help_hint(prog_name, "keygen-asym");
				return -1;
			}
			if (parse_key_size(optarg, &opts->op.keygen.key_size)) {
				print_help_hint(prog_name, "keygen-asym");
				return -1;
			}
			break;

		case 'i':
			if (!optarg) {
				ERROR("--id requires an argument");
				print_help_hint(prog_name, "keygen-asym");
				return -1;
			}
			if (parse_key_id(optarg, &opts->op.keygen.key_id)) {
				print_help_hint(prog_name, "keygen-asym");
				return -1;
			}
			id_specified = true;
			break;

		case 'a':
			if (!optarg) {
				ERROR("--algo requires an argument");
				print_help_hint(prog_name, "keygen-asym");
				return -1;
			}
			opts->op.keygen.permitted_algo = strdup(optarg);
			if (!opts->op.keygen.permitted_algo) {
				ERROR("Memory allocation failed");
				return -1;
			}
			break;

		case 'u':
			if (!optarg) {
				ERROR("--usage requires an argument");
				print_help_hint(prog_name, "keygen-asym");
				return -1;
			}
			opts->op.keygen.usage = strdup(optarg);
			if (!opts->op.keygen.usage) {
				ERROR("Memory allocation failed");
				return -1;
			}
			break;

		case 'S':
			opts->subsystem = parse_subsystem(optarg);
			break;

		case 'L':
			if (parse_log_option(opts, argc, argv, prog_name,
					     "keygen-asym"))
				return -1;
			break;

		case ':':
			/* Missing argument for a known option */
			ERROR("Option '%s' requires an argument",
			      SAFE_ARGV_OPT(argv, "<unknown>"));
			print_help_hint(prog_name, "keygen-asym");
			return -1;

		case '?':
		default:
			/* Unknown option */
			ERROR("Unknown option '%s'",
			      SAFE_ARGV_OPT(argv, "<unknown>"));
			print_help_hint(prog_name, "keygen-asym");
			return -1;
		}
	}

	if (opts->show_list) {
		cli_keygen_asym_print_list();
		return 0;
	}

	/* Validate required options */
	if (!opts->show_help) {
		if (!opts->op.keygen.key_type) {
			ERROR("--type is required for asymmetric key gen");
			PRINT_USE_LIST("types");
			print_help_hint(prog_name, "keygen-asym");
			return -1;
		}

		if (!opts->op.keygen.permitted_algo) {
			ERROR("--algo is required for asymmetric key gen");
			print_help_hint(prog_name, "keygen-asym");
			return -1;
		}

		if (!opts->op.keygen.usage) {
			ERROR("--usage is required for asymmetric key gen");
			print_help_hint(prog_name, "keygen-asym");
			return -1;
		}

		/* Validate ID constraints based on persistence */
		if (opts->op.keygen.transient) {
			if (id_specified) {
				ERROR("--id cannot be used with --transient");
				print_help_hint(prog_name, "keygen-asym");
				return -1;
			}
			opts->op.keygen.key_id = KEY_ID_TRANSIENT;
		} else {
			if (!id_specified) {
				ERROR("--id is required for persistent keys");
				FPRINTF(stderr,
					"              ID must be in range (0 < id < 0x%08x)\n",
					KEY_ID_RESERVED_START);
				print_help_hint(prog_name, "keygen-asym");
				return -1;
			}
			if (!opts->op.keygen.key_id ||
			    opts->op.keygen.key_id >= KEY_ID_RESERVED_START) {
				ERROR("Persistent key ID must be in range (0 < id < 0x%08x)",
				      KEY_ID_RESERVED_START);
				print_help_hint(prog_name, "keygen-asym");
				return -1;
			}
		}
	}
	return 0;
}
