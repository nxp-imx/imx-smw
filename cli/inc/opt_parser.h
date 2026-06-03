/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2026 NXP
 */

#ifndef CLI_OPT_PARSER_H
#define CLI_OPT_PARSER_H

#include <getopt.h>
#include <stdbool.h>
#include "cipher_algo_generated.h"
#include "hash_algo_enum.h"
#include "logger.h"

/* Operation types */
enum operation {
	OP_NONE = 0,
	OP_RNG,
	OP_HASH,
	OP_DEV_GET_UUID,
	OP_DEV_GET_LIFECYCLE,
	OP_DEV_SET_LIFECYCLE,
	OP_DEV_GET_ATTESTATION,
	OP_KEYGEN_SYM,
	OP_KEYGEN_ASYM,
	OP_KEY_EXPORT,
	OP_KEY_DELETE,
	OP_MAC,
	OP_MAC_VERIFY,
	OP_ENCRYPT,
	OP_DECRYPT
};

/* RNG-specific options */
struct rng {
	size_t size;
};

/* Hash-specific options */
struct hash {
	enum hash_algo algo;
	size_t output_length;
};

/* Device attestation-specific options */
struct dev_att {
	char *challenge_filename;
};

/* Device set lifecycle-specific options */
struct dev_set_lc {
	const char *lifecycle_name;
};

/* Symmetric key generation-specific options */
struct keygen {
	char *key_type;
	unsigned int key_size;
	unsigned int key_id;
	char *permitted_algo;
	char *usage;
	bool transient;
	bool non_sensitive;
};

/* Key export-specific options */
struct key_export {
	unsigned int key_id;
	char *key_file;
	bool use_der;
	bool use_pem;
};

/* Key delete-specific options */
struct key_delete {
	unsigned int key_id;
};

/* MAC-specific options */
struct mac {
	unsigned int key_id;
	char *algo;
	char *mac_filename;
};

/* Cipher-specific options (shared by encrypt and decrypt) */
struct cipher_options {
	enum cipher_algo algo;
	unsigned int key_id;
	char *iv_hex;
};

/* Parsed options structure */
struct parsed_options {
	enum operation operation;
	const char *operation_name;
	bool show_help;
	bool show_list;

	/* Common options */
	char *output_filename;
	char *input_filename;
	smw_subsystem_t subsystem;
	bool text_format;

	/* Logging options */
	enum log_dest log_dest;
	char *log_filename;

	/* Operation-specific options */
	union {
		struct rng rng;
		struct hash hash;
		struct dev_att dev_att;
		struct dev_set_lc dev_set_lc;
		struct keygen keygen;
		struct key_export key_export;
		struct key_delete key_delete;
		struct mac mac;
		struct cipher_options cipher;
	} op;
};

/* Shared Functions between op_parsers */
smw_subsystem_t parse_subsystem(const char *subsystem_str);
char *parse_file_opt(const char *src, const char *field_name);
int parse_log_option(struct parsed_options *opts, int argc, char **argv,
		     const char *prog_name, const char *operation);
void print_help_hint(const char *prog_name, const char *operation);

/* Function prototypes */
enum operation parse_cli_options(int argc, char **argv,
				 struct parsed_options *opts);
void opt_parser_cleanup(struct parsed_options *opts);

#endif /* CLI_OPT_PARSER_H */
