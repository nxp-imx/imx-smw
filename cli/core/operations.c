// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <smw_crypto.h>
#include <psa/crypto.h>
#include <stdio.h>
#include <string.h>
#include "helper.h"
#include "logger.h"
#include "operations.h"
#include "utils.h"

/**
 * @brief  Get inline description for RNG operation
 */
const char *cli_rng_inline_desc(void)
{
	return "Generate random numbers";
}

/**
 * @brief  Get inline description for hash operation
 */
const char *cli_hash_inline_desc(void)
{
	return "Compute cryptographic hash";
}

/**
 * @brief Print common RNG help (backend-agnostic)
 */
void cli_rng_help_common(void)
{
	const char *prog_name = get_program_name();

	printf("Usage: %s rng [OPTIONS]\n\n", prog_name);
	printf("Generate random numbers using hardware RNG.\n\n");

	printf("Options:\n");
	printf("  -s, --size <bytes>      Bytes to generate (required)\n");
	printf("  -o, --output <file>     Output file\n");
	printf("  -t, --text              Write hex format\n");
	printf("  -L, --log <dest>        Enable session logging");
	printf(" (%s log --help for info)\n", prog_name);
	printf("  -h, --help              Show help\n");
}

/**
 * @brief Print common hash help (backend-agnostic)
 */
void cli_hash_help_common(void)
{
	const char *prog_name = get_program_name();

	printf("Usage: %s hash [OPTIONS]\n\n", prog_name);
	printf("Compute cryptographic hash/digest of input data.\n\n");

	printf("Options:\n");
	printf("\n      --list		    List all available hash algorithms\n\n");
	printf("  -a, --algo <algorithm>    Hash algorithm (required)\n");
	printf("  -i, --input <file>        Input file (required)\n");
	printf("  -o, --output <file>       Output file\n");
	printf("  -l, --length <bytes>      Output length for XOF algorithms (e.g. SHAKE256)\n");
	printf("  -t, --text                Write hex format\n");
	printf("  -L, --log <dest>          Enable session logging");
	printf(" (%s log --help for info)\n", prog_name);
	printf("  -h, --help                Show help\n");
}
