// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
 */

#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <getopt.h>

#include <smw_status.h>
#include <smw_osal.h>

#include "psa_arch_tests.h"

#define DEFAULT_KEY_DB "/var/tmp/key_db_smw_psa_test.dat"

static void read_custom_test_list_file(char **buffer, char *file_name)
{
	FILE *f = NULL;
	long err = 0;
	unsigned long fsize = 0;

	if (!file_name)
		return;

	f = fopen(file_name, "r");
	if (!f)
		goto end;

	if (fseek(f, 0, SEEK_END)) {
		if (ferror(f))
			perror("fseek() SEEK_END");
		goto end;
	}

	err = ftell(f);
	if (err < 0) {
		if (ferror(f))
			perror("ftell()");
		goto end;
	}

	fsize = err;

	if (fseek(f, 0, SEEK_SET)) {
		if (ferror(f))
			perror("fseek() SEEK_SET");
		goto end;
	}

	*buffer = malloc(fsize + 1);
	if (!*buffer)
		goto end;

	if (fsize != fread(*buffer, sizeof **buffer, fsize, f)) {
		if (ferror(f))
			perror("fread()");

		free(*buffer);
		*buffer = NULL;

		goto end;
	}

	*(*buffer + fsize) = '\0';

end:
	if (f && fclose(f))
		perror("fclose()");
}

/**
 * usage - Print program usage.
 * @progname: Program name.
 *
 * Return:
 * None.
 */
static void usage(char *progname)
{
	printf("Usage: %s <options>\n", progname);
	printf("\n");
	printf("options:\n");
	printf("\t-h    This help\n");
	printf("\t-t    Custom test list file\n");
	printf("\n");
}

/**
 * main() - PSA Architecture Testsuite main function.
 * @argc: The number of command line arguments.
 * @argv: Array containing command line arguments.
 *
 * Return:
 * error status
 */
int main(int argc, char **argv)
{
	uint32_t ret;
	enum smw_status_code status;
	char *filepath = DEFAULT_KEY_DB;
	int option = 0;
	char *custom_test_list = NULL;
	char *custom_test_list_file_name = NULL;

	struct se_info {
		unsigned int storage_id;
		unsigned int storage_nonce;
		unsigned short storage_replay;
	} se_default_info = { 0x50534154, 0x444546, 1000 }; // PSA, DEF

	struct tee_info {
		char ta_uuid[37];
	} tee_default_info = { { "1682dada-20de-4b02-9eaa-284776931233" } };

	if (argc > 1) {
		/* Parse command line argument to get the options. */
		do {
			option = getopt(argc, argv, "h:t:");

			switch (option) {
			case -1:
				break;

			case 't':
				custom_test_list_file_name = optarg;
				break;

			case 'h':
				usage(argv[0]);
				return 0;

			default:
				usage(argv[0]);
				return -1;
			}
		} while (option != -1);
	}

	status = smw_osal_set_subsystem_info("ELE", &se_default_info,
					     sizeof(se_default_info));
	if (status != SMW_STATUS_OK)
		return -1;

	status = smw_osal_set_subsystem_info("TEE", &tee_default_info,
					     sizeof(tee_default_info));
	if (status != SMW_STATUS_OK)
		return -1;

	status = smw_osal_open_key_db(filepath, strlen(filepath) + 1);
	if (status != SMW_STATUS_OK)
		return -1;

	status = smw_osal_lib_init();
	if (status != SMW_STATUS_OK &&
	    status != SMW_STATUS_LIBRARY_ALREADY_INIT)
		return -1;

	read_custom_test_list_file(&custom_test_list,
				   custom_test_list_file_name);

	pal_set_custom_test_list(custom_test_list);

	ret = val_entry();

	if (custom_test_list)
		free(custom_test_list);

	return ret;
}
