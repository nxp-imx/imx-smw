// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020 NXP
 */

#include <stdlib.h>
#include <unistd.h>

#include "util.h"
#include "run.h"
#include "types.h"

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
	printf("\t-d    Definition test file\n");
	printf("\t-o    Path to output test status directory\n");
	printf("\n");
}

int main(int argc, char *argv[])
{
	int res = ERR_CODE(BAD_ARGS);
	int option = 0;
	char *def_file = NULL;
	char *test_name = NULL;
	char *output_dir = NULL;

	if (argc > 1) {
		/*
		 * Parse command line argument to get the
		 * option of the test execution.
		 * If one of the option is unknown exit in error.
		 */
		do {
			option = getopt(argc, argv, "hd:o:");

			switch (option) {
			case -1:
				break;

			case 'd':
				def_file = optarg;
				break;

			case 'o':
				output_dir = optarg;
				break;

			case 'h':
				usage(argv[0]);
				return 0;

			default:
				usage(argv[0]);
				return res;
			}
		} while (option != -1);
	} else {
		usage(argv[0]);
		return res;
	}

	res = get_test_name(&test_name, def_file);
	if (res != ERR_CODE(PASSED))
		return res;

	res = run_test(def_file, test_name, output_dir);

	free(test_name);
	return res;
}
