// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021, 2023 NXP
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "builtin_macros.h"
#include "tests_pkcs11.h"

const char *progname;

static void printf_repeat(size_t count, const char ch)
{
	for (size_t i = 0; i < count; i++)
		printf("%c", ch);

	printf("\n");
}

static void usage(void)
{
	printf("Usage: %s <options>\n", progname);
	printf("\n");
	printf("options:\n");
	printf("\t-h    This help\n");
	printf("\t-t    Test name\n");
	printf("\t-l    List of tests\n");
	printf("\n");
}

static int run_tests(char *test_name)
{
	return tests_pkcs11(test_name);
}

int main(int argc, char *argv[])
{
	int ret = -1;
	int option = 0;
	char *test_name = NULL;
	size_t nb_char = 0;

	printf("\n");

	nb_char = strlen(argv[0]);
	if (INC_OVERFLOW(nb_char, 4))
		nb_char = strlen(argv[0]);

	printf_repeat(nb_char, '*');
	printf("* %s *\n", argv[0]);
	printf_repeat(nb_char, '*');
	printf("\n");

	progname = argv[0];

	if (argc > 1) {
		/*
		 * Parse command line argument to get the
		 * option of the test execution.
		 * If one of the option is unknown exit in error.
		 */
		do {
			option = getopt(argc, argv, "ht:l");

			switch (option) {
			case -1:
				break;

			case 't':
				test_name = optarg;
				printf("Run test name %s\n", optarg);
				break;

			case 'l':
				tests_pkcs11_list();
				return 0;

			case 'h':
				usage();
				return 0;

			default:
				usage();
				return ret;
			}
		} while (option != -1);
	}

	ret = run_tests(test_name);

	return ret;
}
