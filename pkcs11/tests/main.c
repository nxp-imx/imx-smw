// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021 NXP
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "tests_pkcs11.h"

static void printf_repeat(size_t count, const char ch)
{
	size_t i = count;

	do {
		printf("%c", ch);
	} while (--i);

	printf("\n");
}

static void usage(char *progname)
{
	printf("Usage: %s <options>\n", progname);
	printf("\n");
	printf("options:\n");
	printf("\t-h    This help\n");
}

static int run_tests(void)
{
	int ret;

	ret = tests_pkcs11();

	return ret;
}

int main(int argc, char *argv[])
{
	int ret = -1;
	int option = 0;

	printf("\n");
	printf_repeat(strlen(argv[0]) + 4, '*');
	printf("* %s *\n", argv[0]);
	printf_repeat(strlen(argv[0]) + 4, '*');
	printf("\n");

	if (argc > 1) {
		/*
		 * Parse command line argument to get the
		 * option of the test execution.
		 * If one of the option is unknown exit in error.
		 */
		do {
			option = getopt(argc, argv, "h");

			switch (option) {
			case -1:
				break;

			case 'h':
				usage(argv[0]);
				return 0;

			default:
				usage(argv[0]);
				return ret;
			}
		} while (option != -1);
	}

	ret = run_tests();

	return ret;
}
