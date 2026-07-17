/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2026 NXP
 */

#ifndef CLI_PRINT_H
#define CLI_PRINT_H

#include <stdio.h>
#include <unistd.h>
#include "helper.h"

/* ANSI color codes */
#define COLOR_GREEN  "\033[0;32m"
#define COLOR_RED    "\033[0;31m"
#define COLOR_YELLOW "\033[0;33m"
#define COLOR_RESET  "\033[0m"

/* Use colors only if stdout/stderr is a terminal */
#define IS_TTY_STDOUT isatty(STDOUT_FILENO)
#define IS_TTY_STDERR isatty(STDERR_FILENO)

#define SUCCESS(op)                                                            \
	printf("\n%s[CLI] [SUCCESS] %s completed successfully%s\n\n",          \
	       IS_TTY_STDOUT ? COLOR_GREEN : "", (op),                         \
	       IS_TTY_STDOUT ? COLOR_RESET : "")

#define INFO(field, fmt, ...)                                                  \
	printf("  %-12s: " fmt "\n", (field), ##__VA_ARGS__)

#define WARNING(fmt, ...)                                                      \
	printf("\n%s[WARNING] " fmt "%s\n", IS_TTY_STDOUT ? COLOR_YELLOW : "", \
	       ##__VA_ARGS__, IS_TTY_STDOUT ? COLOR_RESET : "")

#define ERROR(fmt, ...)                                                        \
	FPRINTF(stderr, "\n%s[CLI] [ERROR] " fmt "%s\n",                       \
		IS_TTY_STDERR ? COLOR_RED : "", ##__VA_ARGS__,                 \
		IS_TTY_STDERR ? COLOR_RESET : "")

#endif /* CLI_PRINT_H */
