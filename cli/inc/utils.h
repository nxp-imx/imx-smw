/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2026 NXP
 */

#ifndef CLI_UTILS_H
#define CLI_UTILS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

/* =================================================================
 * Program Information
 * =================================================================
 */

const char *get_program_name(void);
void set_program_name(const char *name);
void print_tool_banner(void);

/* =================================================================
 * Output Utilities
 * =================================================================
 */

int util_write_output_data(const unsigned char *buffer, size_t size,
			   const char *filename, bool text_format);
void *util_alloc_buffer(size_t size, const char *purpose);
int util_get_file_size(FILE *fp, size_t *size, const char *filename);

#endif /* CLI_UTILS_H */
