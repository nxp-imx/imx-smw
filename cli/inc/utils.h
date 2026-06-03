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
bool is_psa(const char *prog_name);

/* =================================================================
 * Output Utilities
 * =================================================================
 */

int util_write_output_data(const unsigned char *buffer, size_t size,
			   const char *filename, bool text_format);
int util_hex_string_to_bytes(const char *hex_str, unsigned char **out,
			     size_t *out_len);
void *util_alloc_buffer(size_t size, const char *purpose);
int util_get_file_size(FILE *fp, size_t *size, const char *filename);
size_t util_get_file_size_by_path(const char *path);
int util_read_file(const char *filename, unsigned char **buf, size_t *size);

#endif /* CLI_UTILS_H */
