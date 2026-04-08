// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "helper.h"
#include "logger.h"
#include "opt_parser.h"
#include "utils.h"

/* =================================================================
 * Program Information
 * =================================================================
 */

/* Global program name storage */
static const char *program_name;

/**
 * @brief Set the program name
 *
 * @param name of the program
 */
void set_program_name(const char *name)
{
	program_name = name;
}

/**
 * @brief Get the program name
 */
const char *get_program_name(void)
{
	return program_name ? program_name : "nxp_cli";
}

/**
 * @brief Print tool banner
 */
void print_tool_banner(void)
{
	printf("=================================================\n");
	printf("NXP Semiconductors - Security Middleware CLI Tool\n");
	printf("=================================================\n\n");
}

/* =================================================================
 * Output Utilities
 * =================================================================
 */

/**
 * @brief Print buffer as hexadecimal dump to file stream
 *
 * Prints 16 bytes per line in format: "XX XX XX XX ..."
 *
 * @param fp File pointer to write the hexadecimal dump to
 * @param buf Buffer containing the data to dump
 * @param len Length of the buffer in bytes
 */
static void fprint_hex_dump(FILE *fp, const unsigned char *buf, size_t len)
{
	size_t idx = 0;
	char out[64] = { 0 };
	size_t off = 0;
	int nb_char = 0;

	if (!fp || !buf || !len)
		return;

	for (idx = 0; idx < len; idx++) {
		/* Print line after every 16 bytes or if buffer is full */
		if ((!(idx % 16) && idx > 0) || off >= (sizeof(out) - 4)) {
			FPRINTF(fp, "%s\n", out);
			off = 0;
			memset(out, 0, sizeof(out));
		}

		/* Format byte as hex */
		nb_char = snprintf(out + off, (sizeof(out) - off), "%02X ",
				   buf[idx]);
		if (nb_char < 0)
			break;

		off += (size_t)nb_char;
	}

	/* Print remaining bytes */
	if (off > 0)
		FPRINTF(fp, "%s\n", out);

	FFLUSH(fp);
}

/**
 * @brief Write data to file or stdout in binary or text format
 *
 * @param buffer Data buffer to write
 * @param size of data in bytes
 * @param filename Output filename (NULL or empty for stdout)
 * @param text_format true for hex dump, false for raw binary
 */
int util_write_output_data(const unsigned char *buffer, size_t size,
			   const char *filename, bool text_format)
{
	FILE *fp = NULL;
	int ret = -1;

	/* Validate input */
	if (!buffer || !size) {
		LOG_ERROR("Invalid buffer or size");
		return -1;
	}

	/* Check if output file is specified */
	if (filename && strlen(filename) > 0) {
		/* Write to file (text or binary) */
		fp = fopen(filename, text_format ? "w" : "wb");
		if (!fp) {
			LOG_ERROR("Failed to open file: %s", filename);
			goto cleanup;
		}

		if (text_format) {
			/* Text format: hex dump */
			fprint_hex_dump(fp, buffer, size);
		} else {
			/* Binary format: raw bytes */
			size_t written = fwrite(buffer, 1, size, fp);

			if (written != size) {
				LOG_ERROR("fwrite failed: %zu/%zu bytes",
					  written, size);
				goto cleanup;
			}
		}
	} else {
		/* No output file: write to stdout */
		fprint_hex_dump(stdout, buffer, size);
	}

	ret = 0; /* Success */

cleanup:
	if (fp)
		FCLOSE(fp);

	return ret;
}

/* =================================================================
 * Memory Allocation
 * =================================================================
 */

/**
 * @brief Allocate zeroed buffer with error handling
 *
 * @param size in bytes to allocate
 * @param purpose Description of what the buffer is for (optional, can be NULL)
 */
void *util_alloc_buffer(size_t size, const char *purpose)
{
	void *buffer = NULL;

	if (!size) {
		LOG_ERROR("Attempted to allocate 0 bytes (%s)",
			  purpose ? purpose : "unknown");
		return NULL;
	}

	buffer = calloc(1, size);
	if (!buffer) {
		LOG_ERROR("Memory allocation failed for %zu bytes (%s)", size,
			  purpose ? purpose : "unknown");
	}

	return buffer;
}

/**
 * @brief Get file size with full error checking
 *
 * @param fp: FILE pointer (must be opened for reading)
 * @param size: Pointer to store the size
 * @param filename: Filename string (for error messages)
 */
int util_get_file_size(FILE *fp, size_t *size, const char *filename)
{
	long file_size = 0;

	if (fseek(fp, 0, SEEK_END)) {
		LOG_ERROR("Failed to seek to end of file: %s", filename);
		return -1;
	}

	file_size = ftell(fp);
	if (file_size < 0) {
		LOG_ERROR("Failed to get file size: %s", filename);
		return -1;
	}

	if (!file_size) {
		LOG_ERROR("Input file is empty: %s", filename);
		return -1;
	}

	*size = (size_t)file_size;

	if (fseek(fp, 0, SEEK_SET)) {
		LOG_ERROR("Failed to seek to start of file: %s", filename);
		return -1;
	}

	return 0;
}
