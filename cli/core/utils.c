// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <getopt.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cli_print.h"
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
		printf("Output      :\n\n");
		/* No output file: write to stdout */
		fprint_hex_dump(stdout, buffer, size);
	}

	if (filename && strlen(filename) > 0)
		INFO("Output", "%s (%zu bytes)", filename, size);

	printf("\n");
	ret = 0; /* Success */

cleanup:
	if (fp)
		FCLOSE(fp);

	return ret;
}

/**
 * @brief Convert a hex string to a byte array
 *
 * @param hex_str Input hex string (must have even length, e.g. "0A1B2C")
 * @param out Pointer to allocated output buffer (caller must free)
 * @param out_len Pointer to store the output byte length
 */
int util_hex_string_to_bytes(const char *hex_str, unsigned char **out,
			     size_t *out_len)
{
	size_t hex_len = 0;
	size_t byte_len = 0;
	unsigned char *buf = NULL;
	unsigned int byte_val = 0;
	size_t i = 0;

	if (!hex_str || !out || !out_len)
		return -1;

	hex_len = strlen(hex_str);
	if (!hex_len || hex_len % 2) {
		LOG_ERROR("Hex string must have even length (got %zu)",
			  hex_len);
		return -1;
	}

	byte_len = hex_len / 2;
	buf = util_alloc_buffer(byte_len, "hex conversion");
	if (!buf)
		return -1;

	for (i = 0; i < byte_len; i++) {
		if (sscanf(&hex_str[i * 2], "%2x", &byte_val) != 1) {
			LOG_ERROR("Invalid hex character at position %zu",
				  i * 2);
			free(buf);
			return -1;
		}

		if (byte_val > UCHAR_MAX) {
			LOG_ERROR("Parsed hex value 0x%x out of byte range",
				  byte_val);
			free(buf);
			return -1;
		}

		buf[i] = (unsigned char)byte_val;
	}

	*out = buf;
	*out_len = byte_len;
	return 0;
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

/**
 * @brief Get the size of a file by path.
 *
 * @param path File path to query
 */
size_t util_get_file_size_by_path(const char *path)
{
	FILE *fp = NULL;
	size_t size = 0;

	if (!path)
		return 0;

	fp = fopen(path, "rb");
	if (!fp)
		return 0;

	if (util_get_file_size(fp, &size, path))
		size = 0;

	FCLOSE(fp);
	return size;
}

/**
 * @brief Write data to file or stdout.
 *
 * @param data buffer to write
 * @param size of data in bytes
 * @param filename Output filename, or NULL to write hex to stdout
 * @param text_format true and filename is NULL, write as hex text
 */
int util_read_file(const char *filename, unsigned char **buf, size_t *size)
{
	FILE *fp = NULL;
	int ret = -1;

	if (!filename || !buf || !size) {
		LOG_ERROR("Invalid arguments to %s", __func__);
		return -1;
	}

	LOG_VERBOSE("Opening input file: %s", filename);
	fp = fopen(filename, "rb");
	if (!fp) {
		LOG_ERROR("Failed to open file: %s", filename);
		return -1;
	}

	if (util_get_file_size(fp, size, filename))
		goto cleanup;

	*buf = util_alloc_buffer(*size, filename);
	if (!*buf)
		goto cleanup;

	if (fread(*buf, 1, *size, fp) != *size) {
		LOG_ERROR("Failed to read file: %s", filename);
		free(*buf);
		*buf = NULL;
		goto cleanup;
	}

	LOG_VERBOSE("Input file read successfully");

	ret = 0;

cleanup:
	FCLOSE(fp);
	return ret;
}

/**
 * @brief Check if the current binary is the PSA backend
 *
 * @param prog_name Program name string
 */
bool is_psa(const char *prog_name)
{
	return (prog_name && strstr(prog_name, "nxp_psa"));
}
