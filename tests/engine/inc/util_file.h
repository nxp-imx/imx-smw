/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2022, 2024 NXP
 */

#ifndef __UTIL_FILE_H__
#define __UTIL_FILE_H__

/**
 * util_file_open() - Open a file.
 * @dir: Directory where is the file (can be NULL).
 * @name: Name of the file.
 * @mode: File open mode (see fopen() stdio API).
 * @f: File handle
 *
 * Return:
 * PASSED                   - Success.
 * -INTERNAL                - Internal error.
 * -INTERNAL_OUT_OF_MEMORY  - Memory allocation failed.
 * -BAD_ARGS                - One of the arguments is bad.
 */
int util_file_open(const char *dir, const char *name, const char *restrict mode,
		   FILE **f);

/**
 * util_file_to_buffer() - Copy file content into buffer.
 * @dir: Directory where is the file (can be NULL).
 * @name: Name of the file.
 * @buffer: Pointer to buffer to fill. Allocate by this function and must be
 *          free by caller.
 * @length: Length in bytes of the buffer allocated. (can be NULL)
 *
 * Return:
 * PASSED                   - Success.
 * -INTERNAL                - Internal error.
 * -INTERNAL_OUT_OF_MEMORY  - Memory allocation failed.
 * -BAD_ARGS                - One of the arguments is bad.
 */
int util_file_to_buffer(const char *dir, const char *name, char **buffer,
			size_t *length);

/**
 * util_file_append_buffer() - Append buffer to file content.
 * @dir: Directory where is the file (can be NULL).
 * @name: Name of the file.
 * @mode: File open mode (see fopen() stdio API).
 * @buffer: Pointer to buffer to append.
 * @length: Size of the @bufffer.
 *
 * Return:
 * PASSED                   - Success.
 * -INTERNAL                - Internal error.
 * -INTERNAL_OUT_OF_MEMORY  - Memory allocation failed.
 * -BAD_ARGS                - One of the arguments is bad.
 */
int util_file_append_buffer(const char *dir, const char *name,
			    const char *restrict mode, char *buffer,
			    size_t length);

/**
 * util_file_replace() - Find and replace in input file to output file
 * @dir: Directory where is the file (can be NULL).
 * @in_file: Input file name.
 * @out_file: Output file name.
 * @key: String key value to find in @in_file.
 * @value: String value replacing @key in @out_file.
 *
 * Return:
 * PASSED                   - Success.
 * -INTERNAL                - Internal error.
 * -INTERNAL_OUT_OF_MEMORY  - Memory allocation failed.
 * -BAD_ARGS                - One of the arguments is bad.
 */
int util_file_replace(const char *dir, const char *in_file,
		      const char *out_file, const char *key, const char *value);

/**
 * util_file_remove() - Remove a file
 * @filename: Full filename
 */
void util_file_remove(const char *filename);

#endif /* __UTIL_FILE_H__ */
