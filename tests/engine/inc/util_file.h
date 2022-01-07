/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2022 NXP
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
int util_file_open(char *dir, char *name, const char *restrict mode, FILE **f);

/**
 * util_file_to_buffer() - Copy file content into buffer.
 * @dir: Directory where is the file (can be NULL).
 * @name: Name of the file.
 * @buffer: Pointer to buffer to fill. Allocate by this function and must be
 *          free by caller.
 *
 * Return:
 * PASSED                   - Success.
 * -INTERNAL                - Internal error.
 * -INTERNAL_OUT_OF_MEMORY  - Memory allocation failed.
 * -BAD_ARGS                - One of the arguments is bad.
 */
int util_file_to_buffer(char *dir, char *name, char **buffer);

#endif /* __UTIL_FILE_H__ */
