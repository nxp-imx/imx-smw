// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2024 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"
#include "util_file.h"

/**
 * file_copy_buffer() - Copy input buffer into the file
 * @f: Pointer to file stream
 * @buffer: Buffer to copy into the file
 * @length: Length of the @buffer
 *
 * Return:
 * PASSED                   - Success.
 * -INTERNAL                - Internal error
 * -BAD_ARGS                - One of the arguments is bad.
 */
static int file_copy_buffer(FILE *f, char *buffer, size_t length)
{
	int res = ERR_CODE(INTERNAL);

	if (!f || !buffer || !length) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	if (length != fwrite(buffer, sizeof(char), length, f)) {
		DBG_PRINT("fwrite() %s", util_get_strerr());
		res = ERR_CODE(INTERNAL);
	} else {
		if (fflush(f)) {
			DBG_PRINT("fflush failure %s", util_get_strerr());
			res = ERR_CODE(INTERNAL);
		}

		res = ERR_CODE(PASSED);
	}

	return res;
}

/**
 * make_fullname() - Create the file fullname prefixed with directory
 * @fullname: Output fullname string
 * @dir: Directory can be NULL
 * @filename: Filename
 *
 * The returned @fullname buffer must be freed by the caller.
 *
 * Return:
 * PASSED                   - Success.
 * -INTERNAL_OUT_OF_MEMORY  - Memory allocation failed.
 * -BAD_ARGS                - One of the arguments is bad.
 */
static int make_fullname(char **fullname, const char *dir, const char *filename)
{
	size_t fullname_size = 0;
	size_t dir_length = 0;
	char *name = NULL;

	if (!fullname || !filename) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	fullname_size = strlen(filename) + 1;

	if (dir) {
		dir_length = strlen(dir) + 1;

		if (ADD_OVERFLOW(fullname_size, dir_length, &fullname_size)) {
			DBG_PRINT_BAD_ARGS();
			return ERR_CODE(BAD_ARGS);
		}
	}

	name = calloc(1, fullname_size);
	if (!name) {
		DBG_PRINT_ALLOC_FAILURE();
		return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
	}

	if (dir) {
		strcpy(name, dir);
		strcat(name, "/");
	}

	strcat(name, filename);

	*fullname = name;

	return ERR_CODE(PASSED);
}

/**
 * file_rename() - Renmae source file to destination file
 * @src_dir: Source directory of the source file (can be NULL)
 * @src_filename: Source filename
 * @dst_dir: Destination directory of the source file (can be NULL)
 * @dst_filename: Destination filename
 *
 * PASSED                   - Success.
 * -INTERNAL_OUT_OF_MEMORY  - Memory allocation failed.
 * -INTERNAL                - Internal error
 * -BAD_ARGS                - One of the arguments is bad.
 */
static int file_rename(const char *src_dir, const char *src_filename,
		       const char *dst_dir, const char *dst_filename)
{
	int ret = ERR_CODE(PASSED);
	char *buffer = NULL;
	size_t length = 0;

	char *src_fullname = NULL;

	ret = make_fullname(&src_fullname, src_dir, src_filename);
	if (ret != ERR_CODE(PASSED))
		goto exit;

	ret = util_file_to_buffer(NULL, src_fullname, &buffer, &length);
	if (ret != ERR_CODE(PASSED))
		goto exit;

	ret = util_file_append_buffer(dst_dir, dst_filename, "w", buffer,
				      length);
	if (ret != ERR_CODE(PASSED))
		goto exit;

	util_file_remove(src_fullname);

exit:
	if (buffer)
		free(buffer);

	if (src_fullname)
		free(src_fullname);

	return ret;
}

int util_file_open(const char *dir, const char *name, const char *restrict mode,
		   FILE **f)
{
	int ret = ERR_CODE(BAD_ARGS);
	char *fullname = NULL;

	if (!name || !f) {
		DBG_PRINT_BAD_ARGS();
		return ret;
	}

	ret = make_fullname(&fullname, dir, name);
	if (ret == ERR_CODE(PASSED)) {
		*f = fopen(fullname, mode);
		if (*f) {
			ret = ERR_CODE(PASSED);
		} else {
			DBG_PRINT("Open %s failure %s", fullname,
				  util_get_strerr());
			ret = ERR_CODE(INTERNAL);
		}
	}

	if (fullname)
		free(fullname);

	return ret;
}

int util_file_to_buffer(const char *dir, const char *name, char **buffer,
			size_t *length)
{
	int res = ERR_CODE(INTERNAL);
	long file_size = 0;
	size_t read_size = 0;
	FILE *f = NULL;

	if (!name || !buffer) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	res = util_file_open(dir, name, "r", &f);
	if (res != ERR_CODE(PASSED))
		goto exit;

	if (fseek(f, 0, SEEK_END)) {
		DBG_PRINT("fseek(SEEK_END) %s", util_get_strerr());
		res = ERR_CODE(INTERNAL);
		goto exit;
	}

	file_size = ftell(f);
	if (file_size == -1) {
		DBG_PRINT("ftell() %s", util_get_strerr());
		res = ERR_CODE(INTERNAL);
		goto exit;
	}

	if (fseek(f, 0, SEEK_SET)) {
		DBG_PRINT("fseek(SEEK_SET) %s", util_get_strerr());
		res = ERR_CODE(INTERNAL);
		goto exit;
	}

	if (SET_OVERFLOW(file_size, read_size)) {
		DBG_PRINT("File size error");
		res = ERR_CODE(INTERNAL);
		goto exit;
	}

	*buffer = malloc(read_size + 1);
	if (!*buffer) {
		DBG_PRINT_ALLOC_FAILURE();
		res = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
		goto exit;
	}

	if (read_size != fread(*buffer, sizeof(char), read_size, f)) {
		if (feof(f))
			DBG_PRINT("Error reading %s: unexpected EOF", name);
		else
			DBG_PRINT("fread() %s", util_get_strerr());

		res = ERR_CODE(INTERNAL);
	} else {
		*(*buffer + read_size) = '\0';
		res = ERR_CODE(PASSED);

		if (length)
			*length = read_size;
	}

exit:
	if (f && fclose(f))
		DBG_PRINT("fclose() %s", util_get_strerr());

	if (*buffer && res != ERR_CODE(PASSED)) {
		free(*buffer);
		*buffer = NULL;
	}

	return res;
}

int util_file_append_buffer(const char *dir, const char *name,
			    const char *restrict mode, char *buffer,
			    size_t length)
{
	int res = ERR_CODE(INTERNAL);
	FILE *f = NULL;

	if (!name || !buffer || !length) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	res = util_file_open(dir, name, mode, &f);
	if (res == ERR_CODE(PASSED))
		res = file_copy_buffer(f, buffer, length);

	if (f && fclose(f))
		DBG_PRINT("fclose() %s", util_get_strerr());

	return res;
}

int util_file_replace(const char *dir, const char *in_file,
		      const char *out_file, const char *key, const char *value)
{
	int res = ERR_CODE(INTERNAL);
	FILE *f_tmp = NULL;
	char *in_buffer = NULL;
	char *p = NULL;
	char *found = NULL;
	size_t in_length = 0;
	size_t w_length = 0;

	if (!in_file || !out_file || !key || !value) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	res = util_file_open("/var/tmp", out_file, "w", &f_tmp);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/* Read the input file in a buffer */
	res = util_file_to_buffer(dir, in_file, &in_buffer, &in_length);
	if (res != ERR_CODE(PASSED))
		goto exit;

	p = in_buffer;

	while (in_length) {
		w_length = in_length;

		found = strstr(p, key);
		if (found) {
			if (SUB_OVERFLOW((uintptr_t)found, (uintptr_t)p,
					 &w_length)) {
				res = ERR_CODE(INTERNAL);
				goto exit;
			}
		}

		/*
		 * Write into the output file, the input buffer until the
		 * occurrence of the "key" value to replace if found.
		 * Else write the rest of the input buffer.
		 */
		if (w_length != fwrite(p, sizeof(char), w_length, f_tmp)) {
			DBG_PRINT("fwrite() %s", util_get_strerr());

			res = ERR_CODE(INTERNAL);
			goto exit;
		}

		p += w_length;
		in_length -= w_length;

		if (found) {
			/* Replace "key" with the "value" */
			if (strlen(value) !=
			    fwrite(value, sizeof(char), strlen(value), f_tmp)) {
				DBG_PRINT("fwrite() - replace %s",
					  util_get_strerr());

				res = ERR_CODE(INTERNAL);
				goto exit;
			}

			p += strlen(key);
			in_length -= strlen(key);
		}
	}

	if (fflush(f_tmp)) {
		DBG_PRINT("fflush %s failure %s", out_file, util_get_strerr());
		res = ERR_CODE(INTERNAL);
		goto exit;
	}

	if (fclose(f_tmp)) {
		f_tmp = NULL;
		DBG_PRINT("fclose() %s", util_get_strerr());
		res = ERR_CODE(INTERNAL);
		goto exit;
	}

	f_tmp = NULL;

	res = file_rename("/var/tmp", out_file, dir, out_file);

exit:
	if (in_buffer)
		free(in_buffer);

	if (f_tmp && fclose(f_tmp))
		DBG_PRINT("fclose() %s", util_get_strerr());

	return res;
}

void util_file_remove(const char *filename)
{
	if (remove(filename))
		DBG_PRINT("remove (%s) %s", filename, util_get_strerr());
}
