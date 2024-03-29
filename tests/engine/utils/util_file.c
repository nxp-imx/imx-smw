// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "util.h"
#include "util_file.h"

int util_file_open(char *dir, char *name, const char *restrict mode, FILE **f)
{
	int ret = ERR_CODE(INTERNAL);
	size_t fullname_size = 0;
	size_t name_length = 0;
	char *fullname = NULL;

	if (!name || !f) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	if (dir) {
		fullname_size = strlen(dir) + 1;

		name_length = strlen(name) + 1;

		if (ADD_OVERFLOW(fullname_size, name_length, &fullname_size)) {
			DBG_PRINT_BAD_ARGS();
			return ERR_CODE(BAD_ARGS);
		}

		fullname = calloc(1, fullname_size);
		if (!fullname) {
			DBG_PRINT_ALLOC_FAILURE();
			return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
		}

		strcpy(fullname, dir);
		strcat(fullname, "/");

		strcat(fullname, name);
	} else {
		fullname = name;
	}

	*f = fopen(fullname, mode);
	if (*f)
		ret = ERR_CODE(PASSED);
	else
		DBG_PRINT("Open %s failure %s", fullname, util_get_strerr());

	if (dir)
		free(fullname);

	return ret;
}

int util_file_to_buffer(char *dir, char *name, char **buffer)
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

	*buffer = malloc(read_size);
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
		res = ERR_CODE(PASSED);
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

void util_file_remove(const char *filename)
{
	if (unlink(filename))
		DBG_PRINT("unlink(%s) %s", filename, util_get_strerr());
}
