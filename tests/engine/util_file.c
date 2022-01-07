// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"
#include "util_file.h"

int util_file_open(char *dir, char *name, const char *restrict mode, FILE **f)
{
	int ret = ERR_CODE(INTERNAL);
	size_t fullname_size = 0;
	char *fullname = NULL;

	if (!name || !f) {
		DBG_PRINT_BAD_ARGS(__func__);
		return ERR_CODE(BAD_ARGS);
	}

	if (dir)
		fullname_size = strlen(dir) + 1;

	fullname_size += strlen(name) + 1;
	fullname = calloc(1, fullname_size);
	if (!fullname) {
		DBG_PRINT_ALLOC_FAILURE(__func__, __LINE__);
		return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
	}

	if (dir) {
		strcpy(fullname, dir);
		strcat(fullname, "/");
	}

	strcat(fullname, name);
	*f = fopen(fullname, mode);
	if (*f)
		ret = ERR_CODE(PASSED);
	else
		DBG_PRINT("Open %s failure %s", fullname, util_get_strerr());

	free(fullname);

	return ret;
}

int util_file_to_buffer(char *dir, char *name, char **buffer)
{
	int res = ERR_CODE(INTERNAL);
	long size = 0;
	FILE *f = NULL;

	if (!name || !buffer) {
		DBG_PRINT_BAD_ARGS(__func__);
		return ERR_CODE(BAD_ARGS);
	}

	res = util_file_open(dir, name, "r", &f);
	if (res != ERR_CODE(PASSED))
		goto exit;

	if (fseek(f, 0, SEEK_END)) {
		if (ferror(f))
			perror("fseek() SEEK_END");

		goto exit;
	}

	size = ftell(f);
	if (size == -1) {
		if (ferror(f))
			perror("ftell()");

		goto exit;
	}

	if (fseek(f, 0, SEEK_SET)) {
		if (ferror(f))
			perror("fseek() SEEK_SET");

		goto exit;
	}

	*buffer = malloc(size);
	if (!*buffer) {
		DBG_PRINT_ALLOC_FAILURE(__func__, __LINE__);
		res = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
		goto exit;
	}

	if (size != (long)fread(*buffer, sizeof(char), size, f)) {
		if (feof(f))
			DBG_PRINT("Error reading %s: unexpected EOF", name);
		else if (ferror(f))
			perror("fread()");

		res = ERR_CODE(INTERNAL);
	} else {
		res = ERR_CODE(PASSED);
	}

exit:
	if (f && fclose(f))
		perror("fclose()");

	if (*buffer && res != ERR_CODE(PASSED)) {
		free(*buffer);
		*buffer = NULL;
	}

	return res;
}
