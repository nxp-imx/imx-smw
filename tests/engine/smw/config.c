// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2023 NXP
 */

#include <string.h>
#include <stdlib.h>

#include <smw_config.h>

#include "util.h"
#include "paths.h"

#include "config.h"

static int read_config_file(char *file_name, char **buffer, unsigned int *size)
{
	int res = ERR_CODE(INTERNAL);

	long fsize;

	FILE *f = NULL;

	f = fopen(file_name, "r");
	if (!f)
		goto end;

	if (fseek(f, 0, SEEK_END)) {
		DBG_PRINT("fseek(SEEK_END) %s", util_get_strerr());
		goto end;
	}

	fsize = ftell(f);
	if (fsize == -1) {
		DBG_PRINT("ftell() %s", util_get_strerr());
		goto end;
	}
	DBG_PRINT("File size: %ld", fsize);

	/* Check of file size is not too big */
	if (fsize > (long)(UINT16_MAX - 1)) {
		DBG_PRINT("File size too big");
		goto end;
	}

	*size = fsize;
	if (fseek(f, 0, SEEK_SET)) {
		DBG_PRINT("fseek(SEEK_SET) %s", util_get_strerr());
		goto end;
	}

	*buffer = malloc(*size + 1);
	if (!*buffer) {
		res = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
		goto end;
	}
	if (*size != fread(*buffer, sizeof **buffer, *size, f)) {
		if (feof(f))
			DBG_PRINT("Error reading %s: unexpected EOF",
				  file_name);
		else
			DBG_PRINT("fread() %s", util_get_strerr());

		goto end;
	}
	*(*buffer + *size) = '\0';

	res = ERR_CODE(PASSED);

end:
	if (f)
		if (fclose(f))
			DBG_PRINT("fclose() %s", util_get_strerr());

	return res;
}

int config_load(struct subtest_data *subtest)
{
	int res = ERR_CODE(BAD_ARGS);

	char *file_path = NULL;
	char *file_name = NULL;
	unsigned int file_path_size = 0;
	char *buffer = NULL;
	unsigned int size = 0;
	unsigned int offset = 0;

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return res;
	}

	res = util_read_hex_buffer((unsigned char **)&buffer, &size,
				   subtest->params, INPUT_OBJ);
	if (res == ERR_CODE(MISSING_PARAMS)) {
		res = util_read_json_type(&file_name, FILEPATH_OBJ, t_string,
					  subtest->params);
		if (res != ERR_CODE(PASSED)) {
			DBG_PRINT_MISS_PARAM("filepath");
			DBG_PRINT_MISS_PARAM("input");
			goto end;
		}

		file_path_size = strlen(CONFIG_DIR) + strlen(file_name);
		file_path = malloc(file_path_size + 1);
		if (!file_path) {
			DBG_PRINT_ALLOC_FAILURE();
			res = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
			goto end;
		}

		strcpy(file_path, CONFIG_DIR);
		strcat(file_path, file_name);
		DBG_PRINT("Configuration file: %s", file_path);

		res = read_config_file(file_path, &buffer, &size);
		if (res != ERR_CODE(PASSED))
			goto end;

	} else if (res != ERR_CODE(PASSED)) {
		goto end;
	}

	/* Call configuration load function */
	subtest->smw_status = smw_config_load((char *)buffer, size, &offset);
	if (subtest->smw_status != SMW_STATUS_OK)
		res = ERR_CODE(API_STATUS_NOK);

end:
	if (buffer)
		free(buffer);

	if (file_path)
		free(file_path);

	return res;
}

int config_unload(struct subtest_data *subtest)
{
	int res = ERR_CODE(BAD_ARGS);

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return res;
	}

	/* Call configuration unload function */
	subtest->smw_status = smw_config_unload();

	if (subtest->smw_status != SMW_STATUS_OK)
		res = ERR_CODE(API_STATUS_NOK);
	else
		res = ERR_CODE(PASSED);

	return res;
}
