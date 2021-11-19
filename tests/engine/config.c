// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2022 NXP
 */

#include <string.h>

#include "json.h"
#include "util.h"
#include "types.h"
#include "json_types.h"
#include "paths.h"
#include "smw_config.h"

static int read_config_file(char *file_name, char **buffer, unsigned int *size)
{
	int res = ERR_CODE(INTERNAL);

	long fsize;

	FILE *f = NULL;

	f = fopen(file_name, "r");
	if (!f)
		goto end;

	if (fseek(f, 0, SEEK_END)) {
		if (ferror(f))
			perror("fseek() SEEK_END");
		goto end;
	}

	fsize = ftell(f);
	if (fsize == -1) {
		if (ferror(f))
			perror("ftell()");
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
		if (ferror(f))
			perror("fseek() SEEK_SET");
		goto end;
	}

	*buffer = malloc(*size + 1);
	if (!*buffer) {
		res = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
		goto end;
	}
	if (*size != fread(*buffer, sizeof **buffer, *size, f)) {
		if (feof(f)) {
			DBG_PRINT("Error reading %s: unexpected EOF",
				  file_name);
			goto end;
		}

		if (ferror(f))
			perror("fread()");

		goto end;
	}
	*(*buffer + *size) = '\0';

	res = ERR_CODE(PASSED);

end:
	if (f)
		if (fclose(f))
			perror("fclose()");

	return res;
}

int config_load(json_object *params, struct common_parameters *common_params,
		enum smw_status_code *ret_status)
{
	int res = ERR_CODE(PASSED);

	char *file_path = NULL;
	char *file_name = NULL;
	unsigned int file_path_size = 0;
	char *buffer = NULL;
	unsigned int size = 0;
	unsigned int offset = 0;

	if (!params || !ret_status || !common_params) {
		DBG_PRINT_BAD_ARGS(__func__);
		return ERR_CODE(BAD_ARGS);
	}

	res = util_read_hex_buffer((unsigned char **)&buffer, &size, params,
				   INPUT_OBJ);
	if (res == ERR_CODE(MISSING_PARAMS)) {
		res = util_read_json_type(&file_name, FILEPATH_OBJ, t_string,
					  params);
		if (res != ERR_CODE(PASSED)) {
			DBG_PRINT_MISS_PARAM(__func__, "filepath");
			DBG_PRINT_MISS_PARAM(__func__, "input");
			goto end;
		}

		file_path_size = strlen(CONFIG_DIR) + strlen(file_name);
		file_path = malloc(file_path_size + 1);
		if (!file_path) {
			DBG_PRINT_ALLOC_FAILURE(__func__, __LINE__);
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
	*ret_status = smw_config_load((char *)buffer, size, &offset);

	if (CHECK_RESULT(*ret_status, common_params->expected_res))
		res = ERR_CODE(BAD_RESULT);

end:
	if (buffer)
		free(buffer);

	if (file_path)
		free(file_path);

	return res;
}

int config_unload(json_object *params, struct common_parameters *common_params,
		  enum smw_status_code *ret_status)
{
	int res = ERR_CODE(PASSED);

	if (!params || !ret_status || !common_params) {
		DBG_PRINT_BAD_ARGS(__func__);
		return ERR_CODE(BAD_ARGS);
	}

	/* Call configuration unload function */
	*ret_status = smw_config_unload();

	if (CHECK_RESULT(*ret_status, common_params->expected_res))
		res = ERR_CODE(BAD_RESULT);

	return res;
}
