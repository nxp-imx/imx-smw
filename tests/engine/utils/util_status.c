// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <string.h>

#include "status_smw.h"
#include "status_psa.h"

#include "compiler.h"

#include "util.h"
#include "util_debug.h"
#include "util_status.h"

__weak const struct api_status_codes *get_smw_status_codes(void)
{
	return NULL;
}

__weak const struct api_status_codes *get_psa_status_codes(void)
{
	return NULL;
}

static const struct api_status_codes *get_status_codes_array(const char *api)
{
	if (!strcmp(api, "SMW"))
		return get_smw_status_codes();
	else if (!strcmp(api, "PSA"))
		return get_psa_status_codes();

	return NULL;
}

int get_int_status(int *status, const char *string, const char *api)
{
	const struct api_status_codes *array = NULL;

	if (!string || !status) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	array = get_status_codes_array(api);
	if (!array)
		return ERR_CODE(BAD_ARGS);

	for (; array->string; array++) {
		if (!strcmp(array->string, string)) {
			*status = array->status;
			return ERR_CODE(PASSED);
		}
	}

	DBG_PRINT("Unknown expected result");
	return ERR_CODE(UNKNOWN_RESULT);
}

char *get_string_status(int status, const char *api)
{
	const struct api_status_codes *array = NULL;

	array = get_status_codes_array(api);
	if (!array)
		return NULL;

	for (; array->string; array++) {
		if (array->status == status)
			return array->string;
	}

	return NULL;
}
