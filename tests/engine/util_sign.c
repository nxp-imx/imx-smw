// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2022 NXP
 */

#include <stdlib.h>

#include "util.h"
#include "util_sign.h"

static void util_sign_free_data(void *data)
{
	struct signature_data *signature_data = data;

	if (signature_data && signature_data->signature)
		free(signature_data->signature);
}

int util_sign_add_node(struct llist **signatures, unsigned int id,
		       unsigned char *signature, unsigned int signature_length)
{
	int res;

	struct signature_data *data;

	if (!signatures)
		return ERR_CODE(BAD_ARGS);

	if (!*signatures) {
		res = util_list_init(signatures, util_sign_free_data);
		if (res != ERR_CODE(PASSED))
			return res;
	}

	data = malloc(sizeof(*data));
	if (!data) {
		DBG_PRINT_ALLOC_FAILURE();
		return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
	}

	data->signature = signature;
	data->signature_length = signature_length;

	res = util_list_add_node(*signatures, id, data);

	if (res != ERR_CODE(PASSED))
		if (data)
			free(data);

	return res;
}

int util_sign_find_node(struct llist *signatures, unsigned int id,
			unsigned char **signature,
			unsigned int *signature_length)
{
	struct signature_data *data = NULL;

	if (!signatures || !signature || !signature_length)
		return ERR_CODE(BAD_ARGS);

	data = util_list_find_node(signatures, id);
	if (!data)
		return ERR_CODE(FAILED);

	*signature = data->signature;
	*signature_length = data->signature_length;

	return ERR_CODE(PASSED);
}
