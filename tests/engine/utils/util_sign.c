// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2023 NXP
 */

#include <stdlib.h>

#include "util.h"
#include "util_sign.h"

/**
 * struct signature_data - Data of signature linked list node.
 * @signature: Buffer containing the signature generated by SMW.
 * @signature_length: Length of the signature.
 */
struct signature_data {
	unsigned char *signature;
	unsigned int signature_length;
};

static void sign_free_data(void *data)
{
	struct signature_data *signature_data = data;

	if (signature_data) {
		if (signature_data->signature)
			free(signature_data->signature);

		free(signature_data);
	}
}

int util_sign_init(struct llist **list)
{
	if (!list)
		return ERR_CODE(BAD_ARGS);

	return util_list_init(list, sign_free_data, LIST_ID_TYPE_UINT);
}

int util_sign_add_node(struct llist *list, unsigned int id,
		       unsigned char *signature, unsigned int signature_length)
{
	int res = ERR_CODE(BAD_ARGS);
	struct signature_data *data;

	if (!list)
		return res;

	data = malloc(sizeof(*data));
	if (!data) {
		DBG_PRINT_ALLOC_FAILURE();
		return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
	}

	data->signature = signature;
	data->signature_length = signature_length;

	res = util_list_add_node(list, id, data);

	if (res != ERR_CODE(PASSED) && data)
		free(data);

	return res;
}

int util_sign_find_node(struct llist *list, unsigned int id,
			unsigned char **signature,
			unsigned int *signature_length)
{
	int res = ERR_CODE(BAD_ARGS);
	struct signature_data *data = NULL;

	if (!list || !signature || !signature_length)
		return res;

	res = util_list_find_node(list, id, (void **)&data);
	if (res == ERR_CODE(PASSED) && !data)
		return ERR_CODE(FAILED);

	if (res == ERR_CODE(PASSED)) {
		*signature = data->signature;
		*signature_length = data->signature_length;
	}

	return res;
}
