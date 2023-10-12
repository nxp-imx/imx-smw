// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <stdlib.h>
#include <string.h>

#include "util.h"
#include "util_aead.h"

/**
 * aead_free_data() - Release the memory allocated to AEAD output data
 * @data: Pointer to AEAD output data
 *
 * Return:
 * void
 */
static void aead_free_data(void *data)
{
	struct aead_output_data *aead_output_data = data;

	if (aead_output_data) {
		if (aead_output_data->output)
			free(aead_output_data->output);

		free(aead_output_data);
	}
}

int util_aead_init(struct llist **list)
{
	if (!list)
		return ERR_CODE(BAD_ARGS);

	return util_list_init(list, &aead_free_data, LIST_ID_TYPE_UINT);
}

int util_aead_add_output_data(struct llist *list, unsigned int id,
			      unsigned char *out_data, unsigned int data_len)
{
	int res = ERR_CODE(BAD_ARGS);

	struct aead_output_data *data = NULL;
	unsigned int new_output_size = 0;

	if (!out_data || !list)
		return res;

	res = util_list_find_node(list, id, (void **)&data);
	if (res != ERR_CODE(PASSED))
		return res;

	if (!data) {
		/* 1st call, allocate node and output data */
		data = malloc(sizeof(*data));
		if (!data) {
			DBG_PRINT_ALLOC_FAILURE();
			return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
		}

		data->output_len = data_len;
		data->output = malloc(data->output_len);
		if (!data->output) {
			DBG_PRINT_ALLOC_FAILURE();
			free(data);
			return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
		}

		memcpy(data->output, out_data, data->output_len);

		res = util_list_add_node(list, id, data);
		if (res != ERR_CODE(PASSED))
			aead_free_data(data);

	} else {
		/* Realloc output data and fill it */
		if (ADD_OVERFLOW(data->output_len, data_len, &new_output_size))
			return ERR_CODE(BAD_ARGS);

		data->output = realloc(data->output, new_output_size);
		if (!data->output) {
			DBG_PRINT_ALLOC_FAILURE();
			return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
		}

		memcpy(data->output + data->output_len, out_data, data_len);
		data->output_len = new_output_size;
		res = ERR_CODE(PASSED);
	}

	return res;
}

int util_aead_cmp_output_data(struct llist *list, unsigned int id,
			      unsigned char *data, unsigned int data_len)
{
	int res = ERR_CODE(PASSED);
	struct aead_output_data *node_data = NULL;

	res = util_list_find_node(list, id, (void **)&node_data);
	if (res != ERR_CODE(PASSED))
		return res;

	if (!node_data)
		return ERR_CODE(INTERNAL);

	if (strncmp((char *)node_data->output, (char *)data, data_len)) {
		DBG_PRINT("Output doesn't match expected output");
		DBG_DHEX("Got output", node_data->output, data_len);
		DBG_DHEX("Expected output", data, data_len);
		return ERR_CODE(SUBSYSTEM);
	}

	return ERR_CODE(PASSED);
}
