// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2023 NXP
 */

#include <stdlib.h>
#include <string.h>

#include "util.h"
#include "util_cipher.h"

/**
 * struct cipher_output_data - Cipher output data
 * @output: Pointer to output data.
 * @output_len: @output length in bytes.
 */
struct cipher_output_data {
	unsigned char *output;
	unsigned int output_len;
};

static void cipher_free_data(void *data)
{
	struct cipher_output_data *cipher_output_data = data;

	if (cipher_output_data) {
		if (cipher_output_data->output)
			free(cipher_output_data->output);

		free(data);
	}
}

int util_cipher_init(struct llist **list)
{
	if (!list)
		return ERR_CODE(BAD_ARGS);

	return util_list_init(list, &cipher_free_data, LIST_ID_TYPE_UINT);
}

int util_cipher_add_out_data(struct llist *list, unsigned int ctx_id,
			     unsigned char *out_data, unsigned int data_len)
{
	int res = ERR_CODE(BAD_ARGS);

	struct cipher_output_data *data = NULL;
	unsigned int new_output_size = 0;

	if (!out_data || !list)
		return res;

	res = util_list_find_node(list, ctx_id, (void **)&data);
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

		res = util_list_add_node(list, ctx_id, data);
		if (res != ERR_CODE(PASSED))
			cipher_free_data(data);
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

int util_cipher_cmp_output_data(struct llist *list, unsigned int ctx_id,
				unsigned char *data, unsigned int data_len)
{
	int res = ERR_CODE(PASSED);
	struct cipher_output_data *node_data = NULL;

	res = util_list_find_node(list, ctx_id, (void **)&node_data);
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

int util_cipher_copy_node(struct llist *list, unsigned int dst_ctx_id,
			  unsigned int src_ctx_id)
{
	int res = ERR_CODE(PASSED);
	struct cipher_output_data *data = NULL;

	res = util_list_find_node(list, src_ctx_id, (void **)&data);
	if (res != ERR_CODE(PASSED))
		return res;

	if (!data)
		return ERR_CODE(INTERNAL);

	return util_cipher_add_out_data(list, dst_ctx_id, data->output,
					data->output_len);
}
