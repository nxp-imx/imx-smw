// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021 NXP
 */

#include <stdlib.h>
#include <string.h>

#include "util.h"
#include "util_cipher.h"

static void util_cipher_free_data(void *data)
{
	struct cipher_output_data *cipher_output_data = data;

	if (cipher_output_data && cipher_output_data->output)
		free(cipher_output_data->output);
}

int util_cipher_add_out_data(struct llist **list, unsigned int ctx_id,
			     unsigned char *out_data, unsigned int data_len)
{
	int res;

	struct cipher_output_data *data = NULL;

	if (!out_data || !list)
		return ERR_CODE(BAD_ARGS);

	if (!*list) {
		res = util_list_init(list, util_cipher_free_data);
		if (res != ERR_CODE(PASSED))
			return res;
	}

	data = util_list_find_node(*list, ctx_id);

	if (!data) {
		/* 1st call, allocate node and output data */
		data = malloc(sizeof(*data));
		if (!data) {
			DBG_PRINT_ALLOC_FAILURE(__func__, __LINE__);
			return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
		}

		data->output_len = data_len;
		data->output = malloc(data->output_len);
		if (!data->output) {
			DBG_PRINT_ALLOC_FAILURE(__func__, __LINE__);
			free(data);
			return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
		}

		memcpy(data->output, out_data, data->output_len);

		res = util_list_add_node(*list, ctx_id, data);
		if (res != ERR_CODE(PASSED)) {
			util_cipher_free_data(data);
			free(data);
			return res;
		}
	} else {
		/* Realloc output data and fill it */
		data->output =
			realloc(data->output, data->output_len + data_len);
		if (!data->output) {
			DBG_PRINT_ALLOC_FAILURE(__func__, __LINE__);
			return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
		}

		memcpy(data->output + data->output_len, out_data, data_len);
		data->output_len += data_len;
	}

	return ERR_CODE(PASSED);
}

int compare_output_data(struct llist *list, unsigned int ctx_id,
			unsigned char *data, unsigned int data_len)
{
	struct cipher_output_data *node_data = NULL;

	node_data = util_list_find_node(list, ctx_id);

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

int util_cipher_copy_node(struct llist **list, unsigned int dst_ctx_id,
			  unsigned int src_ctx_id)
{
	struct cipher_output_data *data = NULL;

	data = util_list_find_node(*list, src_ctx_id);

	if (!data)
		return ERR_CODE(INTERNAL);

	return util_cipher_add_out_data(list, dst_ctx_id, data->output,
					data->output_len);
}
