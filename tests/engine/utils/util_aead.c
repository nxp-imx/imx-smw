// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2024 NXP
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

		if (aead_output_data->tag)
			free(aead_output_data->tag);

		if (aead_output_data->iv)
			free(aead_output_data->iv);

		free(aead_output_data);
	}
}

int util_aead_init(struct llist **list)
{
	if (!list)
		return ERR_CODE(BAD_ARGS);

	return util_list_init(list, &aead_free_data, LIST_ID_TYPE_UINT);
}

static int util_aead_allocate_buffer(unsigned char **data,
				     unsigned int *data_len)
{
	int res = ERR_CODE(PASSED);
	*data = malloc(*data_len * sizeof(**data));
	if (!*data) {
		DBG_PRINT_ALLOC_FAILURE();
		return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
	}

	return res;
}

static int util_aead_resize_buffer(unsigned char **data, unsigned int *data_len)
{
	int res = ERR_CODE(PASSED);

	*data = realloc(*data, *data_len * sizeof(**data));
	if (!*data) {
		DBG_PRINT_ALLOC_FAILURE();
		return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
	}

	return res;
}

int util_aead_add_output_data(struct llist *list, unsigned int id,
			      unsigned char *output, unsigned int output_len,
			      unsigned char *tag, unsigned int tag_len,
			      unsigned char *iv, unsigned int iv_len)
{
	int res = ERR_CODE(BAD_ARGS);

	struct aead_output_data *data = NULL;
	unsigned int new_output_size = 0;
	unsigned int new_tag_size = 0;
	unsigned int new_iv_size = 0;

	if (!output || !list)
		return res;

	res = util_list_find_node(list, id, (void **)&data);
	if (res != ERR_CODE(PASSED))
		return res;

	if (!data) {
		/* 1st call, allocate node and output data */

		data = calloc(1, sizeof(*data));
		if (!data) {
			DBG_PRINT_ALLOC_FAILURE();
			return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
		}

		if (output) {
			res = util_aead_allocate_buffer(&data->output,
							&output_len);
			if (res != ERR_CODE(PASSED)) {
				DBG_PRINT_ALLOC_FAILURE();
				goto error;
			}

			data->output_len = output_len;
			memcpy(data->output, output, data->output_len);
		}

		data->tag_len = tag_len;

		if (tag) {
			res = util_aead_allocate_buffer(&data->tag, &tag_len);
			if (res != ERR_CODE(PASSED)) {
				DBG_PRINT_ALLOC_FAILURE();
				goto error;
			}

			memcpy(data->tag, tag, data->tag_len);
		}

		if (iv) {
			res = util_aead_allocate_buffer(&data->iv, &iv_len);
			if (res != ERR_CODE(PASSED)) {
				DBG_PRINT_ALLOC_FAILURE();
				goto error;
			}

			data->iv_len = iv_len;
			memcpy(data->iv, iv, data->iv_len);
		}

		res = util_list_add_node(list, id, data);
		if (res != ERR_CODE(PASSED))
			aead_free_data(data);

		return res;
	} else {
		/* Realloc output data and fill it */
		if (ADD_OVERFLOW(data->output_len, output_len,
				 &new_output_size))
			return ERR_CODE(BAD_ARGS);

		res = util_aead_resize_buffer(&data->output, &new_output_size);
		if (res != ERR_CODE(PASSED))
			return res;

		memcpy(data->output + data->output_len, output, output_len);
		data->output_len = new_output_size;

		if (tag) {
			if (ADD_OVERFLOW(data->tag_len, tag_len, &new_tag_size))
				return ERR_CODE(BAD_ARGS);

			res = util_aead_resize_buffer(&data->tag,
						      &new_tag_size);
			if (res != ERR_CODE(PASSED)) {
				DBG_PRINT_ALLOC_FAILURE();
				goto error;
			}

			memcpy(data->tag + data->tag_len, tag, tag_len);
			data->tag_len = new_tag_size;
		}

		if (iv) {
			if (ADD_OVERFLOW(data->iv_len, iv_len, &new_iv_size))
				return ERR_CODE(BAD_ARGS);

			res = util_aead_resize_buffer(&data->iv, &iv_len);
			if (res != ERR_CODE(PASSED)) {
				DBG_PRINT_ALLOC_FAILURE();
				goto error;
			}

			data->iv_len = iv_len;
			memcpy(data->iv, iv, data->iv_len);
		}

		return ERR_CODE(PASSED);
	}

error:

	if (data) {
		if (data->output)
			free(data->output);

		if (data->tag)
			free(data->tag);

		if (data->iv)
			free(data->iv);

		free(data);
		data = NULL;
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

int util_aead_find_node(struct llist *list, unsigned int id,
			unsigned char **output, unsigned int *output_length,
			unsigned char **tag, unsigned int *tag_length,
			unsigned char **iv, unsigned int *iv_length,
			int tag_field_set)
{
	int res = ERR_CODE(BAD_ARGS);
	struct aead_output_data *data = NULL;

	if (!list || !output || !output_length || !iv || !iv_length)
		return res;

	if (tag_field_set) {
		if (!tag || !tag_length)
			return res;
	}

	res = util_list_find_node(list, id, (void **)&data);
	if (res == ERR_CODE(PASSED) && !data)
		return ERR_CODE(FAILED);

	if (res == ERR_CODE(PASSED)) {
		*output = data->output;
		*output_length = data->output_len;

		*iv = data->iv;
		*iv_length = data->iv_len;

		if (tag_field_set)
			*tag = data->tag;

		*tag_length = data->tag_len;
	}

	return res;
}

int util_aead_copy_node(struct llist *list, unsigned int dst_ctx_id,
			unsigned int src_ctx_id)
{
	int res = ERR_CODE(PASSED);
	struct aead_output_data *data = NULL;

	res = util_list_find_node(list, src_ctx_id, (void **)&data);
	if (res != ERR_CODE(PASSED))
		return res;

	if (!data)
		return ERR_CODE(INTERNAL);

	return util_aead_add_output_data(list, dst_ctx_id, data->output,
					 data->output_len, data->tag,
					 data->tag_len, data->iv, data->iv_len);
}
