// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2026 NXP
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

int util_aead_add_data(struct llist *list, unsigned int id,
		       unsigned char *output, unsigned int output_len,
		       unsigned char *tag, unsigned int tag_len,
		       unsigned char *iv, unsigned int iv_len)
{
	int res = ERR_CODE(BAD_ARGS);

	struct aead_output_data *data = NULL;
	unsigned int new_output_size = 0;
	unsigned int new_tag_size = 0;
	unsigned int new_iv_size = 0;
	bool save_data = false;

	if (!list)
		return res;

	res = util_list_find_node(list, id, (void **)&data);
	if (res != ERR_CODE(PASSED))
		return res;

	if (!data) {
		/* 1st call, allocate node data */
		data = calloc(1, sizeof(*data));
		if (!data) {
			DBG_PRINT_ALLOC_FAILURE();
			return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
		}

		save_data = true;
	}

	if (output && output_len) {
		/* Realloc output data and fill it */
		if (ADD_OVERFLOW(data->output_len, output_len,
				 &new_output_size)) {
			res = ERR_CODE(BAD_ARGS);
			goto error;
		}

		data->output = realloc(data->output, new_output_size);
		if (!data->output) {
			DBG_PRINT_ALLOC_FAILURE();
			res = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
			goto error;
		}

		memcpy(data->output + data->output_len, output, output_len);
		data->output_len = new_output_size;
	}

	if (tag || tag_len) {
		if (ADD_OVERFLOW(data->tag_len, tag_len, &new_tag_size)) {
			res = ERR_CODE(BAD_ARGS);
			goto error;
		}

		if (tag) {
			data->tag = realloc(data->tag, new_tag_size);
			if (!data->tag) {
				DBG_PRINT_ALLOC_FAILURE();
				res = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
				goto error;
			}

			memcpy(data->tag + data->tag_len, tag, tag_len);
		}

		data->tag_len = new_tag_size;
	}

	if (iv) {
		if (ADD_OVERFLOW(data->iv_len, iv_len, &new_iv_size)) {
			res = ERR_CODE(BAD_ARGS);
			goto error;
		}

		data->iv = realloc(data->iv, iv_len);
		if (!data->iv) {
			DBG_PRINT_ALLOC_FAILURE();
			res = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
			goto error;
		}

		data->iv_len = iv_len;
		memcpy(data->iv, iv, data->iv_len);
	}

	if (save_data) {
		res = util_list_add_node(list, id, data);
		if (res != ERR_CODE(PASSED))
			goto error;
	}

	return ERR_CODE(PASSED);

error:
	if (data) {
		aead_free_data(data);
		data = NULL;
		(void)util_list_update_node(list, id, data);
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

	if (!node_data->output ||
	    strncmp((char *)node_data->output, (char *)data, data_len)) {
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

	if (!list)
		return res;

	if (tag_field_set) {
		if (!tag || !tag_length)
			return res;
	}

	res = util_list_find_node(list, id, (void **)&data);
	if (res == ERR_CODE(PASSED) && !data)
		return ERR_CODE(VALUE_NOTFOUND);

	if (res == ERR_CODE(PASSED)) {
		if (output)
			*output = data->output;

		if (output_length)
			*output_length = data->output_len;

		if (iv)
			*iv = data->iv;

		if (iv_length)
			*iv_length = data->iv_len;

		if (tag_field_set && tag)
			*tag = data->tag;

		if (tag_length)
			*tag_length = data->tag_len;
	}

	return res;
}

int util_aead_get_part_output_node(struct llist *list, unsigned int id,
				   unsigned char **output, unsigned int length)
{
	int res = ERR_CODE(BAD_ARGS);
	struct aead_output_data *data = NULL;

	if (!list || !output)
		return res;

	if (!length) {
		*output = NULL;
		return ERR_CODE(PASSED);
	}

	res = util_list_find_node(list, id, (void **)&data);
	if (res == ERR_CODE(PASSED) && !data) {
		res = ERR_CODE(VALUE_NOTFOUND);
	} else if (res == ERR_CODE(PASSED)) {
		if (length + data->output_inc >= data->output_len) {
			res = ERR_CODE(FAILED);
		} else {
			*output = data->output + data->output_inc;
			data->output_inc += length;
		}
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

	return util_aead_add_data(list, dst_ctx_id, data->output,
				  data->output_len, data->tag, data->tag_len,
				  data->iv, data->iv_len);
}

int util_aead_update_save_out_data(struct subtest_data *subtest,
				   unsigned char *output,
				   unsigned int output_length,
				   unsigned int ctx_id)
{
	int res = ERR_CODE(PASSED);
	bool save_flag = false;

	res = util_read_json_type(&save_flag, SAVE_OUT_OBJ, t_boolean,
				  subtest->params);
	if (res == ERR_CODE(VALUE_NOTFOUND))
		res = ERR_CODE(PASSED);

	if (save_flag && output_length)
		res = util_aead_add_data(list_aeads(subtest), ctx_id, output,
					 output_length, NULL, 0, NULL, 0);

	return res;
}

/**
 * check_tag_follows_output() - Check that the tag follows the output
 * @args: Pointer to SMW AEAD final API arguments
 * @tag_length: Tag length
 *
 * In the cases where the output tag is NULL, check that the tag bytes are
 * written after the output bytes.
 *
 * Return:
 * PASSED   - Success
 * FAILED   - Found an output buffer which might be misconstructed
 */
int util_aead_check_tag_follows_output(unsigned char *output,
				       unsigned int input_length,
				       unsigned int tag_length)
{
	static const unsigned char zeros[8] = { 0 };

	if (!output)
		return ERR_CODE(PASSED);

	if (tag_length > sizeof(zeros))
		tag_length = sizeof(zeros);

	if (!memcmp(output + input_length, zeros, tag_length))
		return ERR_CODE(FAILED);

	return ERR_CODE(PASSED);
}
