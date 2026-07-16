/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2023-2024, 2026 NXP
 */
#ifndef __UTIL_AEAD_H__
#define __UTIL_AEAD_H__

#include "util_list.h"

/**
 * struct aead_output_data - AEAD output data
 * @output: Pointer to output data.
 * @output_len: @output length in bytes.
 * @output_inc: @output point increment to return (in case output is input)
 * @tag: Pointer to tag buffer.
 * @tag_len: @tag length in bytes.
 * @iv: Pointer to IV buffer.
 * @iv_len: @iv length in bytes.
 */
struct aead_output_data {
	unsigned char *output;
	unsigned int output_len;
	unsigned int output_inc;
	unsigned char *tag;
	unsigned int tag_len;
	unsigned char *iv;
	unsigned int iv_len;
};

/**
 * util_aead_init() - Initialize the AEAD list
 * @list: Pointer to linked list.
 *
 * Return:
 * PASSED                  - Success.
 * -BAD_ARG                - @list is NULL.
 * -INTERNAL_OUT_OF_MEMORY - Memory allocation failed.
 * -FAILED                 - Failure
 */
int util_aead_init(struct llist **list);

/**
 * util_aead_add_data() - Add data in a AEAD linked list
 * @list: Pointer to AEAD linked list.
 * @id: Id of the node.
 * @output: Pointer to data buffer.
 * @output_len: Data length in bytes.
 * @tag: Pointer to tag buffer.
 * @tag_len: @tag length in bytes.
 * @iv: Pointer to IV buffer.
 * @iv_len: @iv length in bytes.
 *
 * If parameter @list is NULL it's allocated in this function.
 * If it's the first call for parameter @id, the node is allocated.
 *
 * If the @output is given, the output data is set or added to the existing
 * node data.
 * If the @tag is given, the tag data is set or added to the existing
 * node data.
 * If the @iv is given, the iv data is set or added to the existing
 * node data.
 *
 * @list could be either list_aead_output or list_aead.
 *
 * All the memory allocated by this function is freed when
 * util_list_clear() is called.
 *
 * Return:
 * PASSED                  - Success.
 * -BAD_ARG                - Bad argument.
 * -INTERNAL_OUT_OF_MEMORY - Memory allocation failed.
 */
int util_aead_add_data(struct llist *list, unsigned int id,
		       unsigned char *output, unsigned int output_len,
		       unsigned char *tag, unsigned int tag_len,
		       unsigned char *iv, unsigned int iv_len);

/**
 * util_aead_cmp_output_data() - Compare AEAD output data
 * @list: Pointer to AEAD output data linked list.
 * @ctx_id: Local context ID.
 * @data: Data to compare.
 * @data_len: @data length in bytes.
 *
 * Return:
 * PASSED                  - Success.
 * -BAD_ARG                - Bad argument.
 * -INTERNAL               - @ctx_id node is not found.
 * -SUBSYSTEM              - Comparison failed.
 */
int util_aead_cmp_output_data(struct llist *list, unsigned int ctx_id,
			      unsigned char *data, unsigned int data_len);

/**
 * util_aead_find_node() - Point to node members, if node exists
 * @list: Linked list where the search is done.
 * @id: Id of the node.
 * @output: Pointer to the output data buffer.
 * @output_length: @output length in bytes.
 * @tag: Pointer to the tag buffer.
 * @tag_length: @tag length in bytes.
 * @iv: Pointer to the IV buffer.
 * @iv_length: @iv length in bytes.
 * @tag_field_set: 1 if tag is set in the dedicated tag field.
 *
 * If node id exists, point output, iv and tag buffers to the respective members
 * of the linked list node.
 *
 * Return:
 * PASSED                  - Success.
 * -BAD_ARG                - Bad argument.
 * -VALUE_NOTFOUND         - No node found.
 */
int util_aead_find_node(struct llist *list, unsigned int id,
			unsigned char **output, unsigned int *output_length,
			unsigned char **tag, unsigned int *tag_length,
			unsigned char **iv, unsigned int *iv_length,
			int tag_field_set);

/**
 * util_aead_get_part_output_node() - Get part of the output data, if node exists
 * @list: Linked list where the search is done.
 * @id: Id of the node.
 * @output: Pointer to the output data buffer.
 * @length: Length in bytes of output data to get.
 *
 * If node id exists, returns the output pointer of the output data and
 * increments the remaining output data to read.
 *
 * Return:
 * PASSED                  - Success.
 * -BAD_ARG                - @list or @output is NULL.
 * -FAILED                 - Length of data requested too big.
 * -VALUE_NOTFOUND         - No node found.
 */

int util_aead_get_part_output_node(struct llist *list, unsigned int id,
				   unsigned char **output, unsigned int length);

/**
 * util_aead_copy_node() - Copy a AEAD output data node
 * @list: Pointer to AEAD output data linked list
 * @dst_ctx_id: Context ID associated to the new node
 * @src_ctx_id: Context ID associated to the source node
 *
 * A new node is created in parameter @list linked list, associated to parameter
 * @dst_ctx_id. Data present in parameter @src_ctx_id node are copied in the new
 * node.
 *
 * Return:
 * PASSED                  - Success
 * -BAD_ARG                - Bad argument.
 * -INTERNAL               - Source node not found
 * -INTERNAL_OUT_OF_MEMORY - Memory allocation failed
 */
int util_aead_copy_node(struct llist *list, unsigned int dst_ctx_id,
			unsigned int src_ctx_id);

/**
 * util_aead_update_save_out_data() - Save intermediate output data
 * @subtest: Subtest data
 * @output: Output data
 * @output_length: Length of the output data
 * @ctx_id: Local context ID
 *
 * If 'save_output' JSON parameter is set to true, output data from a AEAD update
 * operation is saved in the AEAD output data linked list.
 *
 * Return:
 * PASSED           - Success
 * -BAD_PARAM_TYPE  - JSON parameter incorrectly set
 * Error code from autil_read_json_type
 * Error code from util_aead_add_data
 */
int util_aead_update_save_out_data(struct subtest_data *subtest,
				   unsigned char *output,
				   unsigned int output_length,
				   unsigned int ctx_id);

/**
 * util_aead_check_tag_follows_output() - Check that the tag follows the output
 * @output: Output buffer resulting of the AEAD encryption
 * @input_length: Length of the input data encrypted
 * @tag_length: Tag length
 *
 * Check if the TAG is present at the end of the output buffer (AEAD cipher
 * data).
 *
 * Return:
 * PASSED   - Success
 * FAILED   - Found an output buffer which might be misconstructed
 */
int util_aead_check_tag_follows_output(unsigned char *output,
				       unsigned int input_length,
				       unsigned int tag_length);
#endif /* __UTIL_aead_H__ */
