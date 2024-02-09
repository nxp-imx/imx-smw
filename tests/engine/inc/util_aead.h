/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2023-2024 NXP
 */
#ifndef __UTIL_AEAD_H__
#define __UTIL_AEAD_H__

#include "util_list.h"

/**
 * struct aead_output_data - AEAD output data
 * @output: Pointer to output data.
 * @output_len: @output length in bytes.
 * @tag: Pointer to tag buffer.
 * @tag_len: @tag length in bytes.
 * @iv: Pointer to IV buffer.
 * @iv_len: @iv length in bytes.
 */
struct aead_output_data {
	unsigned char *output;
	unsigned int output_len;
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
 * util_aead_add_output_data() - Add data in a AEAD output linked list
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
 * Else, parameter @output and @tag (if tag is set in a dedicated tag field)
 * and IV are added to existing node data.
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
int util_aead_add_output_data(struct llist *list, unsigned int id,
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
 * -FAILED                 - @output is NULL or @id is not found.
 */
int util_aead_find_node(struct llist *list, unsigned int id,
			unsigned char **output, unsigned int *output_length,
			unsigned char **tag, unsigned int *tag_length,
			unsigned char **iv, unsigned int *iv_length,
			int tag_field_set);

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

#endif /* __UTIL_aead_H__ */
