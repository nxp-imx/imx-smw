/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021 NXP
 */
#ifndef __UTIL_CIPHER_H__
#define __UTIL_CIPHER_H__

/**
 * struct cipher_output_node - Cipher output data node
 * @ctx_id: Local context ID.
 * @output: Pointer to output data.
 * @output_len: @output length in bytes.
 * @next: Pointer to next node of the linked list.
 */
struct cipher_output_node {
	unsigned int ctx_id;
	unsigned char *output;
	unsigned int output_len;
	struct cipher_output_node *next;
};

/**
 * struct cipher_output_list - Cipher output data linked list
 * @head: Pointer to the head of the list
 */
struct cipher_output_list {
	struct cipher_output_node *head;
};

/**
 * util_cipher_add_out_data() - Add data in a cipher output linked list
 * @list: Pointer to cipher output data linked list.
 * @ctx_id: Local context ID.
 * @out_data: Data to add.
 * @data_len: @out_data length in bytes.
 *
 * If @list is NULL it's allocated in this function.
 * If it's the first call for the @ctx_id, the node is allocated.
 * Else, @out_data is added to existing node data.
 * All the memory allocated by this function is freed when
 * util_cipher_clear_out_data_list() is called.
 *
 * Return:
 * PASSED			- Success.
 * -INTERNAL_OUT_OF_MEMORY	- Memory allocation failed.
 */
int util_cipher_add_out_data(struct cipher_output_list **list,
			     unsigned int ctx_id, unsigned char *out_data,
			     unsigned int data_len);

/**
 * util_cipher_clear_out_data_list() - Clear a cipher output linked list
 * @list: Pointer to the list to free.
 *
 * Function frees the data buffer allocated by function
 * util_cipher_add_out_data()
 *
 * Return:
 * none
 */
void util_cipher_clear_out_data_list(struct cipher_output_list *list);

/**
 * compare_output_data() - Compare cipher output data
 * @list: Pointer to cipher output data linked list.
 * @ctx_id: Local context ID.
 * @data: Data to compare.
 * @data_len: @data length in bytes.
 *
 * This function compares the output data saved in @list for @ctx_id with @data.
 *
 * Return:
 * PASSED	- Success.
 * -INTERNAL	- @ctx_id node is not found.
 * -SUBSYSTEM	- Comparison failed.
 */
int compare_output_data(struct cipher_output_list *list, unsigned int ctx_id,
			unsigned char *data, unsigned int data_len);

#endif /* __UTIL_CIPHER_H__ */
