// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021 NXP
 */

#include <stdlib.h>
#include <string.h>

#include "util.h"
#include "util_cipher.h"

/**
 * find_node() - Find a node in a cipher output data linked list
 * @list: Pointer to cipher output data linked list.
 * @ctx_id: Context ID associated to the wanted node.
 * @node: Pointer to cipher output data node to update.
 *
 * Parameter @node is not updated if not found.
 *
 * Return:
 * none
 */
static void find_node(struct cipher_output_list *list, unsigned int ctx_id,
		      struct cipher_output_node **node)
{
	struct cipher_output_node *head = list->head;

	while (head) {
		if (head->ctx_id == ctx_id) {
			*node = head;
			return;
		}

		head = head->next;
	}
}

/**
 * insert_node() - Insert a node in a cipher output data linked list
 * @list: Pointer to cipher output data linked list.
 * @node: Pointer to the node to insert.
 *
 * Return:
 * none
 */
static void insert_node(struct cipher_output_list *list,
			struct cipher_output_node *node)
{
	struct cipher_output_node *head = list->head;

	if (!head) {
		list->head = node;
	} else {
		while (head->next)
			head = head->next;

		head->next = node;
	}
}

int util_cipher_add_out_data(struct cipher_output_list **list,
			     unsigned int ctx_id, unsigned char *out_data,
			     unsigned int data_len)
{
	struct cipher_output_node *node = NULL;

	if (!*list) {
		*list = malloc(sizeof(struct cipher_output_list));
		if (!*list) {
			DBG_PRINT_ALLOC_FAILURE(__func__, __LINE__);
			return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
		}

		(*list)->head = NULL;
	}

	find_node(*list, ctx_id, &node);

	if (!node) {
		/* 1st call, allocate note and output data */
		node = malloc(sizeof(struct cipher_output_node));
		if (!node) {
			DBG_PRINT_ALLOC_FAILURE(__func__, __LINE__);
			return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
		}

		node->ctx_id = ctx_id;
		node->next = NULL;
		node->output_len = data_len;

		node->output = malloc(node->output_len);
		if (!node->output) {
			free(node);
			DBG_PRINT_ALLOC_FAILURE(__func__, __LINE__);
			return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
		}

		memcpy(node->output, out_data, node->output_len);

		insert_node(*list, node);
	} else {
		/* Realloc output data and fill it */
		node->output =
			realloc(node->output, node->output_len + data_len);
		if (!node->output) {
			DBG_PRINT_ALLOC_FAILURE(__func__, __LINE__);
			return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
		}

		memcpy(node->output + node->output_len, out_data, data_len);
		node->output_len += data_len;
	}

	return ERR_CODE(PASSED);
}

void util_cipher_clear_out_data_list(struct cipher_output_list *list)
{
	struct cipher_output_node *head = NULL;
	struct cipher_output_node *del = NULL;

	if (!list)
		return;

	head = list->head;

	while (head) {
		del = head;
		head = head->next;

		if (del->output)
			free(del->output);

		free(del);
	}

	free(list);
}

int compare_output_data(struct cipher_output_list *list, unsigned int ctx_id,
			unsigned char *data, unsigned int data_len)
{
	struct cipher_output_node *node = NULL;

	find_node(list, ctx_id, &node);

	if (!node)
		return ERR_CODE(INTERNAL);

	if (strncmp((char *)node->output, (char *)data, data_len)) {
		DBG_PRINT("Output doesn't match expected output");
		DBG_DHEX("Got output", node->output, data_len);
		DBG_DHEX("Expected output", data, data_len);
		return ERR_CODE(SUBSYSTEM);
	}

	return ERR_CODE(PASSED);
}
