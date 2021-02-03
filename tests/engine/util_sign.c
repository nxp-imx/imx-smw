// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021 NXP
 */

#include <stdlib.h>

#include "util.h"
#include "util_sign.h"

int util_sign_add_node(struct signature_list **signatures, unsigned int id,
		       unsigned char *signature, unsigned int signature_length)
{
	struct signature_node *head = NULL;
	struct signature_node *node;

	node = malloc(sizeof(*node));
	if (!node) {
		DBG_PRINT_ALLOC_FAILURE(__func__, __LINE__);
		return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
	}

	node->id = id;
	node->signature = signature;
	node->signature_length = signature_length;
	node->next = NULL;

	if (!*signatures) {
		*signatures = malloc(sizeof(struct signature_list));
		if (!*signatures) {
			free(node);
			DBG_PRINT_ALLOC_FAILURE(__func__, __LINE__);
			return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
		}

		/* New signature is the first of the list */
		(*signatures)->head = node;
	} else {
		head = (*signatures)->head;
		while (head->next)
			head = head->next;

		/* New signature is the last of the list */
		head->next = node;
	}

	return ERR_CODE(PASSED);
}

void util_sign_clear_list(struct signature_list *signatures)
{
	struct signature_node *head = NULL;
	struct signature_node *del = NULL;

	if (!signatures)
		return;

	head = signatures->head;

	while (head) {
		del = head;
		head = head->next;
		if (del->signature)
			free(del->signature);
		free(del);
	}

	free(signatures);
}

int util_sign_find_node(struct signature_list *signatures, unsigned int id,
			unsigned char **signature,
			unsigned int *signature_length)
{
	struct signature_node *head = NULL;

	if (!signatures || !signature || !signature_length)
		return ERR_CODE(FAILED);

	head = signatures->head;

	while (head) {
		if (head->id == id) {
			*signature = head->signature;
			*signature_length = head->signature_length;
			return ERR_CODE(PASSED);
		}

		head = head->next;
	}

	return ERR_CODE(FAILED);
}
