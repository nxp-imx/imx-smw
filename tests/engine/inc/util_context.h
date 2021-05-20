/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021 NXP
 */
#ifndef __UTIL_CONTEXT_H__
#define __UTIL_CONTEXT_H__

/**
 * struct context_node - Node of operation context linked list.
 * @id: Local ID of the operation context. Comes from test definition file.
 * @smw_context: Pointer to SMW API operation context structure.
 * @next: Pointer to next node.
 */
struct context_node {
	unsigned int id;
	struct smw_op_context *smw_context;
	struct context_node *next;
};

/**
 * struct context_list - LInked list to save SMW operation context structures.
 * @head: Pointer to the head of the linked list.
 */
struct context_list {
	struct context_node *head;
};

/**
 * util_context_add_node() - Add a new node is a context linked list.
 * @list: Pointer to linked list.
 * @id: Local ID of the operation context. Comes from test definition file.
 * @smw_context: Pointer to SMW API operation context structure.
 *
 * Return:
 * PASSED			- Success.
 * -INTERNAL_OUT_OF_MEMORY	- Memory allocation failed.
 */
int util_context_add_node(struct context_list **list, unsigned int id,
			  struct smw_op_context *smw_context);

/**
 * util_context_clear_list() - Clear context linked list.
 * @list: Pointer to linked list to clear.
 *
 * Memory present in the node is also freed.
 *
 * Return:
 * none
 */
void util_context_clear_list(struct context_list *list);

/**
 * util_context_find_node() - Search an operation context.
 * @list: Context linked list where the research is done.
 * @id: Context ID.
 * @smw_context: Pointer to smw context structure.
 *
 * Return:
 * PASSED	- Success.
 * -BAD_ARGS	- One of the arguments is bad.
 * -FAILED	- @id is not found.
 */
int util_context_find_node(struct context_list *list, unsigned int id,
			   struct smw_op_context **smw_context);

#endif /* __UTIL_CONTEXT_H__ */
