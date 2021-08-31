/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021 NXP
 */
#ifndef __UTIL_LIST_H__
#define __UTIL_LIST_H__

/**
 * struct llist - Linked list.
 * @head: Pointer to the head of the linked list
 * @free: Pointer to the function to free node data.
 */
struct llist {
	struct node *head;
	void (*free)(void *data);
};

/**
 * util_list_init() - Init a link list.
 * @list: Pointer to linked list.
 * @free: Pointer to a function to free a node data.
 *
 * Return:
 * PASSED			- Success.
 * -BAD_ARGS			- @list is NULL.
 */
int util_list_init(struct llist **list, void (*free)(void *));

/**
 * util_list_add_node() - Add a new node in a linked list.
 * @list: Linked list.
 * @id: Local ID of the data. Comes from test definition file.
 * @data: Buffer stored by the node.
 *
 * Return:
 * PASSED			- Success.
 * -INTERNAL_OUT_OF_MEMORY	- Memory allocation failed.
 */
int util_list_add_node(struct llist *list, unsigned int id, void *data);

/**
 * util_list_clear() - Clear linked list.
 * @list: Linked list to clear.
 *
 * Return:
 * none
 */
void util_list_clear(struct llist *list);

/**
 * util_list_find_node() - Search a node.
 * @list: Linked list where the research is done.
 * @id: Id of the data stored by the node.
 *
 * Return:
 * Address of the data stored by the node if found,
 * NULL otherwise.
 */
void *util_list_find_node(struct llist *list, unsigned int id);

/**
 * util_list_next() - Return address of the next node.
 * @list: Linked list.
 * @node: A node from a list.
 * @id: Pointer to the data ID
 *
 * @node must be NULL or returned by a previous call of util_list_next().
 *
 * Return:
 * Address of the next node
 */
struct node *util_list_next(struct llist *list, struct node *node,
			    unsigned int *id);

/**
 * util_list_data() - Return address of the node data.
 * @node: A node from a list.
 *
 * @node must be returned by a call of util_list_next().
 *
 * Return:
 * Address of the data stored by the node.
 */
void *util_list_data(struct node *node);

#endif /* __UTIL_LIST_H__ */
