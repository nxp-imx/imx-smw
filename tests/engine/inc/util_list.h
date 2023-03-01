/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021-2023 NXP
 */
#ifndef __UTIL_LIST_H__
#define __UTIL_LIST_H__

#include <stdint.h>

enum list_id_type { LIST_ID_TYPE_UINT = 0, LIST_ID_TYPE_STRING };

/**
 * struct llist - Linked list.
 * @head: Pointer to the head of the linked list
 * @lock: List protector
 * @free_data: Pointer to the function to free node data.
 * @wwrite_id: Pointer to the function to write node ID.
 * @free_id: Pointer to the function to free node ID.
 * @match_id: Pointer to the function to match node ID.
 */
struct llist {
	struct node *head;
	void *lock;
	void (*free_data)(void *data);
	int (*write_id)(struct node *node, uintptr_t id);
	void (*free_id)(uintptr_t id);
	int (*match_id)(uintptr_t node_id, uintptr_t id);
};

/**
 * util_list_init() - Init a link list.
 * @list: Pointer to linked list.
 * @free_data: Pointer to a function to free a node data.
 * @id_type: Node ID type.
 *
 * Return:
 * PASSED                  - Success.
 * -BAD_ARG                - @list is NULL.
 * -INTERNAL_OUT_OF_MEMORY - Memory allocation failed.
 * -FAILED                 - Failure
 */
int util_list_init(struct llist **list, void (*free_data)(void *),
		   enum list_id_type id_type);

/**
 * util_list_add_node() - Add a new node in a linked list.
 * @list: Linked list.
 * @id: Local ID of the data.
 * @data: Buffer stored by the node.
 *
 * Return:
 * PASSED                  - Success.
 * -BAD_ARG                - @list is NULL.
 * -INTERNAL_OUT_OF_MEMORY - Memory allocation failed.
 */
int util_list_add_node(struct llist *list, uintptr_t id, void *data);

/**
 * util_list_add_node_nl() - Add a new node in a linked list without locking.
 * @list: Linked list.
 * @id: Local ID of the data.
 * @data: Buffer stored by the node.
 *
 * Return:
 * PASSED                  - Success.
 * -BAD_ARG                - @list is NULL.
 * -INTERNAL_OUT_OF_MEMORY - Memory allocation failed.
 */
int util_list_add_node_nl(struct llist *list, uintptr_t id, void *data);

/**
 * util_list_clear() - Clear linked list.
 * @list: Linked list to clear.
 *
 * Return:
 * PASSED                  - Success.
 * -MUTEX_DESTROY          - Mutex destroy failed.
 */
int util_list_clear(struct llist *list);

/**
 * util_list_find_node() - Search a node and return its data.
 * @list: Linked list where the research is done.
 * @id: Id of the data stored by the node.
 * @data: Data of the node matching
 *
 * Return:
 * PASSED                  - Success.
 * -BAD_ARG                - @list is NULL.
 */
int util_list_find_node(struct llist *list, uintptr_t id, void **data);

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
			    uintptr_t *id);

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

/**
 * util_list_lock() - Lock a list if list not empty.
 * @list: Linked list.
 */
void util_list_lock(struct llist *list);

/**
 * util_list_unlock() - Unlock a list if list not empty.
 * @list: Linked list.
 *
 * Return:
 */
void util_list_unlock(struct llist *list);

#endif /* __UTIL_LIST_H__ */
