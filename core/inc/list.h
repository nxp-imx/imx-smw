/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2022 NXP
 */

#ifndef __LIST_H__
#define __LIST_H__

#include <stdbool.h>

/* List management */

struct node;
/**
 * struct smw_utils_list - Linked list
 * @length: Current number of nodes
 * @first: Pointer to the first node of the list
 * @last: Pointer to the last node of the list
 *
 */
struct smw_utils_list {
	struct node *first;
	struct node *last;
};

/**
 * smw_utils_list_init() - Initialize a linked list.
 * @list: Pointer to a linked list.
 *
 * This function initializes a linked list.
 *
 * Return:
 * none.
 */
void smw_utils_list_init(struct smw_utils_list *list);

/**
 * smw_utils_list_destroy() - Destroy a linked list.
 * @list: Pointer to a linked list.
 *
 * This function destroys a linked list.
 * All modes are destroyed.
 * All memory dynamically allocated is freed.
 *
 * Return:
 * none.
 */
void smw_utils_list_destroy(struct smw_utils_list *list);

/**
 * smw_utils_list_append_data() - Append data to the linked list.
 * @list: Pointer to a linked list.
 * @ref: Reference associated to the data to be stored.
 * @data: Pointer to the data to be stored.
 * @print: Pointer to a dedicated function to print the data.
 *
 * This function creates a node containing the data,
 * and links the node after the last node of the list.
 *
 * Return:
 * * true	- the operation is successful.
 * * false	- the operation has failed.
 */
bool smw_utils_list_append_data(struct smw_utils_list *list, void *data,
				unsigned int ref, void (*print)(void *));

/**
 * smw_utils_list_find_first() - Return address of the first node.
 * @list: Linked list.
 * @ref: Pointer to the reference associated to the node.
 *
 * Parameter @ref may be NULL.
 * If NULL, the function returns the address of the first node.
 * If not NULL, the function returns the address of the first node matching @ref
 * or NULL if none is matching.
 *
 * Return:
 * Address of the first node of @list.
 * Address of the first node associated to @ref.
 * NULL.
 */
struct node *smw_utils_list_find_first(struct smw_utils_list *list,
				       unsigned int *ref);

/**
 * smw_utils_list_find_next() - Return address of the next node.
 * @node: A node from a list.
 * @ref: Pointer to the reference associated to the node.
 *
 * Parameter @node must be a valid node.
 * Parameter @ref may be NULL.
 * If NULL, the function returns the address of the next node.
 * If not NULL, the function returns the address of the next node matching @ref
 * or NULL if none is matching.
 *
 * Return:
 * Address of the next node in @list.
 * Address of the next node associated to @ref.
 * NULL.
 */
struct node *smw_utils_list_find_next(struct node *node, unsigned int *ref);

/**
 * smw_utils_list_get_ref() - Return reference associated to the node.
 * @node: A node from a list.
 *
 * Parameter @node must be a valid node.
 *
 * Return:
 * Reference associated to the node.
 */
unsigned int smw_utils_list_get_ref(struct node *node);

/**
 * smw_utils_list_get_data() - Return address of the node data.
 * @node: A node from a list.
 *
 * Parameter @node must be a valid node.
 *
 * Return:
 * Address of the data stored by the node.
 */
void *smw_utils_list_get_data(struct node *node);

/**
 * smw_utils_list_print() - Print the linked list.
 * @list: Pointer to a linked list.
 *
 * This function prints the linked list.
 *
 * Return:
 * none.
 */
void smw_utils_list_print(struct smw_utils_list *list);

#endif /* __LIST_H__ */
