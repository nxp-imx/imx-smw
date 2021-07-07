/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2021 NXP
 */

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
 * @data: Pointer to the data to be stored.
 * @destructor: Pointer to a dedicated function to destroy the data.
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
				void (*destructor)(void *),
				void (*print)(void *));

/**
 * smw_utils_list_find_data() - Find data from the linked list.
 * @list: Pointer to a linked list.
 * @filter: Pointer to criteria to find a node in the list.
 * @match: Pointer to a dedicated function that matches
 *         the data contained in a node and the criteria pointed by filter.
 *
 * This function returns the pointer to the data
 * contained in the node matching the criteria if any.
 *
 * Return:
 * * pointer to the data if found
 * * NULL
 */
void *smw_utils_list_find_data(struct smw_utils_list *list, void *filter,
			       bool (*match)(void *, void *));

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
