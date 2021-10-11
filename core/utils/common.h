/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2021 NXP
 */

/**
 * struct node - Linked list node
 * @prev: Previous node
 * @next: Next node
 * @data: Pointer to the data contained in the node
 * @printer: Pointer to a dedicated function to print the data
 * @ref: Reference associated to the node
 *
 */
struct node {
	struct node *prev;
	struct node *next;
	void *data;
	void (*printer)(void *params);
	unsigned int ref;
};
