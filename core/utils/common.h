/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020 NXP
 */

/**
 * struct node - Linked list node
 * @prev: Previous node
 * @next: Next node
 * @data: Pointer to the data contained in the node
 * @destructor: Pointer to a dedicated function to destroy the data
 * @printer: Pointer to a dedicated function to print the data
 *
 */
struct node {
	struct node *prev;
	struct node *next;
	void *data;
	void (*destructor)(void *params);
	void (*printer)(void *params);
};
