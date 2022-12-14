/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2023 NXP
 */
#ifndef __UTIL_MAC_H__
#define __UTIL_MAC_H__

#include "util_list.h"

/**
 * util_mac_init() - Initialize the MAC list
 * @list: Pointer to linked list.
 *
 * Return:
 * PASSED                  - Success.
 * -BAD_ARG                - @list is NULL.
 * -INTERNAL_OUT_OF_MEMORY - Memory allocation failed.
 * -FAILED                 - Failure
 */
int util_mac_init(struct llist **list);

/**
 * util_mac_add_node() - Add a new node in a MAC linked list.
 * @macs: Pointer to linked list.
 * @id: Local ID of the MAC. Comes from test definition file.
 * @mac: MAC buffer.
 * @mac_length: MAC length.
 *
 * Return:
 * PASSED                  - Success.
 * -BAD_ARG                - Bad argument.
 * -INTERNAL_OUT_OF_MEMORY - Memory allocation failed.
 */
int util_mac_add_node(struct llist *macs, unsigned int id, unsigned char *mac,
		      unsigned int mac_length);

/**
 * util_mac_find_node() - Search a MAC.
 * @macs: MAC linked list where the research is done.
 * @id: Id of the MAC.
 * @mac: Pointer to the MAC buffer.
 * @mac_length: Pointer to the MAC length.
 *
 * Return:
 * PASSED                  - Success.
 * -BAD_ARG                - Bad argument.
 * -FAILED                 - @signatures is NULL or @id is not found.
 */
int util_mac_find_node(struct llist *macs, unsigned int id, unsigned char **mac,
		       unsigned int *mac_length);

#endif /* __UTIL_MAC_H__ */
