/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021 NXP
 */
#ifndef __UTIL_CONTEXT_H__
#define __UTIL_CONTEXT_H__

#include "smw_crypto.h"

#include "util_list.h"

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
int util_context_add_node(struct llist **list, unsigned int id,
			  struct smw_op_context *smw_context);

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
int util_context_find_node(struct llist *list, unsigned int id,
			   struct smw_op_context **smw_context);

#endif /* __UTIL_CONTEXT_H__ */
